//! Windows backend.
//!
//! Detection: SMBIOS firmware tables, `GetAdaptersAddresses`, storage IOCTLs,
//! and documented registry keys. MAC changes use the vendor-supported
//! `NetworkAddress` registry value followed by an adapter restart, and are
//! verified through a fresh adapter enumeration.

use std::ffi::c_void;
use std::mem::size_of;
use std::process::Command;
use std::sync::LazyLock;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
    HANDLE,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::Storage::FileSystem::{
    BusTypeNvme, BusTypeSata, BusTypeUsb, CreateFileW, GetFileSizeEx, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageDeviceProperty, IOCTL_STORAGE_QUERY_PROPERTY,
    STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
};
use windows::Win32::System::SystemInformation::{GetSystemFirmwareTable, FIRMWARE_TABLE_PROVIDER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::IO::DeviceIoControl;

use super::{Actions, IdentityFormat, MachineIdentity, Platform, SystemContext};
use crate::hardware::network::{InterfaceKind, MacAddress, NetworkInterface};
use crate::hardware::smbios::{self, SmbiosData};
use crate::hardware::{
    self, BiosInfo, BoardInfo, CpuInfo, DiskInfo, GpuInfo, Privilege, SystemInfo, Value,
};

const NETWORK_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
const DISPLAY_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
const MACHINE_GUID_KEY: &str = r"SOFTWARE\Microsoft\Cryptography";
const MACHINE_GUID_SOURCE: &str = r"HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid";
const CPU_KEY: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";
const WINDOWS_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const NETWORK_ADDRESS_VALUE: &str = "NetworkAddress";

pub struct Windows;

impl Windows {
    pub fn new() -> Self {
        Windows
    }
}

impl Default for Windows {
    fn default() -> Self {
        Self::new()
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn open_key(path: &str, access: REG_SAM_FLAGS) -> Result<RegKey> {
    let path_wide = wide(path);
    let mut key = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_wide.as_ptr()),
            None,
            access,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        bail!("RegOpenKeyExW({path}) failed with Win32 error {}", status.0);
    }
    Ok(RegKey(key))
}

fn decode_registry_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn read_string(key: HKEY, name: &str) -> Result<Option<String>> {
    let name_wide = wide(name);
    let mut value_type = REG_VALUE_TYPE(0);
    let mut size = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        bail!(
            "RegQueryValueExW({name}) size query failed with Win32 error {}",
            status.0
        );
    }
    if size == 0 {
        return Ok(Some(String::new()));
    }
    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            Some(buffer.as_mut_ptr()),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        bail!(
            "RegQueryValueExW({name}) data query failed with Win32 error {}",
            status.0
        );
    }
    buffer.truncate(size as usize);
    Ok(Some(decode_registry_string(&buffer)))
}

fn set_string(key: HKEY, name: &str, value: &str) -> Result<()> {
    let name_wide = wide(name);
    let data: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: Vec<u8> = data.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let status =
        unsafe { RegSetValueExW(key, PCWSTR(name_wide.as_ptr()), None, REG_SZ, Some(&bytes)) };
    if status != ERROR_SUCCESS {
        bail!(
            "RegSetValueExW({name}) failed with Win32 error {} (administrator required)",
            status.0
        );
    }
    Ok(())
}

fn delete_value(key: HKEY, name: &str) -> Result<()> {
    let name_wide = wide(name);
    let status = unsafe { RegDeleteValueW(key, PCWSTR(name_wide.as_ptr())) };
    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
        bail!(
            "RegDeleteValueW({name}) failed with Win32 error {}",
            status.0
        );
    }
    Ok(())
}

fn enum_subkeys(key: HKEY) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for index in 0.. {
        let mut buffer = [0u16; 256];
        let mut length = buffer.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                Some(PWSTR(buffer.as_mut_ptr())),
                &mut length,
                None,
                None,
                None,
                None,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS {
            bail!("RegEnumKeyExW failed with Win32 error {}", status.0);
        }
        names.push(String::from_utf16_lossy(&buffer[..length as usize]));
    }
    Ok(names)
}

pub(crate) fn elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

fn require_admin() -> Result<()> {
    if !elevated() {
        bail!(
            "Administrator privileges are required for this operation; \
             restart the terminal with UAC elevation"
        );
    }
    Ok(())
}

static SMB_TABLE: LazyLock<Option<Vec<u8>>> = LazyLock::new(fetch_smbios_table);

fn fetch_smbios_table() -> Option<Vec<u8>> {
    const RSMB: u32 = 0x5253_4D42;
    let size = unsafe { GetSystemFirmwareTable(FIRMWARE_TABLE_PROVIDER(RSMB), 0, None) };
    if size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    let written =
        unsafe { GetSystemFirmwareTable(FIRMWARE_TABLE_PROVIDER(RSMB), 0, Some(&mut buffer)) };
    if written == 0 {
        return None;
    }
    buffer.truncate((written as usize).min(buffer.len()));
    Some(buffer)
}

pub(crate) fn smbios_data() -> Option<SmbiosData> {
    SMB_TABLE.as_ref().and_then(|raw| smbios::parse_raw(raw))
}

fn optional(value: Option<String>, reason: &str) -> Value {
    match value {
        Some(value) => Value::known(value),
        None => Value::unavailable(reason),
    }
}

pub(crate) fn detect_cpu() -> CpuInfo {
    match open_key(CPU_KEY, KEY_READ) {
        Ok(key) => {
            let vendor = read_string(key.0, "VendorIdentifier").ok().flatten();
            let model = read_string(key.0, "ProcessorNameString")
                .ok()
                .flatten()
                .or_else(|| read_string(key.0, "Identifier").ok().flatten());
            CpuInfo {
                vendor: optional(vendor, "VendorIdentifier missing from the registry"),
                model: optional(model, "ProcessorNameString missing from the registry"),
                family: None,
                model_number: None,
                stepping: None,
                logical_cpus: None,
                microcode: None,
            }
        }
        Err(error) => CpuInfo {
            vendor: Value::unavailable(format!("failed to open {CPU_KEY}: {error:#}")),
            model: Value::unavailable(format!("failed to open {CPU_KEY}: {error:#}")),
            family: None,
            model_number: None,
            stepping: None,
            logical_cpus: None,
            microcode: None,
        },
    }
}

pub(crate) fn detect_gpus() -> Vec<GpuInfo> {
    let Ok(class) = open_key(DISPLAY_CLASS, KEY_READ) else {
        return Vec::new();
    };
    let Ok(subkeys) = enum_subkeys(class.0) else {
        return Vec::new();
    };
    let mut gpus = Vec::new();
    for subkey in subkeys {
        if !subkey.chars().all(|character| character.is_ascii_digit()) {
            continue;
        }
        let path = format!(r"{DISPLAY_CLASS}\{subkey}");
        let Ok(key) = open_key(&path, KEY_READ) else {
            continue;
        };
        let Some(description) = read_string(key.0, "DriverDesc").ok().flatten() else {
            continue;
        };
        let matching = read_string(key.0, "MatchingDeviceId").ok().flatten();
        let (vendor_id, device_id) = matching
            .as_deref()
            .map(parse_pci_ids)
            .unwrap_or((None, None));
        gpus.push(GpuInfo {
            name: description,
            vendor_id,
            device_id,
            driver: None,
        });
    }
    gpus.sort_by(|a, b| a.name.cmp(&b.name));
    gpus
}

fn parse_pci_ids(matching: &str) -> (Option<String>, Option<String>) {
    let mut vendor = None;
    let mut device = None;
    for part in matching.split('&') {
        if let Some(value) = part.strip_prefix("VEN_") {
            vendor = Some(value.trim_start_matches("VEN_").to_string());
        } else if let Some(value) = part.strip_prefix("DEV_") {
            device = Some(value.to_string());
        }
    }
    (vendor, device)
}

pub(crate) fn detect_interfaces() -> Result<Vec<NetworkInterface>> {
    let mut size = 16 * 1024u32;
    let mut buffer: Vec<usize> = Vec::new();
    loop {
        buffer.clear();
        buffer.resize((size as usize).div_ceil(size_of::<usize>()), 0);
        let result = unsafe {
            GetAdaptersAddresses(
                0, // AF_UNSPEC
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if result == ERROR_SUCCESS.0 {
            break;
        }
        if result == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        bail!("GetAdaptersAddresses failed with Win32 error {result}");
    }

    let mut interfaces = Vec::new();
    let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let friendly = unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default();
        let description = unsafe { adapter.Description.to_string() }.unwrap_or_default();
        let guid = unsafe { adapter.AdapterName.to_string() }.ok();
        let length = (adapter.PhysicalAddressLength as usize).min(8);
        if length == 6 {
            let mut octets = [0u8; 6];
            octets.copy_from_slice(&adapter.PhysicalAddress[..6]);
            let mac = MacAddress::from_octets(octets);
            let kind = match adapter.IfType {
                6 => InterfaceKind::Ethernet,
                71 => InterfaceKind::Wifi,
                _ => InterfaceKind::Other,
            };
            let lower_description = description.to_ascii_lowercase();
            let lower_name = friendly.to_ascii_lowercase();
            let virtual_device = matches!(adapter.IfType, 24 | 131)
                || [
                    "virtual",
                    "vpn",
                    "tap-windows",
                    "tun",
                    "hyper-v",
                    "vmware",
                    "virtualbox",
                    "loopback",
                ]
                .iter()
                .any(|needle| lower_description.contains(needle) || lower_name.contains(needle));
            let has_override = guid
                .as_deref()
                .and_then(|guid| read_network_address(guid).ok().flatten())
                .is_some();
            interfaces.push(NetworkInterface {
                name: if friendly.is_empty() {
                    description.clone()
                } else {
                    friendly
                },
                description,
                mac,
                permanent_mac: if has_override { None } else { Some(mac) },
                virtual_device,
                up: adapter.OperStatus == IfOperStatusUp,
                kind,
                guid,
            });
        }
        current = adapter.Next;
    }
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

pub(crate) fn detect_disks() -> Vec<DiskInfo> {
    let mut disks = Vec::new();
    for index in 0..32u32 {
        let path = format!(r"\\.\PhysicalDrive{index}");
        let path_wide = HSTRING::from(path.as_str());
        let handle = match unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(handle) => handle,
            Err(_) => {
                let last_error = unsafe { windows::Win32::Foundation::GetLastError() };
                if last_error == windows::Win32::Foundation::ERROR_ACCESS_DENIED {
                    disks.push(DiskInfo {
                        name: format!("PhysicalDrive{index}"),
                        model: None,
                        serial: Value::unavailable(
                            "access denied opening the raw drive; Administrator privileges are required to read its serial",
                        ),
                        size_bytes: None,
                        bus: None,
                        rotational: None,
                    });
                }
                break;
            }
        };

        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut output = vec![0usize; 1024 / size_of::<usize>()];
        let mut returned = 0u32;
        let result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                Some(&query as *const _ as *const c_void),
                size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                Some(output.as_mut_ptr() as *mut c_void),
                (output.len() * size_of::<usize>()) as u32,
                Some(&mut returned),
                None,
            )
        };
        let mut size_bytes = None;
        if result.is_ok() && returned as usize >= size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            let bytes = unsafe {
                std::slice::from_raw_parts(output.as_ptr() as *const u8, returned as usize)
            };
            let descriptor = unsafe { &*(bytes.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
            let model = ascii_at(bytes, descriptor.ProductIdOffset);
            let serial = ascii_at(bytes, descriptor.SerialNumberOffset);
            let bus = match descriptor.BusType {
                bus if bus == BusTypeNvme => Some("nvme".to_string()),
                bus if bus == BusTypeSata => Some("sata".to_string()),
                bus if bus == BusTypeUsb => Some("usb".to_string()),
                _ => None,
            };
            let mut file_size = 0i64;
            if unsafe { GetFileSizeEx(handle, &mut file_size) }.is_ok() && file_size > 0 {
                size_bytes = Some(file_size as u64);
            }
            let serial = match serial {
                Some(serial) => Value::known(serial),
                None => Value::unavailable(
                    "drive descriptor has no serial number (SerialNumberOffset is zero)",
                ),
            };
            disks.push(DiskInfo {
                name: format!("PhysicalDrive{index}"),
                model,
                serial,
                size_bytes,
                bus,
                rotational: None,
            });
        }
        let _ = unsafe { CloseHandle(handle) };
    }
    disks
}

fn ascii_at(buffer: &[u8], offset: u32) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let start = offset as usize;
    if start >= buffer.len() {
        return None;
    }
    let end = buffer[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| start + position)
        .unwrap_or(buffer.len());
    let text = String::from_utf8_lossy(&buffer[start..end])
        .trim()
        .to_string();
    (!text.is_empty()).then_some(text)
}

fn find_adapter_key(guid: &str) -> Result<Option<String>> {
    let class = open_key(NETWORK_CLASS, KEY_READ)?;
    for subkey in enum_subkeys(class.0)? {
        if !subkey.chars().all(|character| character.is_ascii_digit()) {
            continue;
        }
        let path = format!(r"{NETWORK_CLASS}\{subkey}");
        let Ok(key) = open_key(&path, KEY_READ) else {
            continue;
        };
        if let Ok(Some(instance)) = read_string(key.0, "NetCfgInstanceId") {
            if instance.eq_ignore_ascii_case(guid) {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

fn read_network_address(guid: &str) -> Result<Option<String>> {
    let Some(path) = find_adapter_key(guid)? else {
        return Ok(None);
    };
    let key = open_key(&path, KEY_READ)?;
    read_string(key.0, NETWORK_ADDRESS_VALUE)
}

fn write_network_address(guid: &str, value: Option<&str>) -> Result<()> {
    let path = find_adapter_key(guid)?
        .with_context(|| format!("no adapter registry key found for {guid}"))?;
    let key = open_key(&path, KEY_READ | KEY_WRITE)?;
    match value {
        Some(value) => set_string(key.0, NETWORK_ADDRESS_VALUE, value),
        None => delete_value(key.0, NETWORK_ADDRESS_VALUE),
    }
}

fn restart_adapter(name: &str) -> Result<&'static str> {
    let escaped = name.replace('\'', "''");
    let script = format!("Restart-NetAdapter -Name '{escaped}' -Confirm:$false -ErrorAction Stop");
    let powershell = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status();
    if let Ok(status) = powershell {
        if status.success() {
            return Ok("Restart-NetAdapter");
        }
    }

    let disabled = Command::new("netsh")
        .args([
            "interface",
            "set",
            "interface",
            &format!("name={name}"),
            "admin=disable",
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    sleep(Duration::from_secs(1));
    let enabled = Command::new("netsh")
        .args([
            "interface",
            "set",
            "interface",
            &format!("name={name}"),
            "admin=enable",
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if disabled && enabled {
        Ok("netsh disable/enable")
    } else {
        bail!(
            "failed to restart adapter '{name}' with Restart-NetAdapter and with netsh; \
             the adapter must be restarted for NetworkAddress to take effect"
        )
    }
}

fn wait_for_mac(guid: &str, expected: MacAddress, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(interfaces) = detect_interfaces() {
            if interfaces.iter().any(|interface| {
                interface
                    .guid
                    .as_deref()
                    .map(|candidate| candidate.eq_ignore_ascii_case(guid))
                    .unwrap_or(false)
                    && interface.mac == expected
            }) {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(250));
    }
}

impl Platform for Windows {
    fn context(&self) -> SystemContext {
        let elevated = elevated();
        let (product, display, build) = windows_version();
        SystemContext {
            os: format!("{product} {display} (build {build})"),
            arch: std::env::consts::ARCH.to_string(),
            elevated,
            privilege: if elevated {
                "Administrator".to_string()
            } else {
                "standard user".to_string()
            },
            user: std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string()),
            hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
        }
    }

    fn board(&self) -> BoardInfo {
        hardware::motherboard::detect()
    }

    fn bios(&self) -> BiosInfo {
        hardware::bios::detect()
    }

    fn system(&self) -> SystemInfo {
        match smbios_data() {
            Some(data) => SystemInfo {
                manufacturer: optional(data.system_manufacturer, "not present in the SMBIOS table"),
                product_name: optional(data.system_product, "not present in the SMBIOS table"),
                serial: optional(data.system_serial, "not present in the SMBIOS table"),
                uuid: optional(data.system_uuid, "SMBIOS table has no usable system UUID"),
            },
            None => SystemInfo {
                manufacturer: Value::unavailable(
                    "SMBIOS table unavailable (GetSystemFirmwareTable failed)",
                ),
                product_name: Value::unavailable(
                    "SMBIOS table unavailable (GetSystemFirmwareTable failed)",
                ),
                serial: Value::unavailable(
                    "SMBIOS table unavailable (GetSystemFirmwareTable failed)",
                ),
                uuid: Value::unavailable(
                    "SMBIOS table unavailable (GetSystemFirmwareTable failed)",
                ),
            },
        }
    }

    fn cpu(&self) -> CpuInfo {
        hardware::cpu::detect()
    }

    fn gpus(&self) -> Vec<GpuInfo> {
        hardware::gpu::detect()
    }

    fn disks(&self) -> Vec<DiskInfo> {
        hardware::disk::detect()
    }

    fn interfaces(&self) -> Result<Vec<NetworkInterface>> {
        hardware::network::detect()
    }

    fn machine_identity(&self) -> MachineIdentity {
        let value = match open_key(MACHINE_GUID_KEY, KEY_READ)
            .and_then(|key| read_string(key.0, "MachineGuid"))
        {
            Ok(Some(value)) if !value.trim().is_empty() => Value::known(value.trim().to_string()),
            Ok(_) => Value::unavailable("MachineGuid registry value is missing or empty"),
            Err(error) => Value::unavailable(format!("failed to read MachineGuid: {error:#}")),
        };
        MachineIdentity {
            value,
            source: MACHINE_GUID_SOURCE.to_string(),
            format: IdentityFormat::Uuid,
        }
    }

    fn mac_supported(&self) -> bool {
        true
    }

    fn identity_supported(&self) -> bool {
        true
    }

    fn mac_method(&self) -> &'static str {
        "vendor-supported adapter NetworkAddress registry value (HKLM network class key) followed by Restart-NetAdapter or netsh disable/enable"
    }

    fn identity_method(&self) -> &'static str {
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid registry rewrite (REG_SZ, Administrator)"
    }

    fn mac_persistence_note(&self) -> &'static str {
        "Windows changes are persistent: the NetworkAddress value survives reboot. `restore` removes or resets it and restarts the adapter"
    }

    fn required_privilege(&self) -> Privilege {
        Privilege::Administrator
    }

    fn apply_mac(&self, iface: &NetworkInterface, mac: &MacAddress) -> Result<Actions> {
        require_admin()?;
        mac.validate_for_spoof()?;
        if iface.virtual_device {
            bail!(
                "{} is a virtual adapter; only physical adapters are supported",
                iface.name
            );
        }
        let guid = iface
            .guid
            .as_deref()
            .with_context(|| format!("{} has no adapter GUID", iface.name))?;
        let registry_value = mac.to_hex_upper();

        let mut actions = Vec::new();
        write_network_address(guid, Some(&registry_value))
            .context("failed to write the adapter NetworkAddress value")?;
        actions.push(format!(
            "wrote NetworkAddress={registry_value} to the adapter's registry key"
        ));
        let method = restart_adapter(&iface.name)?;
        actions.push(format!("restarted the adapter via {method}"));
        if !wait_for_mac(guid, *mac, Duration::from_secs(20)) {
            bail!(
                "adapter restart completed but {guid} did not report {mac} within 20 seconds; \
                 the driver may ignore the NetworkAddress override"
            );
        }
        actions.push("adapter reports the new MAC through GetAdaptersAddresses".to_string());
        Ok(actions)
    }

    fn restore_mac(
        &self,
        iface: &NetworkInterface,
        mac: &MacAddress,
        prior_override: Option<&str>,
    ) -> Result<Actions> {
        require_admin()?;
        let guid = iface
            .guid
            .as_deref()
            .with_context(|| format!("{} has no adapter GUID", iface.name))?;
        let mut actions = Vec::new();
        match prior_override {
            Some(value) => {
                write_network_address(guid, Some(value))
                    .context("failed to restore the pre-existing NetworkAddress value")?;
                actions.push(format!(
                    "restored the pre-existing NetworkAddress={value} registry value"
                ));
            }
            None => {
                write_network_address(guid, None)
                    .context("failed to remove the NetworkAddress override")?;
                actions.push("removed the NetworkAddress override".to_string());
            }
        }
        let method = restart_adapter(&iface.name)?;
        actions.push(format!("restarted the adapter via {method}"));
        if !wait_for_mac(guid, *mac, Duration::from_secs(20)) {
            bail!(
                "adapter restart completed but {guid} did not report the restored MAC {mac}; \
                 the driver may be using another address source"
            );
        }
        actions.push("adapter reports the restored MAC through GetAdaptersAddresses".to_string());
        Ok(actions)
    }

    fn existing_mac_override(&self, iface: &NetworkInterface) -> Result<Option<String>> {
        let guid = iface
            .guid
            .as_deref()
            .with_context(|| format!("{} has no adapter GUID", iface.name))?;
        read_network_address(guid)
    }

    fn apply_machine_identity(&self, value: &str) -> Result<()> {
        require_admin()?;
        if !is_uuid(value) {
            bail!("MachineGuid must be an RFC 4122 UUID, got '{value}'");
        }
        let key = open_key(MACHINE_GUID_KEY, KEY_READ | KEY_WRITE)
            .context("failed to open the MachineGuid registry key")?;
        set_string(key.0, "MachineGuid", value)
            .context("failed to write MachineGuid; Administrator privileges required")?;
        Ok(())
    }
}

fn windows_version() -> (String, String, String) {
    match open_key(WINDOWS_VERSION_KEY, KEY_READ) {
        Ok(key) => {
            let product = read_string(key.0, "ProductName")
                .ok()
                .flatten()
                .unwrap_or_else(|| "Windows".to_string());
            let display = read_string(key.0, "DisplayVersion")
                .ok()
                .flatten()
                .unwrap_or_else(|| "unknown version".to_string());
            let build = read_string(key.0, "CurrentBuild")
                .ok()
                .flatten()
                .unwrap_or_else(|| "unknown build".to_string());
            (product, display, build)
        }
        Err(_) => (
            "Windows".to_string(),
            "unknown version".to_string(),
            "unknown build".to_string(),
        ),
    }
}

fn is_uuid(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(parts.iter())
            .all(|(length, part)| {
                part.len() == *length && part.chars().all(|c| c.is_ascii_hexdigit())
            })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pci_identifiers() {
        let (vendor, device) = parse_pci_ids(r"PCI\VEN_1002&DEV_1681&SUBSYS_12345678");
        assert_eq!(vendor.as_deref(), Some("1002"));
        assert_eq!(device.as_deref(), Some("1681"));
    }

    #[test]
    fn validates_machine_guid_format() {
        assert!(is_uuid("4f4d4a2e-5c3b-4c2b-9f1e-0123456789ab"));
        assert!(!is_uuid("not-a-guid"));
        assert!(!is_uuid("4f4d4a2e-5c3b-4c2b-9f1e-0123456789a"));
    }

    #[test]
    fn decodes_utf16_registry_data() {
        let bytes: Vec<u8> = "Ethernet"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(decode_registry_string(&bytes), "Ethernet");
    }
}
