//! Hardware identifier detection and capability model.
//!
//! Every value in a report comes from a real platform query: sysfs/DMI on
//! Linux, firmware tables, registry, and device IOCTLs on Windows. There are no
//! synthetic values and no optimistic "supported" flags.

pub mod bios;
pub mod cpu;
pub mod disk;
pub mod gpu;
pub mod motherboard;
pub mod network;
#[cfg(any(windows, test))]
pub mod smbios;

use serde::Serialize;

use crate::platform::{MachineIdentity, Platform, SystemContext};
use network::NetworkInterface;

/// Privilege level needed to perform a modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    None,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Root,
    #[cfg_attr(not(windows), allow(dead_code))]
    Administrator,
}

impl Privilege {
    pub fn label(self) -> &'static str {
        match self {
            Privilege::None => "none",
            Privilege::Root => "root",
            Privilege::Administrator => "Administrator",
        }
    }

    pub fn satisfied_by(self, elevated: bool) -> bool {
        self == Privilege::None || elevated
    }
}

/// A detected value or an explicit explanation of why it is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Value {
    Known { value: String },
    Unavailable { reason: String },
}

impl Value {
    pub fn known(value: impl Into<String>) -> Self {
        Value::Known {
            value: value.into(),
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Value::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Known { value } => Some(value),
            Value::Unavailable { .. } => None,
        }
    }

    pub fn display(&self) -> String {
        match self {
            Value::Known { value } => value.clone(),
            Value::Unavailable { reason } => format!("unavailable ({reason})"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BoardInfo {
    pub vendor: Value,
    pub name: Value,
    pub version: Value,
    pub serial: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct BiosInfo {
    pub vendor: Value,
    pub version: Value,
    pub release_date: Value,
    /// SMBIOS Type 0 defines no serial field; kept explicit instead of faking one.
    pub serial: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub manufacturer: Value,
    pub product_name: Value,
    pub serial: Value,
    pub uuid: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuInfo {
    pub vendor: Value,
    pub model: Value,
    pub family: Option<String>,
    pub model_number: Option<String>,
    pub stepping: Option<String>,
    pub logical_cpus: Option<u32>,
    pub microcode: Option<String>,
}

impl CpuInfo {
    /// A single line that identifies the CPU, used by `scan` and `capabilities`.
    pub fn summary(&self) -> Value {
        if let Some(model) = self.model.as_str() {
            let mut details = Vec::new();
            if let Some(family) = &self.family {
                details.push(format!("family {family}"));
            }
            if let Some(model_number) = &self.model_number {
                details.push(format!("model {model_number}"));
            }
            if let Some(stepping) = &self.stepping {
                details.push(format!("stepping {stepping}"));
            }
            if details.is_empty() {
                return Value::known(model);
            }
            return Value::known(format!("{model} [{}]", details.join(", ")));
        }
        match &self.vendor {
            Value::Known { value } => Value::known(value.clone()),
            Value::Unavailable { reason } => Value::unavailable(reason.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GpuInfo {
    pub name: String,
    pub vendor_id: Option<String>,
    pub device_id: Option<String>,
    pub driver: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub name: String,
    pub model: Option<String>,
    pub serial: Value,
    pub size_bytes: Option<u64>,
    pub bus: Option<String>,
    pub rotational: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Identifier {
    pub id: &'static str,
    pub label: &'static str,
    pub value: Value,
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub id: &'static str,
    pub label: &'static str,
    pub current: Value,
    pub firmware_controlled: bool,
    pub supported: bool,
    pub method: Option<String>,
    pub privileges: Privilege,
    pub requires_restart: bool,
    pub reasons: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardwareDetails {
    pub motherboard: BoardInfo,
    pub bios: BiosInfo,
    pub system: SystemInfo,
    pub cpu: CpuInfo,
    pub gpus: Vec<GpuInfo>,
    pub disks: Vec<DiskInfo>,
    pub interfaces: Vec<NetworkInterface>,
    pub machine_identity: MachineIdentity,
}

/// Everything obtained from live inspection during one command.
#[derive(Debug, Clone)]
pub struct Inventory {
    pub system: SystemContext,
    pub hardware: HardwareDetails,
}

impl Inventory {
    pub fn collect(platform: &dyn Platform) -> anyhow::Result<Self> {
        let interfaces = platform.interfaces()?;
        Ok(Inventory {
            system: platform.context(),
            hardware: HardwareDetails {
                motherboard: platform.board(),
                bios: platform.bios(),
                system: platform.system(),
                cpu: platform.cpu(),
                gpus: platform.gpus(),
                disks: platform.disks(),
                interfaces,
                machine_identity: platform.machine_identity(),
            },
        })
    }

    pub fn identifiers(&self) -> Vec<Identifier> {
        let hw = &self.hardware;
        let disk_value = join_disk_serials(&hw.disks);
        let gpu_value = join_gpu_names(&hw.gpus);
        let mac_value = join_macs(&hw.interfaces);

        vec![
            Identifier {
                id: "motherboard_serial",
                label: "Motherboard Serial",
                value: hw.motherboard.serial.clone(),
                source: identifier_source("motherboard_serial"),
            },
            Identifier {
                id: "bios",
                label: "BIOS (Vendor/Version/Date)",
                value: bios::summary(&hw.bios),
                source: identifier_source("bios"),
            },
            Identifier {
                id: "bios_serial",
                label: "BIOS Serial",
                value: hw.bios.serial.clone(),
                source: identifier_source("bios_serial"),
            },
            Identifier {
                id: "system_uuid",
                label: "System UUID",
                value: hw.system.uuid.clone(),
                source: identifier_source("system_uuid"),
            },
            Identifier {
                id: "disk_serial",
                label: "Disk Serial",
                value: disk_value,
                source: identifier_source("disk_serial"),
            },
            Identifier {
                id: "cpu",
                label: "CPU Identifier",
                value: hw.cpu.summary(),
                source: identifier_source("cpu"),
            },
            Identifier {
                id: "gpu",
                label: "GPU Identifier",
                value: gpu_value,
                source: identifier_source("gpu"),
            },
            Identifier {
                id: "mac",
                label: "MAC Address",
                value: mac_value,
                source: identifier_source("mac"),
            },
            Identifier {
                id: "machine_identity",
                label: "Machine Identity",
                value: hw.machine_identity.value.clone(),
                source: identifier_source("machine_identity"),
            },
        ]
    }

    pub fn capabilities(&self, platform: &dyn Platform) -> Vec<Capability> {
        let hw = &self.hardware;
        let physical_interfaces: Vec<&NetworkInterface> = hw
            .interfaces
            .iter()
            .filter(|iface| iface.mac_spoof_supported())
            .collect();

        let mac_supported = !physical_interfaces.is_empty() && platform.mac_supported();
        let mut mac_reasons = Vec::new();
        if physical_interfaces.is_empty() {
            mac_reasons.push(
                "no physical Ethernet or Wi-Fi adapter detected (virtual adapters are not spoofed)"
                    .to_string(),
            );
        }
        if !platform.mac_supported() {
            mac_reasons.push(platform.unsupported_reason().to_string());
        }

        let mut capabilities = vec![
            Capability {
                id: "motherboard_serial",
                label: "Motherboard Serial",
                current: hw.motherboard.serial.clone(),
                firmware_controlled: true,
                supported: false,
                method: None,
                privileges: Privilege::None,
                requires_restart: false,
                reasons: vec![
                    "SMBIOS Type 2 baseboard serial is firmware data; there is no supported OS write interface".to_string(),
                    "Changing it requires a vendor firmware procedure and is outside this tool's scope".to_string(),
                ],
                notes: Vec::new(),
            },
            Capability {
                id: "bios_serial",
                label: "BIOS Serial",
                current: hw.bios.serial.clone(),
                firmware_controlled: true,
                supported: false,
                method: None,
                privileges: Privilege::None,
                requires_restart: false,
                reasons: vec![
                    "SMBIOS Type 0 (BIOS Information) has no serial number field".to_string(),
                    "vendor, version, and release date are readable but firmware-controlled and read-only".to_string(),
                ],
                notes: Vec::new(),
            },
            Capability {
                id: "system_uuid",
                label: "System UUID",
                current: hw.system.uuid.clone(),
                firmware_controlled: true,
                supported: false,
                method: None,
                privileges: Privilege::None,
                requires_restart: false,
                reasons: vec![
                    "SMBIOS Type 1 UUID is firmware data; writing it is vendor-specific and not a supported OS interface".to_string(),
                ],
                notes: Vec::new(),
            },
            Capability {
                id: "disk_serial",
                label: "Disk Serial",
                current: join_disk_serials(&hw.disks),
                firmware_controlled: true,
                supported: false,
                method: None,
                privileges: Privilege::None,
                requires_restart: false,
                reasons: vec![
                    "ATA/NVMe identify data lives in the drive controller; no supported OS write interface exists".to_string(),
                ],
                notes: Vec::new(),
            },
            Capability {
                id: "cpu",
                label: "CPU Identifier",
                current: hw.cpu.summary(),
                firmware_controlled: true,
                supported: false,
                method: None,
                privileges: Privilege::None,
                requires_restart: false,
                reasons: vec!["CPU vendor/model/CPUID identity is fixed silicon and firmware data".to_string()],
                notes: Vec::new(),
            },
            Capability {
                id: "gpu",
                label: "GPU Identifier",
                current: join_gpu_names(&hw.gpus),
                firmware_controlled: true,
                supported: false,
                method: None,
                privileges: Privilege::None,
                requires_restart: false,
                reasons: vec!["PCI vendor/device IDs and VBIOS identity are firmware-controlled".to_string()],
                notes: Vec::new(),
            },
            Capability {
                id: "mac",
                label: "MAC Address",
                current: join_macs(&hw.interfaces),
                firmware_controlled: false,
                supported: mac_supported,
                method: Some(platform.mac_method().to_string()),
                privileges: platform.required_privilege(),
                requires_restart: false,
                reasons: mac_reasons,
                notes: vec![
                    platform.mac_persistence_note().to_string(),
                    "Only physical Ethernet and Wi-Fi adapters are supported; virtual interfaces are rejected".to_string(),
                ],
            },
            Capability {
                id: "machine_identity",
                label: "Machine Identity",
                current: hw.machine_identity.value.clone(),
                firmware_controlled: false,
                supported: platform.identity_supported(),
                method: Some(platform.identity_method().to_string()),
                privileges: platform.required_privilege(),
                requires_restart: platform.identity_requires_restart(),
                reasons: if platform.identity_supported() {
                    Vec::new()
                } else {
                    vec![platform.unsupported_reason().to_string()]
                },
                notes: vec![
                    "Back up the original value before changing it; use `hwid-spoofer restore` to revert".to_string(),
                    "Software activation, service registration, and network identity may be affected".to_string(),
                ],
            },
        ];
        capabilities.shrink_to_fit();
        capabilities
    }
}

fn join_disk_serials(disks: &[DiskInfo]) -> Value {
    if disks.is_empty() {
        return Value::unavailable("no fixed disks detected");
    }
    let known: Vec<String> = disks
        .iter()
        .filter_map(|disk| {
            disk.serial
                .as_str()
                .map(|serial| format!("{}: {}", disk.name, serial))
        })
        .collect();
    if known.is_empty() {
        let reason = disks
            .iter()
            .find_map(|disk| match &disk.serial {
                Value::Unavailable { reason } => Some(reason.clone()),
                Value::Known { .. } => None,
            })
            .unwrap_or_else(|| "no serial exposed by any disk".to_string());
        return Value::unavailable(reason);
    }
    Value::known(known.join("; "))
}

fn join_gpu_names(gpus: &[GpuInfo]) -> Value {
    if gpus.is_empty() {
        return Value::unavailable("no PCI display device detected");
    }
    Value::known(
        gpus.iter()
            .map(|gpu| gpu.name.clone())
            .collect::<Vec<_>>()
            .join("; "),
    )
}

fn join_macs(interfaces: &[NetworkInterface]) -> Value {
    let addresses: Vec<String> = interfaces
        .iter()
        .filter(|iface| !iface.mac.is_zero())
        .map(|iface| format!("{}: {}", iface.name, iface.mac))
        .collect();
    if addresses.is_empty() {
        return Value::unavailable("no adapter reports a non-zero MAC address");
    }
    Value::known(addresses.join("; "))
}

fn identifier_source(id: &str) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        match id {
            "motherboard_serial" => "/sys/class/dmi/id/board_serial",
            "bios" => "/sys/class/dmi/id/bios_version, bios_date",
            "bios_serial" => "SMBIOS Type 0 (no serial field)",
            "system_uuid" => "/sys/class/dmi/id/product_uuid",
            "disk_serial" => "/sys/block/*/device (NVMe/SCSI VPD)",
            "cpu" => "/proc/cpuinfo",
            "gpu" => "/sys/class/drm",
            "mac" => "/sys/class/net/*/address",
            "machine_identity" => "/etc/machine-id",
            _ => "unknown",
        }
    }
    #[cfg(windows)]
    {
        match id {
            "motherboard_serial" => "SMBIOS Type 2 (GetSystemFirmwareTable)",
            "bios" => "SMBIOS Type 0 (GetSystemFirmwareTable)",
            "bios_serial" => "SMBIOS Type 0 (no serial field)",
            "system_uuid" => "SMBIOS Type 1 (GetSystemFirmwareTable)",
            "disk_serial" => "IOCTL_STORAGE_QUERY_PROPERTY",
            "cpu" => "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor",
            "gpu" => "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-...}",
            "mac" => "GetAdaptersAddresses",
            "machine_identity" => "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid",
            _ => "unknown",
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = id;
        "unsupported platform"
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub system: SystemContext,
    pub identifiers: Vec<Identifier>,
    pub capabilities: Vec<Capability>,
    pub hardware: HardwareDetails,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    pub system: SystemContext,
    pub capabilities: Vec<Capability>,
}

impl Inventory {
    pub fn scan_report(&self, platform: &dyn Platform) -> ScanReport {
        ScanReport {
            system: self.system.clone(),
            identifiers: self.identifiers(),
            capabilities: self.capabilities(platform),
            hardware: self.hardware.clone(),
        }
    }

    pub fn capability_report(&self, platform: &dyn Platform) -> CapabilityReport {
        CapabilityReport {
            system: self.system.clone(),
            capabilities: self.capabilities(platform),
        }
    }
}
