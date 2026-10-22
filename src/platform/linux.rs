//! Linux backend.
//!
//! Detection uses sysfs/DMI and procfs. MAC changes use the documented kernel
//! interface `ioctl(SIOCSIFHWADDR)` on a physical interface. Machine identity
//! changes use an atomic replacement of `/etc/machine-id` and its D-Bus copy.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use nix::unistd::Uid;

use super::{Actions, IdentityFormat, MachineIdentity, Platform, SystemContext};
use crate::hardware::motherboard::read_dmi_at;
use crate::hardware::network::{MacAddress, NetworkInterface};
use crate::hardware::{
    self, BiosInfo, BoardInfo, CpuInfo, DiskInfo, GpuInfo, Privilege, SystemInfo, Value,
};

const DMI_ROOT: &str = "/sys/class/dmi/id";
pub(crate) const MACHINE_ID_PATH: &str = "/etc/machine-id";
const DBUS_MACHINE_ID_PATH: &str = "/var/lib/dbus/machine-id";

pub struct Linux;

impl Linux {
    pub fn new() -> Self {
        Linux
    }
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn is_elevated() -> bool {
    Uid::effective().is_root()
}

fn require_root() -> Result<()> {
    if !is_elevated() {
        bail!(
            "root privileges are required for this operation; re-run with sudo (CAP_NET_ADMIN / write access to /etc)"
        );
    }
    Ok(())
}

impl Platform for Linux {
    fn context(&self) -> SystemContext {
        let elevated = is_elevated();
        let user = std::env::var("USER")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                nix::unistd::User::from_uid(Uid::effective())
                    .ok()
                    .flatten()
                    .map(|user| user.name)
            })
            .unwrap_or_else(|| "unknown".to_string());
        let hostname = nix::unistd::gethostname()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".to_string());

        SystemContext {
            os: os_pretty_name(),
            arch: std::env::consts::ARCH.to_string(),
            elevated,
            privilege: if elevated {
                "root".to_string()
            } else {
                "standard user".to_string()
            },
            user,
            hostname,
        }
    }

    fn board(&self) -> BoardInfo {
        hardware::motherboard::detect()
    }

    fn bios(&self) -> BiosInfo {
        hardware::bios::detect()
    }

    fn system(&self) -> SystemInfo {
        let root = Path::new(DMI_ROOT);
        SystemInfo {
            manufacturer: read_dmi_at(root, "sys_vendor"),
            product_name: read_dmi_at(root, "product_name"),
            serial: read_dmi_at(root, "product_serial"),
            uuid: read_dmi_at(root, "product_uuid"),
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
        let value = match fs::read_to_string(MACHINE_ID_PATH) {
            Ok(contents) => machine_id_value(&contents),
            Err(error) => Value::unavailable(format!("failed to read {MACHINE_ID_PATH}: {error}")),
        };
        MachineIdentity {
            value,
            source: MACHINE_ID_PATH.to_string(),
            format: IdentityFormat::Hex32,
        }
    }

    fn mac_supported(&self) -> bool {
        true
    }

    fn identity_supported(&self) -> bool {
        true
    }

    fn mac_method(&self) -> &'static str {
        "ioctl(SIOCSIFHWADDR) on the physical interface via AF_INET control socket; link is brought down only when the driver returns EBUSY"
    }

    fn identity_method(&self) -> &'static str {
        "atomic rewrite of /etc/machine-id (32 hex characters) plus the D-Bus machine-id copy when it is a regular file"
    }

    fn mac_persistence_note(&self) -> &'static str {
        "Linux MAC changes are runtime-only: the driver reloads the hardware address on reboot unless the change is re-applied by a unit"
    }

    fn required_privilege(&self) -> Privilege {
        Privilege::Root
    }

    fn apply_mac(&self, iface: &NetworkInterface, mac: &MacAddress) -> Result<Actions> {
        require_root()?;
        mac.validate_for_spoof()?;
        if iface.virtual_device {
            bail!(
                "{} is a virtual interface; only physical adapters can be spoofed",
                iface.name
            );
        }

        let name = iface.name.as_str();
        let mut actions = Vec::new();
        let original_flags = mac_ioctl::get_flags(name)
            .with_context(|| format!("failed to read link flags for {name}"))?;
        let was_up = original_flags & mac_ioctl::IFF_UP != 0;

        match mac_ioctl::set_mac(name, &mac.octets()) {
            Ok(()) => actions.push(format!(
                "ioctl(SIOCSIFHWADDR) applied {mac} while the link was up"
            )),
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                mac_ioctl::set_flags(name, original_flags & !mac_ioctl::IFF_UP)
                    .with_context(|| format!("failed to bring {name} down"))?;
                actions.push(format!(
                    "brought {name} down (driver requires it for address changes)"
                ));
                if let Err(set_error) = mac_ioctl::set_mac(name, &mac.octets()) {
                    let restore = mac_ioctl::set_flags(name, original_flags);
                    bail!(
                        "failed to set MAC on {name}: {set_error}; link flags restore {}",
                        if restore.is_ok() {
                            "succeeded"
                        } else {
                            "FAILED"
                        }
                    );
                }
                mac_ioctl::set_flags(name, original_flags).with_context(|| {
                    format!("MAC set, but failed to restore link flags for {name}")
                })?;
                actions.push(format!("restored original link flags for {name}"));
            }
            Err(error) => {
                bail!(
                    "ioctl(SIOCSIFHWADDR) failed for {name}: {error}. \
                     The driver or adapter does not permit MAC address changes"
                );
            }
        }

        let final_flags = mac_ioctl::get_flags(name)
            .with_context(|| format!("failed to re-read link flags for {name}"))?;
        if was_up && final_flags & mac_ioctl::IFF_UP == 0 {
            mac_ioctl::set_flags(name, final_flags | mac_ioctl::IFF_UP)
                .with_context(|| format!("failed to bring {name} back up"))?;
            actions.push(format!("brought {name} back up"));
        }

        Ok(actions)
    }

    fn restore_mac(
        &self,
        iface: &NetworkInterface,
        mac: &MacAddress,
        _prior_override: Option<&str>,
    ) -> Result<Actions> {
        // Linux has no persistent driver override in the Windows sense.
        self.apply_mac(iface, mac)
    }

    fn existing_mac_override(&self, _iface: &NetworkInterface) -> Result<Option<String>> {
        Ok(None)
    }

    fn apply_machine_identity(&self, value: &str) -> Result<()> {
        require_root()?;
        write_machine_id(Path::new(MACHINE_ID_PATH), value)?;

        let dbus = Path::new(DBUS_MACHINE_ID_PATH);
        match fs::symlink_metadata(dbus) {
            Ok(metadata) if metadata.file_type().is_file() => {
                write_machine_id(dbus, value).context(
                    "updated /etc/machine-id but failed to update /var/lib/dbus/machine-id",
                )?;
            }
            Ok(_) => {
                // Symlink (normally to /etc/machine-id) or absent: nothing to do.
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("failed to inspect /var/lib/dbus/machine-id");
            }
        }
        Ok(())
    }
}

fn machine_id_value(contents: &str) -> Value {
    let trimmed = contents.trim();
    if trimmed.is_empty() || trimmed == "uninitialized" {
        Value::unavailable(format!(
            "{MACHINE_ID_PATH} is not initialized (value: '{trimmed}')"
        ))
    } else {
        Value::known(trimmed)
    }
}

fn os_pretty_name() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim().trim_matches('"').to_string())
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Linux".to_string())
}

pub(crate) fn validate_machine_id(value: &str) -> Result<()> {
    if value.len() != 32 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        bail!("machine-id must be exactly 32 hexadecimal characters, got '{value}'");
    }
    Ok(())
}

/// Atomically replace a machine-id file, preserving the conventional 0444 mode.
/// Symlinks are followed so writing `/etc/machine-id` works when it is linked.
pub(crate) fn write_machine_id(path: &Path, value: &str) -> Result<()> {
    validate_machine_id(value)?;
    let target = resolve_target(path)?;
    let directory = target
        .parent()
        .with_context(|| format!("{} has no parent directory", target.display()))?;
    let file_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "machine-id".to_string());
    let temporary = directory.join(format!(
        ".{file_name}.hwid-spoofer.{}.tmp",
        std::process::id()
    ));

    let result = (|| -> Result<()> {
        let mut file = fs::File::create(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(value.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
        fs::rename(&temporary, &target)
            .with_context(|| format!("failed to replace {}", target.display()))?;
        if let Ok(directory_handle) = fs::File::open(directory) {
            let _ = directory_handle.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn resolve_target(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::canonicalize(path)
            .with_context(|| format!("failed to resolve symlink {}", path.display())),
        _ => Ok(path.to_path_buf()),
    }
}

#[cfg(target_os = "linux")]
mod mac_ioctl {
    use std::io;

    use libc::{c_char, c_int, c_short, c_ulong, c_ushort};

    const SIOCSIFHWADDR: c_ulong = 0x8924;
    const SIOCGIFFLAGS: c_ulong = 0x8913;
    const SIOCSIFFLAGS: c_ulong = 0x8914;
    pub const IFF_UP: c_short = 0x1;
    const ARPHRD_ETHER: c_ushort = 1;
    const IFREQ_SIZE: usize = 40;

    #[repr(C)]
    struct IfReqHwAddr {
        name: [c_char; libc::IFNAMSIZ],
        family: c_ushort,
        data: [u8; 14],
        _pad: [u8; 8],
    }

    #[repr(C)]
    struct IfReqFlags {
        name: [c_char; libc::IFNAMSIZ],
        flags: c_short,
        _pad: [u8; 22],
    }

    const _: () = assert!(std::mem::size_of::<IfReqHwAddr>() == IFREQ_SIZE);
    const _: () = assert!(std::mem::size_of::<IfReqFlags>() == IFREQ_SIZE);

    struct ControlSocket(c_int);

    impl ControlSocket {
        fn open() -> io::Result<Self> {
            let fd =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ControlSocket(fd))
            }
        }

        fn ioctl<T>(&self, request: c_ulong, value: &mut T) -> io::Result<()> {
            let result = unsafe { libc::ioctl(self.0, request, value as *mut T) };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for ControlSocket {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    fn interface_name(name: &str) -> io::Result<[c_char; libc::IFNAMSIZ]> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid network interface name '{name}'"),
            ));
        }
        let mut bytes = [0 as c_char; libc::IFNAMSIZ];
        for (index, byte) in name.bytes().enumerate() {
            bytes[index] = byte as c_char;
        }
        Ok(bytes)
    }

    pub fn get_flags(name: &str) -> io::Result<c_short> {
        let socket = ControlSocket::open()?;
        let mut request = IfReqFlags {
            name: interface_name(name)?,
            flags: 0,
            _pad: [0; 22],
        };
        socket.ioctl(SIOCGIFFLAGS, &mut request)?;
        Ok(request.flags)
    }

    pub fn set_flags(name: &str, flags: c_short) -> io::Result<()> {
        let socket = ControlSocket::open()?;
        let mut request = IfReqFlags {
            name: interface_name(name)?,
            flags,
            _pad: [0; 22],
        };
        socket.ioctl(SIOCSIFFLAGS, &mut request)
    }

    pub fn set_mac(name: &str, mac: &[u8; 6]) -> io::Result<()> {
        let socket = ControlSocket::open()?;
        let mut request = IfReqHwAddr {
            name: interface_name(name)?,
            family: ARPHRD_ETHER,
            data: [0; 14],
            _pad: [0; 8],
        };
        request.data[..6].copy_from_slice(mac);
        socket.ioctl(SIOCSIFHWADDR, &mut request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "hwid-spoofer-identity-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn writes_machine_id_atomically_with_expected_mode() {
        let directory = temp_path("write");
        let path = directory.join("machine-id");
        fs::write(&path, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n").unwrap();

        write_machine_id(&path, "0123456789abcdef0123456789abcdef").unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "0123456789abcdef0123456789abcdef\n");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o444);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn treats_uninitialized_machine_id_as_unavailable() {
        assert!(matches!(
            machine_id_value("uninitialized\n"),
            Value::Unavailable { .. }
        ));
        assert!(matches!(machine_id_value("\n"), Value::Unavailable { .. }));
        assert_eq!(
            machine_id_value("0123456789abcdef0123456789abcdef\n"),
            Value::known("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn rejects_malformed_machine_ids() {
        assert!(validate_machine_id("not-hex").is_err());
        assert!(validate_machine_id("0123456789abcdef0123456789abcde").is_err());
        assert!(validate_machine_id("0123456789abcdef0123456789abcdef").is_ok());
    }

    #[test]
    fn restores_machine_id_from_backup_value() {
        let directory = temp_path("restore");
        let path = directory.join("machine-id");
        fs::write(&path, "ffffffffffffffffffffffffffffffff\n").unwrap();
        write_machine_id(&path, "11111111111111111111111111111111").unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap().trim(),
            "11111111111111111111111111111111"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ioctl_helpers_reject_oversized_names() {
        let long_name = "a".repeat(64);
        assert!(mac_ioctl::get_flags(&long_name).is_err());
        assert!(mac_ioctl::set_mac(&long_name, &[2, 0, 0, 0, 0, 1]).is_err());
    }
}
