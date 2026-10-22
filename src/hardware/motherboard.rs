//! Baseboard (motherboard) identification.
//!
//! Linux: `/sys/class/dmi/id` exposed by the kernel from SMBIOS.
//! Windows: raw SMBIOS Type 2 through `GetSystemFirmwareTable`.

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::path::Path;

use super::{BoardInfo, Value};

#[cfg(target_os = "linux")]
pub fn detect() -> BoardInfo {
    BoardInfo {
        vendor: read_dmi("board_vendor"),
        name: read_dmi("board_name"),
        version: read_dmi("board_version"),
        serial: read_dmi("board_serial"),
    }
}

#[cfg(windows)]
pub fn detect() -> BoardInfo {
    let data = crate::platform::windows::smbios_data();
    match data {
        Some(data) => BoardInfo {
            vendor: option_value(data.board_manufacturer),
            name: option_value(data.board_product),
            version: option_value(data.board_version),
            serial: option_value(data.board_serial),
        },
        None => BoardInfo {
            vendor: Value::unavailable("SMBIOS table unavailable (GetSystemFirmwareTable failed)"),
            name: Value::unavailable("SMBIOS table unavailable (GetSystemFirmwareTable failed)"),
            version: Value::unavailable("SMBIOS table unavailable (GetSystemFirmwareTable failed)"),
            serial: Value::unavailable("SMBIOS table unavailable (GetSystemFirmwareTable failed)"),
        },
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn detect() -> BoardInfo {
    BoardInfo {
        vendor: Value::unavailable("platform not supported"),
        name: Value::unavailable("platform not supported"),
        version: Value::unavailable("platform not supported"),
        serial: Value::unavailable("platform not supported"),
    }
}

#[cfg(target_os = "linux")]
fn read_dmi(field: &str) -> Value {
    read_dmi_at(Path::new("/sys/class/dmi/id"), field)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_dmi_at(root: &Path, field: &str) -> Value {
    let path = root.join(field);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                Value::unavailable(format!("empty value exposed by {}", path.display()))
            } else {
                Value::known(trimmed)
            }
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => Value::unavailable(format!(
            "permission denied reading {}; DMI identity files are root-only, run as root",
            path.display()
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            Value::unavailable(format!("not exposed by this firmware ({})", path.display()))
        }
        Err(error) => Value::unavailable(format!("failed to read {}: {error}", path.display())),
    }
}

#[cfg(windows)]
fn option_value(value: Option<String>) -> Value {
    match value {
        Some(value) => Value::known(value),
        None => Value::unavailable("not present in the SMBIOS table"),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "hwid-spoofer-motherboard-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn reads_trimmed_dmi_value() {
        let dir = temp_dir("board");
        fs::write(dir.join("board_serial"), "  BOARD123\n").unwrap();
        assert_eq!(read_dmi_at(&dir, "board_serial"), Value::known("BOARD123"));
        assert!(read_dmi_at(&dir, "board_name")
            .display()
            .contains("not exposed"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reports_empty_values() {
        let dir = temp_dir("empty");
        fs::write(dir.join("board_serial"), "\n").unwrap();
        assert!(read_dmi_at(&dir, "board_serial")
            .display()
            .contains("empty value"));
        fs::remove_dir_all(dir).unwrap();
    }
}
