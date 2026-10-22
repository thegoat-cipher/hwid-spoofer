//! BIOS identification.
//!
//! SMBIOS Type 0 ("BIOS Information") exposes vendor, version, and release
//! date. It does not define a serial number field, so `serial` is reported as
//! unavailable instead of inventing a value.

use super::{BiosInfo, Value};

#[cfg(target_os = "linux")]
pub fn detect() -> BiosInfo {
    use super::motherboard::read_dmi_at;
    use std::path::Path;

    let root = Path::new("/sys/class/dmi/id");
    BiosInfo {
        vendor: read_dmi_at(root, "bios_vendor"),
        version: read_dmi_at(root, "bios_version"),
        release_date: read_dmi_at(root, "bios_date"),
        serial: Value::unavailable(
            "SMBIOS Type 0 (BIOS Information) defines no serial number field",
        ),
    }
}

#[cfg(windows)]
pub fn detect() -> BiosInfo {
    match crate::platform::windows::smbios_data() {
        Some(data) => BiosInfo {
            vendor: optional(data.bios_vendor, "not present in the SMBIOS table"),
            version: optional(data.bios_version, "not present in the SMBIOS table"),
            release_date: optional(data.bios_release_date, "not present in the SMBIOS table"),
            serial: Value::unavailable(
                "SMBIOS Type 0 (BIOS Information) defines no serial number field",
            ),
        },
        None => BiosInfo {
            vendor: Value::unavailable("SMBIOS table unavailable (GetSystemFirmwareTable failed)"),
            version: Value::unavailable("SMBIOS table unavailable (GetSystemFirmwareTable failed)"),
            release_date: Value::unavailable(
                "SMBIOS table unavailable (GetSystemFirmwareTable failed)",
            ),
            serial: Value::unavailable(
                "SMBIOS Type 0 (BIOS Information) defines no serial number field",
            ),
        },
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn detect() -> BiosInfo {
    let reason = "platform not supported";
    BiosInfo {
        vendor: Value::unavailable(reason),
        version: Value::unavailable(reason),
        release_date: Value::unavailable(reason),
        serial: Value::unavailable(reason),
    }
}

/// Human-readable vendor/version/date combination used by `scan`.
pub fn summary(info: &BiosInfo) -> Value {
    let mut parts = Vec::new();
    if let Some(vendor) = info.vendor.as_str() {
        parts.push(vendor.to_string());
    }
    if let Some(version) = info.version.as_str() {
        parts.push(version.to_string());
    }
    if let Some(date) = info.release_date.as_str() {
        parts.push(format!("({date})"));
    }
    if parts.is_empty() {
        let reason = match &info.vendor {
            Value::Unavailable { reason } => reason.clone(),
            Value::Known { .. } => "BIOS details unavailable".to_string(),
        };
        Value::unavailable(reason)
    } else {
        Value::known(parts.join(" "))
    }
}

#[cfg(windows)]
fn optional(value: Option<String>, reason: &str) -> Value {
    match value {
        Some(value) => Value::known(value),
        None => Value::unavailable(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_skips_missing_parts() {
        let info = BiosInfo {
            vendor: Value::known("Vendor"),
            version: Value::unavailable("missing"),
            release_date: Value::known("2025-01-01"),
            serial: Value::unavailable("no field"),
        };
        assert_eq!(summary(&info), Value::known("Vendor (2025-01-01)"));
    }
}
