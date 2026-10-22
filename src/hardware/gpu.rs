//! GPU identification through PCI/DRM sysfs (Linux) or the display driver
//! registry class (Windows).

use super::GpuInfo;

#[cfg(target_os = "linux")]
pub fn detect() -> Vec<GpuInfo> {
    detect_with_root(std::path::Path::new("/sys/class/drm"))
}

#[cfg(target_os = "linux")]
pub(crate) fn detect_with_root(root: &std::path::Path) -> Vec<GpuInfo> {
    use std::fs;

    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut gpus = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_card_name(&name) {
            continue;
        }
        let device = entry.path().join("device");
        let vendor_id = read_trimmed(&device.join("vendor"));
        let device_id = read_trimmed(&device.join("device"));
        if vendor_id.is_none() && device_id.is_none() {
            continue;
        }
        let driver = fs::read_link(device.join("driver")).ok().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        });
        let vendor = vendor_id
            .as_deref()
            .map(vendor_name)
            .unwrap_or("Unknown vendor");
        let name = match (&vendor_id, &device_id) {
            (Some(vendor_id), Some(device_id)) => {
                format!("{vendor} [{vendor_id}:{device_id}] ({name})")
            }
            _ => format!("{vendor} ({name})"),
        };
        gpus.push(GpuInfo {
            name,
            vendor_id,
            device_id,
            driver,
        });
    }
    gpus.sort_by(|a, b| a.name.cmp(&b.name));
    gpus
}

#[cfg(windows)]
pub fn detect() -> Vec<GpuInfo> {
    crate::platform::windows::detect_gpus()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn detect() -> Vec<GpuInfo> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// `card0`, `card12`, ... but not connectors like `card0-DP-1` or `renderD128`.
#[cfg(target_os = "linux")]
pub(crate) fn is_card_name(name: &str) -> bool {
    let Some(index) = name.strip_prefix("card") else {
        return false;
    };
    !index.is_empty() && index.chars().all(|character| character.is_ascii_digit())
}

#[cfg(target_os = "linux")]
fn vendor_name(vendor_id: &str) -> &'static str {
    match vendor_id.to_ascii_lowercase().as_str() {
        "0x1002" => "AMD",
        "0x10de" => "NVIDIA",
        "0x8086" => "Intel",
        "0x1af4" => "virtio",
        "0x15ad" => "VMware",
        "0x1234" => "QEMU",
        "0x1b36" => "Red Hat",
        _ => "Unknown vendor",
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn identifies_primary_drm_cards_only() {
        assert!(is_card_name("card0"));
        assert!(is_card_name("card12"));
        assert!(!is_card_name("card0-DP-1"));
        assert!(!is_card_name("renderD128"));
        assert!(!is_card_name("card"));
    }

    #[test]
    fn maps_known_vendors() {
        assert_eq!(vendor_name("0x1002"), "AMD");
        assert_eq!(vendor_name("0x10DE"), "NVIDIA");
        assert_eq!(vendor_name("0x9999"), "Unknown vendor");
    }
}
