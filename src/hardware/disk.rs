//! Fixed-disk serial identification.

use super::DiskInfo;
#[cfg(target_os = "linux")]
use super::Value;

#[cfg(target_os = "linux")]
pub fn detect() -> Vec<DiskInfo> {
    detect_with_root(std::path::Path::new("/sys"))
}

#[cfg(target_os = "linux")]
pub(crate) fn detect_with_root(sys_root: &std::path::Path) -> Vec<DiskInfo> {
    use std::fs;

    let block = sys_root.join("block");
    let Ok(entries) = fs::read_dir(&block) else {
        return Vec::new();
    };
    let mut disks = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_ignored_block(&name) {
            continue;
        }
        let device_root = block.join(&name);
        let device = device_root.join("device");
        let model = read_trimmed(&device.join("model"));
        let serial = read_serial(&device);
        let size_bytes = read_trimmed(&device_root.join("size"))
            .and_then(|sectors| sectors.parse::<u64>().ok())
            .map(|sectors| sectors.saturating_mul(512));
        let rotational =
            read_trimmed(&device_root.join("queue/rotational")).map(|value| value == "1");
        let bus = detect_bus(&device);
        disks.push(DiskInfo {
            name,
            model,
            serial,
            size_bytes,
            bus,
            rotational,
        });
    }
    disks.sort_by(|a, b| a.name.cmp(&b.name));
    disks
}

#[cfg(windows)]
pub fn detect() -> Vec<DiskInfo> {
    crate::platform::windows::detect_disks()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn detect() -> Vec<DiskInfo> {
    Vec::new()
}

#[cfg(target_os = "linux")]
pub(crate) fn is_ignored_block(name: &str) -> bool {
    const PREFIXES: [&str; 9] = [
        "loop",
        "ram",
        "zram",
        "dm-",
        "md",
        "sr",
        "fd",
        "nbd",
        "mmcblk0boot",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "linux")]
fn read_serial(device: &std::path::Path) -> Value {
    if let Some(serial) = read_trimmed(&device.join("serial")) {
        return Value::known(serial);
    }
    if let Some(serial) = read_vpd_page80(&device.join("vpd_pg80")) {
        return Value::known(serial);
    }
    if let Some(wwid) = read_trimmed(&device.join("wwid")) {
        return Value::known(wwid);
    }
    Value::unavailable(format!(
        "no serial exposed under {} (driver exposes neither serial, VPD page 80, nor wwid)",
        device.display()
    ))
}

/// SCSI VPD page 0x80: 4-byte page header followed by the unit serial number.
#[cfg(target_os = "linux")]
fn read_vpd_page80(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() <= 4 {
        return None;
    }
    let data = &bytes[4..];
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    let serial = String::from_utf8_lossy(&data[..end]).trim().to_string();
    (!serial.is_empty()).then_some(serial)
}

#[cfg(target_os = "linux")]
fn detect_bus(device: &std::path::Path) -> Option<String> {
    let canonical = std::fs::canonicalize(device).ok()?;
    let path = canonical.to_string_lossy();
    for (needle, bus) in [
        ("/nvme/", "nvme"),
        ("/usb", "usb"),
        ("/ata", "sata"),
        ("/scsi", "scsi"),
        ("/mmc", "mmc"),
        ("/virtio", "virtio"),
    ] {
        if path.contains(needle) {
            return Some(bus.to_string());
        }
    }
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_root(name: &str) -> PathBuf {
        let mut root = std::env::temp_dir();
        root.push(format!("hwid-spoofer-disks-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn reads_serial_model_size_and_rotational() {
        let root = fixture_root("basic");
        let disk = root.join("block/nvme0n1");
        fs::create_dir_all(disk.join("device")).unwrap();
        fs::create_dir_all(disk.join("queue")).unwrap();
        fs::write(disk.join("device/serial"), "S4EWNX0R123456\n").unwrap();
        fs::write(disk.join("device/model"), "Samsung SSD 990 PRO 1TB\n").unwrap();
        fs::write(disk.join("size"), "1953525168\n").unwrap();
        fs::write(disk.join("queue/rotational"), "0\n").unwrap();

        // Virtual/loop devices must be ignored.
        fs::create_dir_all(root.join("block/loop0")).unwrap();
        fs::create_dir_all(root.join("block/zram0")).unwrap();

        let disks = detect_with_root(&root);
        assert_eq!(disks.len(), 1);
        let disk = &disks[0];
        assert_eq!(disk.name, "nvme0n1");
        assert_eq!(disk.serial.as_str(), Some("S4EWNX0R123456"));
        assert_eq!(disk.model.as_deref(), Some("Samsung SSD 990 PRO 1TB"));
        assert_eq!(disk.size_bytes, Some(1953525168 * 512));
        assert_eq!(disk.rotational, Some(false));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn falls_back_to_vpd_page80() {
        let root = fixture_root("vpd");
        let disk = root.join("block/sda");
        fs::create_dir_all(disk.join("device")).unwrap();
        let mut vpd = vec![0x00, 0x80, 0x00, 0x0C];
        vpd.extend_from_slice(b"WD-ABC123\0garbage");
        fs::write(disk.join("device/vpd_pg80"), vpd).unwrap();

        let disks = detect_with_root(&root);
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].serial.as_str(), Some("WD-ABC123"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_missing_serial_explicitly() {
        let root = fixture_root("noserial");
        fs::create_dir_all(root.join("block/sdb/device")).unwrap();
        let disks = detect_with_root(&root);
        assert_eq!(disks.len(), 1);
        assert!(disk_missing_serial(&disks[0]));
        fs::remove_dir_all(root).unwrap();
    }

    fn disk_missing_serial(disk: &DiskInfo) -> bool {
        matches!(&disk.serial, Value::Unavailable { reason } if reason.contains("no serial exposed"))
    }

    #[test]
    fn ignores_virtual_block_devices() {
        for name in ["loop0", "dm-0", "md0", "zram0", "sr0", "sda"] {
            assert_eq!(
                is_ignored_block(name),
                name != "sda",
                "unexpected classification for {name}"
            );
        }
    }
}
