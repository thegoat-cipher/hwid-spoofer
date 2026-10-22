//! CPU identification.

use super::CpuInfo;
#[cfg(target_os = "linux")]
use super::Value;

#[cfg(target_os = "linux")]
pub fn detect() -> CpuInfo {
    match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(text) => parse_cpuinfo(&text),
        Err(error) => CpuInfo {
            vendor: Value::unavailable(format!("failed to read /proc/cpuinfo: {error}")),
            model: Value::unavailable(format!("failed to read /proc/cpuinfo: {error}")),
            family: None,
            model_number: None,
            stepping: None,
            logical_cpus: None,
            microcode: None,
        },
    }
}

#[cfg(windows)]
pub fn detect() -> CpuInfo {
    crate::platform::windows::detect_cpu()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn detect() -> CpuInfo {
    CpuInfo {
        vendor: Value::unavailable("platform not supported"),
        model: Value::unavailable("platform not supported"),
        family: None,
        model_number: None,
        stepping: None,
        logical_cpus: None,
        microcode: None,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_cpuinfo(text: &str) -> CpuInfo {
    let mut vendor = None;
    let mut model = None;
    let mut family = None;
    let mut model_number = None;
    let mut stepping = None;
    let mut microcode = None;
    let mut logical_cpus = 0u32;

    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key == "processor" {
            logical_cpus += 1;
            continue;
        }
        // All identifying fields for x86 live in the first processor block.
        if logical_cpus > 1 || value.is_empty() {
            continue;
        }
        match key {
            "vendor_id" => vendor = Some(value.to_string()),
            "model name" => model = Some(value.to_string()),
            "cpu family" => family = Some(value.to_string()),
            "model" => model_number = Some(value.to_string()),
            "stepping" => stepping = Some(value.to_string()),
            "microcode" => microcode = Some(value.to_string()),
            _ => {}
        }
    }

    let reason = "not present in /proc/cpuinfo";
    CpuInfo {
        vendor: vendor
            .map(Value::known)
            .unwrap_or_else(|| Value::unavailable(reason)),
        model: model
            .map(Value::known)
            .unwrap_or_else(|| Value::unavailable(reason)),
        family,
        model_number,
        stepping,
        logical_cpus: (logical_cpus > 0).then_some(logical_cpus),
        microcode,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
processor\t: 0
vendor_id\t: AuthenticAMD
cpu family\t: 25
model\t\t: 68
model name\t: AMD Ryzen 7 6800H with Radeon Graphics
stepping\t: 1
microcode\t: 0xa404102

processor\t: 1
vendor_id\t: AuthenticAMD
cpu family\t: 25
model\t\t: 68
model name\t: AMD Ryzen 7 6800H with Radeon Graphics
stepping\t: 1
";

    #[test]
    fn parses_x86_cpuinfo() {
        let cpu = parse_cpuinfo(FIXTURE);
        assert_eq!(cpu.vendor.as_str(), Some("AuthenticAMD"));
        assert_eq!(
            cpu.model.as_str(),
            Some("AMD Ryzen 7 6800H with Radeon Graphics")
        );
        assert_eq!(cpu.family.as_deref(), Some("25"));
        assert_eq!(cpu.model_number.as_deref(), Some("68"));
        assert_eq!(cpu.stepping.as_deref(), Some("1"));
        assert_eq!(cpu.microcode.as_deref(), Some("0xa404102"));
        assert_eq!(cpu.logical_cpus, Some(2));
        assert!(cpu
            .summary()
            .as_str()
            .unwrap()
            .contains("family 25, model 68, stepping 1"));
    }

    #[test]
    fn tolerates_missing_fields() {
        let cpu = parse_cpuinfo("processor\t: 0\n");
        assert_eq!(cpu.logical_cpus, Some(1));
        assert!(cpu.model.display().contains("not present"));
    }
}
