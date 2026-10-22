//! Supported spoofing operations.

pub mod identity;
pub mod mac;

use anyhow::{bail, Result};

use crate::platform::Platform;

/// Plausible OEM-style serial candidate. Firmware serials are read-only; this
/// value is informational and `capabilities` always reports that limitation.
pub fn random_serial() -> Result<String> {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    let limit = 256 - (256 % CHARSET.len());
    let mut serial = String::with_capacity(12);
    let mut buffer = [0u8; 32];
    while serial.len() < 12 {
        crate::random::fill(&mut buffer)?;
        for byte in buffer {
            if (byte as usize) < limit {
                serial.push(CHARSET[byte as usize % CHARSET.len()] as char);
                if serial.len() == 12 {
                    break;
                }
            }
        }
    }
    Ok(serial)
}

/// Fail before touching anything when the required elevation is absent.
pub fn require_privilege(platform: &dyn Platform) -> Result<()> {
    let context = platform.context();
    let required = platform.required_privilege();
    if !required.satisfied_by(context.elevated) {
        #[cfg(target_os = "linux")]
        let hint = "re-run with sudo";
        #[cfg(windows)]
        let hint = "restart the terminal as Administrator (UAC elevation)";
        #[cfg(not(any(target_os = "linux", windows)))]
        let hint = "run with administrative privileges";
        bail!(
            "{} privileges are required for this operation; {hint}",
            required.label()
        );
    }
    Ok(())
}
