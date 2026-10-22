//! System machine identity inspection and regeneration.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::backup::BackupFile;
use crate::hardware::Value;
use crate::platform::{IdentityFormat, Platform};

pub const CONSEQUENCES: &[&str] = &[
    "Software activation and licenses may treat this machine as a new computer.",
    "Registered services, backup agents, and monitoring tools may lose their association.",
    "Network identity changes: DHCP client IDs, VPN profiles, captive portals, and domain trust can be affected.",
    "Running services keep the old value until restarted; a reboot is recommended.",
    "The original value is backed up first and can be restored with `hwid-spoofer restore`.",
];

#[derive(Debug, Clone, Serialize)]
pub struct IdentityInspection {
    pub value: Value,
    pub source: String,
    pub format: IdentityFormat,
    pub writable: bool,
    pub elevated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityOutcome {
    pub source: String,
    pub previous: String,
    pub applied: String,
    pub verified: bool,
}

pub fn inspect(platform: &dyn Platform) -> IdentityInspection {
    let identity = platform.machine_identity();
    let elevated = platform.context().elevated;
    IdentityInspection {
        value: identity.value,
        source: identity.source,
        format: identity.format,
        writable: platform.identity_supported()
            && platform.required_privilege().satisfied_by(elevated),
        elevated,
    }
}

/// Generate a valid replacement in the format the platform expects.
pub fn generate_value(format: IdentityFormat) -> Result<String> {
    match format {
        IdentityFormat::Hex32 => random_hex32(),
        IdentityFormat::Uuid => random_uuid_v4(),
    }
}

pub fn regenerate(
    platform: &dyn Platform,
    backup: &mut BackupFile,
    backup_path: &Path,
) -> Result<IdentityOutcome> {
    super::require_privilege(platform)?;
    if !platform.identity_supported() {
        bail!("{}", platform.unsupported_reason());
    }

    let identity = platform.machine_identity();
    let previous = identity
        .value
        .as_str()
        .map(|value| value.to_string())
        .context(
            "current machine identity is unreadable; refusing to change it without a backup",
        )?;
    let applied = generate_value(identity.format)?;

    // Persist the original before the first write.
    backup.record_identity_original(&identity);
    backup.save(backup_path)?;

    if let Err(error) = platform.apply_machine_identity(&applied) {
        let rollback = platform.apply_machine_identity(&previous);
        bail!(
            "failed to apply the new machine identity: {error:#}. \
             Rollback to the original value {}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "FAILED"
            }
        );
    }

    let verified = platform
        .machine_identity()
        .value
        .as_str()
        .map(|value| value.eq_ignore_ascii_case(&applied))
        .unwrap_or(false);

    if !verified {
        let rollback = platform.apply_machine_identity(&previous);
        bail!(
            "the OS did not report the new machine identity after writing it; \
             rollback to the original value {}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "FAILED"
            }
        );
    }

    backup.mark_identity_applied(&identity.source, &applied);
    backup.save(backup_path)?;

    Ok(IdentityOutcome {
        source: identity.source,
        previous,
        applied,
        verified,
    })
}

pub fn random_hex32() -> Result<String> {
    let mut bytes = [0u8; 16];
    crate::random::fill(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn random_uuid_v4() -> Result<String> {
    let mut bytes = [0u8; 16];
    crate::random::fill(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // RFC 4122 variant
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex32_is_32_lowercase_hex_characters() {
        let first = random_hex32().unwrap();
        let second = random_hex32().unwrap();
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|character| character.is_ascii_hexdigit()));
        assert_eq!(first, first.to_ascii_lowercase());
        assert_ne!(first, second);
    }

    #[test]
    fn uuid_is_rfc4122_version_4() {
        let value = random_uuid_v4().unwrap();
        let parts: Vec<&str> = value.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        assert!(parts[2].starts_with('4'), "version nibble: {value}");
        assert!(
            matches!(parts[3].chars().next(), Some('8' | '9' | 'a' | 'b')),
            "variant nibble: {value}"
        );
    }

    #[test]
    fn generate_value_matches_requested_format() {
        assert_eq!(generate_value(IdentityFormat::Hex32).unwrap().len(), 32);
        assert_eq!(
            generate_value(IdentityFormat::Uuid)
                .unwrap()
                .split('-')
                .count(),
            5
        );
    }
}
