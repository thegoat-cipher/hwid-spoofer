//! Independent verification of the values recorded in the backup.

use serde::Serialize;

use crate::backup::{BackupFile, Entry};
use crate::hardware::network::MacAddress;
use crate::platform::Platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    /// Live value equals the expected value (applied override or restored original).
    Matches,
    /// The target exists but reports a different value.
    Drift,
    /// The interface or identity source is not readable/present.
    TargetMissing,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyItem {
    pub kind: &'static str,
    pub target: String,
    /// `applied` value when one was recorded, otherwise the original.
    pub expected: String,
    pub actual: Option<String>,
    pub status: VerifyStatus,
    /// True when `expected` is a value this tool applied, false for originals.
    pub expected_is_applied: bool,
}

pub fn verify_backup(platform: &dyn Platform, backup: &BackupFile) -> Vec<VerifyItem> {
    let interfaces = platform.interfaces().unwrap_or_default();
    let identity = platform.machine_identity();
    let mut items = Vec::new();

    for entry in &backup.entries {
        match entry {
            Entry::Mac(mac_entry) => {
                let expected_is_applied = mac_entry.applied.is_some();
                let expected = mac_entry
                    .applied
                    .clone()
                    .unwrap_or_else(|| mac_entry.original.clone());
                let interface = interfaces.iter().find(|interface| {
                    interface.name == mac_entry.interface
                        || (mac_entry.guid.is_some() && interface.guid == mac_entry.guid)
                });
                let actual = interface.map(|interface| interface.mac.to_string());
                let status = match (&actual, &interface) {
                    (_, None) => VerifyStatus::TargetMissing,
                    (Some(actual), Some(_)) => {
                        if mac_matches(&expected, actual) {
                            VerifyStatus::Matches
                        } else {
                            VerifyStatus::Drift
                        }
                    }
                    (None, Some(_)) => VerifyStatus::TargetMissing,
                };
                items.push(VerifyItem {
                    kind: "mac",
                    target: mac_entry.interface.clone(),
                    expected,
                    actual,
                    status,
                    expected_is_applied,
                });
            }
            Entry::MachineIdentity(identity_entry) => {
                let expected_is_applied = identity_entry.applied.is_some();
                let expected = identity_entry
                    .applied
                    .clone()
                    .unwrap_or_else(|| identity_entry.original.clone());
                let actual = identity
                    .value
                    .as_str()
                    .map(|value| value.to_ascii_lowercase());
                let status = match &actual {
                    None => VerifyStatus::TargetMissing,
                    Some(actual) if actual == &expected.to_ascii_lowercase() => {
                        VerifyStatus::Matches
                    }
                    Some(_) => VerifyStatus::Drift,
                };
                items.push(VerifyItem {
                    kind: "machine_identity",
                    target: identity_entry.target.clone(),
                    expected,
                    actual,
                    status,
                    expected_is_applied,
                });
            }
        }
    }

    items
}

fn mac_matches(expected: &str, actual: &str) -> bool {
    match (expected.parse::<MacAddress>(), actual.parse::<MacAddress>()) {
        (Ok(expected), Ok(actual)) => expected == actual,
        _ => expected.eq_ignore_ascii_case(actual),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_macs_regardless_of_formatting() {
        assert!(mac_matches("02:11:22:33:44:55", "02-11-22-33-44-55"));
        assert!(mac_matches("02:11:22:33:44:55", "021122334455"));
        assert!(!mac_matches("02:11:22:33:44:55", "02:11:22:33:44:56"));
        assert!(!mac_matches("not-a-mac", "02:11:22:33:44:55"));
    }
}
