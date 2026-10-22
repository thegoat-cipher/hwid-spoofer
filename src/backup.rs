//! Persistent backup of every configurable identifier value.
//!
//! The backup is written before a modification, kept across commands, and used
//! by `restore` and `verify`. Original values are never overwritten by later
//! snapshots.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::hardware::network::{MacAddress, NetworkInterface};
use crate::platform::{MachineIdentity, Platform};

pub const SCHEMA_VERSION: u32 = 1;
pub const STATE_DIR_ENV: &str = "HWID_SPOOFER_STATE_DIR";
const BACKUP_FILE: &str = "backup.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFile {
    pub schema: u32,
    pub created_at: String,
    pub updated_at: String,
    pub platform: String,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    Mac(MacEntry),
    MachineIdentity(MachineIdentityEntry),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacEntry {
    pub interface: String,
    pub guid: Option<String>,
    /// MAC observed before this tool changed anything.
    pub original: String,
    /// Last value this tool applied, if any.
    pub applied: Option<String>,
    /// Existing driver override found before we wrote one (Windows registry).
    pub prior_override: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineIdentityEntry {
    pub target: String,
    pub original: String,
    pub applied: Option<String>,
    pub updated_at: String,
}

impl BackupFile {
    pub fn new(platform_name: &str) -> Self {
        let now = now_utc();
        BackupFile {
            schema: SCHEMA_VERSION,
            created_at: now.clone(),
            updated_at: now,
            platform: platform_name.to_string(),
            entries: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read backup {}", path.display()));
            }
        };
        let backup: BackupFile = serde_json::from_str(&contents)
            .with_context(|| format!("invalid backup file {}", path.display()))?;
        if backup.schema != SCHEMA_VERSION {
            bail!(
                "backup {} uses schema {} but this build expects schema {}",
                path.display(),
                backup.schema,
                SCHEMA_VERSION
            );
        }
        Ok(Some(backup))
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.updated_at = now_utc();
        let directory = path
            .parent()
            .with_context(|| format!("{} has no parent directory", path.display()))?;
        fs::create_dir_all(directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
        restrict_directory(directory)?;

        let temporary = directory.join(format!(".backup.json.{}.tmp", std::process::id()));
        let serialized =
            serde_json::to_string_pretty(self).context("failed to serialize the backup")?;
        let write_result = (|| -> Result<()> {
            fs::write(&temporary, serialized)
                .with_context(|| format!("failed to write {}", temporary.display()))?;
            restrict_file(&temporary)?;
            fs::rename(&temporary, path)
                .with_context(|| format!("failed to replace {}", path.display()))?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    pub fn ensure_platform(&self) -> Result<()> {
        let current = std::env::consts::OS;
        if self.platform != current {
            bail!(
                "backup was created on '{}' but this host is '{current}'; \
                 refusing to mix platform-specific identifiers",
                self.platform
            );
        }
        Ok(())
    }

    /// Clear the applied marker after a successful restore so `verify` expects
    /// the original value again.
    pub fn mark_restored(&mut self, kind: &str, target: &str) {
        for entry in &mut self.entries {
            match entry {
                Entry::Mac(mac) if kind == "mac" && mac.interface == target => {
                    mac.applied = None;
                    mac.updated_at = now_utc();
                }
                Entry::MachineIdentity(identity)
                    if kind == "machine_identity" && identity.target == target =>
                {
                    identity.applied = None;
                    identity.updated_at = now_utc();
                }
                _ => {}
            }
        }
    }

    pub fn find_mac(&self, interface: &NetworkInterface) -> Option<&MacEntry> {
        self.entries.iter().find_map(|entry| match entry {
            Entry::Mac(mac)
                if mac.interface == interface.name
                    || (interface.guid.is_some() && mac.guid == interface.guid) =>
            {
                Some(mac)
            }
            _ => None,
        })
    }

    /// Record the original MAC before a change. Returns `true` if a new entry
    /// was created; an existing entry's original value is never overwritten.
    pub fn record_mac_original(
        &mut self,
        interface: &NetworkInterface,
        prior_override: Option<String>,
    ) -> bool {
        if self.find_mac(interface).is_some() {
            return false;
        }
        self.entries.push(Entry::Mac(MacEntry {
            interface: interface.name.clone(),
            guid: interface.guid.clone(),
            original: interface.mac.to_string(),
            applied: None,
            prior_override,
            updated_at: now_utc(),
        }));
        true
    }

    pub fn mark_mac_applied(&mut self, interface: &NetworkInterface, mac: MacAddress) {
        let found = self.entries.iter_mut().find(|entry| match entry {
            Entry::Mac(mac_entry) => {
                mac_entry.interface == interface.name
                    || (interface.guid.is_some() && mac_entry.guid == interface.guid)
            }
            Entry::MachineIdentity(_) => false,
        });
        if let Some(Entry::Mac(entry)) = found {
            entry.applied = Some(mac.to_string());
            entry.updated_at = now_utc();
        }
    }

    /// Record the original machine identity before a change.
    pub fn record_identity_original(&mut self, identity: &MachineIdentity) -> bool {
        let Some(original) = identity.value.as_str() else {
            return false;
        };
        if self
            .entries
            .iter()
            .any(|entry| matches!(entry, Entry::MachineIdentity(existing) if existing.target == identity.source))
        {
            return false;
        }
        self.entries
            .push(Entry::MachineIdentity(MachineIdentityEntry {
                target: identity.source.clone(),
                original: original.to_string(),
                applied: None,
                updated_at: now_utc(),
            }));
        true
    }

    pub fn mark_identity_applied(&mut self, target: &str, value: &str) {
        if let Some(Entry::MachineIdentity(entry)) = self.entries.iter_mut().find(
            |entry| matches!(entry, Entry::MachineIdentity(existing) if existing.target == target),
        ) {
            entry.applied = Some(value.to_string());
            entry.updated_at = now_utc();
        }
    }
}

/// Directory used for `backup.json`, overridable with `HWID_SPOOFER_STATE_DIR`
/// (documented and used by the test suite).
pub fn state_dir() -> PathBuf {
    if let Some(override_path) = std::env::var_os(STATE_DIR_ENV) {
        return PathBuf::from(override_path);
    }
    #[cfg(target_os = "linux")]
    {
        if crate::platform::linux::is_elevated() {
            return PathBuf::from("/var/lib/hwid-spoofer");
        }
        base_state_dir().join("hwid-spoofer")
    }
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("hwid-spoofer")
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        base_state_dir().join("hwid-spoofer")
    }
}

#[cfg(target_os = "linux")]
fn base_state_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub fn backup_path() -> PathBuf {
    state_dir().join(BACKUP_FILE)
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to restrict {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn same_interface(left: &NetworkInterface, right: &NetworkInterface) -> bool {
    left.name == right.name || (right.guid.is_some() && left.guid == right.guid)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreStatus {
    Restored,
    AlreadyOriginal,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreResult {
    pub kind: &'static str,
    pub target: String,
    pub status: RestoreStatus,
    pub message: String,
    pub actions: Vec<String>,
}

/// Restore every backed-up value and verify each restoration independently.
pub fn restore_all(platform: &dyn Platform, backup: &BackupFile) -> Vec<RestoreResult> {
    let interfaces = platform.interfaces().unwrap_or_default();
    let mut results = Vec::new();

    for entry in &backup.entries {
        match entry {
            Entry::Mac(mac_entry) => {
                let interface = interfaces.iter().find(|interface| {
                    interface.name == mac_entry.interface
                        || (mac_entry.guid.is_some() && interface.guid == mac_entry.guid)
                });
                let Some(interface) = interface else {
                    results.push(RestoreResult {
                        kind: "mac",
                        target: mac_entry.interface.clone(),
                        status: RestoreStatus::Failed,
                        message: "interface not present; reconnect the adapter and retry"
                            .to_string(),
                        actions: Vec::new(),
                    });
                    continue;
                };
                let Ok(original) = mac_entry.original.parse::<MacAddress>() else {
                    results.push(RestoreResult {
                        kind: "mac",
                        target: mac_entry.interface.clone(),
                        status: RestoreStatus::Failed,
                        message: format!("backup contains invalid MAC '{}'", mac_entry.original),
                        actions: Vec::new(),
                    });
                    continue;
                };
                if interface.mac == original {
                    results.push(RestoreResult {
                        kind: "mac",
                        target: mac_entry.interface.clone(),
                        status: RestoreStatus::AlreadyOriginal,
                        message: format!("{original} already active"),
                        actions: Vec::new(),
                    });
                    continue;
                }
                match platform.restore_mac(
                    interface,
                    &original,
                    mac_entry.prior_override.as_deref(),
                ) {
                    Ok(actions) => {
                        let verified = platform
                            .interfaces()
                            .map(|current| {
                                current
                                    .iter()
                                    .find(|current| same_interface(current, interface))
                                    .map(|current| current.mac == original)
                                    .unwrap_or(false)
                            })
                            .unwrap_or(false);
                        results.push(RestoreResult {
                            kind: "mac",
                            target: mac_entry.interface.clone(),
                            status: if verified {
                                RestoreStatus::Restored
                            } else {
                                RestoreStatus::Failed
                            },
                            message: if verified {
                                format!("verified {original} from an independent adapter query")
                            } else {
                                format!("write completed but independent read did not observe {original}")
                            },
                            actions,
                        });
                    }
                    Err(error) => results.push(RestoreResult {
                        kind: "mac",
                        target: mac_entry.interface.clone(),
                        status: RestoreStatus::Failed,
                        message: format!("{error:#}"),
                        actions: Vec::new(),
                    }),
                }
            }
            Entry::MachineIdentity(identity_entry) => {
                let current = platform.machine_identity();
                let current_value = current.value.as_str().map(|value| value.to_string());
                if current_value.as_deref() == Some(identity_entry.original.as_str()) {
                    results.push(RestoreResult {
                        kind: "machine_identity",
                        target: identity_entry.target.clone(),
                        status: RestoreStatus::AlreadyOriginal,
                        message: "original identity already active".to_string(),
                        actions: Vec::new(),
                    });
                    continue;
                }
                match platform.apply_machine_identity(&identity_entry.original) {
                    Ok(()) => {
                        let verified = platform
                            .machine_identity()
                            .value
                            .as_str()
                            .map(|value| value == identity_entry.original)
                            .unwrap_or(false);
                        results.push(RestoreResult {
                            kind: "machine_identity",
                            target: identity_entry.target.clone(),
                            status: if verified {
                                RestoreStatus::Restored
                            } else {
                                RestoreStatus::Failed
                            },
                            message: if verified {
                                "verified by re-reading the machine identity".to_string()
                            } else {
                                "write completed but independent read did not match".to_string()
                            },
                            actions: Vec::new(),
                        });
                    }
                    Err(error) => results.push(RestoreResult {
                        kind: "machine_identity",
                        target: identity_entry.target.clone(),
                        status: RestoreStatus::Failed,
                        message: format!("{error:#}"),
                        actions: Vec::new(),
                    }),
                }
            }
        }
    }

    results
}

pub fn now_utc() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format_epoch(seconds)
}

fn format_epoch(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60
    )
}

/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_iso_utc() {
        assert_eq!(format_epoch(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_epoch(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn backup_round_trips_and_never_overwrites_original() {
        let mut directory = std::env::temp_dir();
        directory.push(format!("hwid-spoofer-backup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("backup.json");

        let mut backup = BackupFile::new("Linux");
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            description: "physical adapter".to_string(),
            mac: "02:00:00:00:00:01".parse().unwrap(),
            permanent_mac: None,
            virtual_device: false,
            up: true,
            kind: crate::hardware::network::InterfaceKind::Ethernet,
            guid: None,
        };
        assert!(backup.record_mac_original(&interface, None));
        backup.mark_mac_applied(&interface, "02:00:00:00:00:02".parse().unwrap());
        backup.save(&path).unwrap();

        let mut loaded = BackupFile::load(&path).unwrap().unwrap();
        let mac = loaded.find_mac(&interface).unwrap();
        assert_eq!(mac.original, "02:00:00:00:00:01");
        assert_eq!(mac.applied.as_deref(), Some("02:00:00:00:00:02"));

        // A later snapshot must keep the first original.
        let changed = NetworkInterface {
            mac: "02:00:00:00:00:03".parse().unwrap(),
            ..interface.clone()
        };
        assert!(!loaded.record_mac_original(&changed, None));
        assert_eq!(
            loaded.find_mac(&interface).unwrap().original,
            "02:00:00:00:00:01"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn restore_marker_clears_applied_values() {
        let mut backup = BackupFile::new("Linux");
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            description: "physical adapter".to_string(),
            mac: "02:00:00:00:00:01".parse().unwrap(),
            permanent_mac: None,
            virtual_device: false,
            up: true,
            kind: crate::hardware::network::InterfaceKind::Ethernet,
            guid: None,
        };
        backup.record_mac_original(&interface, None);
        backup.mark_mac_applied(&interface, "02:00:00:00:00:02".parse().unwrap());
        assert!(backup.find_mac(&interface).unwrap().applied.is_some());
        backup.mark_restored("mac", "eth0");
        assert!(backup.find_mac(&interface).unwrap().applied.is_none());
    }

    #[test]
    fn platform_guard_rejects_foreign_backups() {
        let mut backup = BackupFile::new("some-other-os");
        assert!(backup.ensure_platform().is_err());
        backup.platform = std::env::consts::OS.to_string();
        assert!(backup.ensure_platform().is_ok());
    }

    #[test]
    fn rejects_unknown_schema() {
        let mut directory = std::env::temp_dir();
        directory.push(format!("hwid-spoofer-backup-schema-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("backup.json");
        fs::write(
            &path,
            r#"{"schema":99,"created_at":"x","updated_at":"x","platform":"x","entries":[]}"#,
        )
        .unwrap();
        assert!(BackupFile::load(&path).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
