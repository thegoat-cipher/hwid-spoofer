//! Physical network adapter MAC spoofing orchestration.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::backup::BackupFile;
use crate::hardware::network::{InterfaceKind, MacAddress, NetworkInterface};
use crate::platform::Platform;

#[derive(Debug, Clone)]
pub struct MacSpoofRequest {
    pub interface: String,
    pub mac: Option<MacAddress>,
    pub allow_virtual: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MacSpoofOutcome {
    pub interface: String,
    pub guid: Option<String>,
    pub original: MacAddress,
    pub applied: MacAddress,
    pub verified: bool,
    pub actions: Vec<String>,
    pub backup_path: PathBuf,
}

pub fn spoof(
    platform: &dyn Platform,
    request: &MacSpoofRequest,
    backup: &mut BackupFile,
    backup_path: &Path,
) -> Result<MacSpoofOutcome> {
    super::require_privilege(platform)?;
    if !platform.mac_supported() {
        bail!("{}", platform.unsupported_reason());
    }

    let interfaces = platform
        .interfaces()
        .context("failed to enumerate network interfaces")?;
    let interface = find_interface(&interfaces, &request.interface)?;

    if !matches!(
        interface.kind,
        InterfaceKind::Ethernet | InterfaceKind::Wifi
    ) {
        bail!(
            "{} is not an Ethernet or Wi-Fi adapter (kind: {}); its MAC cannot be changed by this tool",
            interface.name,
            interface.kind.label()
        );
    }
    if interface.virtual_device && !request.allow_virtual {
        bail!(
            "{} is a virtual interface. Only physical adapters are supported; \
             pass --allow-virtual only for controlled testing on virtual links",
            interface.name
        );
    }

    let applied = match request.mac {
        Some(mac) => mac,
        None => {
            let mut candidate = MacAddress::random()?;
            while candidate == interface.mac {
                candidate = MacAddress::random()?;
            }
            candidate
        }
    };
    applied.validate_for_spoof()?;
    if applied == interface.mac {
        bail!(
            "{} already has MAC {applied}; choose a different address",
            interface.name
        );
    }
    if let Some(other) = interfaces
        .iter()
        .find(|other| !same_target(other, interface) && other.mac == applied)
    {
        bail!(
            "MAC {applied} is already assigned to {}; refusing to create a duplicate address",
            other.name
        );
    }

    let prior_override = platform
        .existing_mac_override(interface)
        .context("failed to read the existing adapter MAC override")?;

    // Persist the original before any write reaches the OS.
    backup.record_mac_original(interface, prior_override.clone());
    backup
        .save(backup_path)
        .context("failed to persist the original MAC before changing it")?;

    let original = interface.mac;
    let actions = match platform.apply_mac(interface, &applied) {
        Ok(actions) => actions,
        Err(error) => {
            let rollback = platform.restore_mac(interface, &original, prior_override.as_deref());
            bail!(
                "failed to apply MAC {applied} to {}: {error:#}. Rollback to {original} {}",
                interface.name,
                if rollback.is_ok() {
                    "succeeded"
                } else {
                    "FAILED"
                }
            );
        }
    };

    // Independent verification: re-query the OS, never trust the write path.
    let refreshed = platform
        .interfaces()
        .context("failed to re-query adapters for verification")?;
    let observed = refreshed
        .iter()
        .find(|current| same_target(current, interface))
        .map(|current| current.mac);
    if observed != Some(applied) {
        let rollback = platform.restore_mac(interface, &original, prior_override.as_deref());
        bail!(
            "verification failed: {} reports {} instead of {applied}. Rollback to {original} {}",
            interface.name,
            observed
                .map(|mac| mac.to_string())
                .unwrap_or_else(|| "no MAC (interface missing)".to_string()),
            if rollback.is_ok() {
                "succeeded"
            } else {
                "FAILED"
            }
        );
    }

    backup.mark_mac_applied(interface, applied);
    backup
        .save(backup_path)
        .context("MAC was applied and verified, but updating the backup failed")?;

    Ok(MacSpoofOutcome {
        interface: interface.name.clone(),
        guid: interface.guid.clone(),
        original,
        applied,
        verified: true,
        actions,
        backup_path: backup_path.to_path_buf(),
    })
}

pub(crate) fn find_interface<'a>(
    interfaces: &'a [NetworkInterface],
    query: &str,
) -> Result<&'a NetworkInterface> {
    if let Some(found) = interfaces.iter().find(|interface| {
        interface.name.eq_ignore_ascii_case(query)
            || interface
                .guid
                .as_deref()
                .is_some_and(|guid| guid.eq_ignore_ascii_case(query))
    }) {
        return Ok(found);
    }
    let mut names: Vec<&str> = interfaces
        .iter()
        .map(|interface| interface.name.as_str())
        .collect();
    names.sort_unstable();
    bail!(
        "network interface '{query}' not found. Available interfaces: {}",
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(", ")
        }
    )
}

fn same_target(left: &NetworkInterface, right: &NetworkInterface) -> bool {
    left.name == right.name || (right.guid.is_some() && left.guid == right.guid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, guid: Option<&str>) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: "test".to_string(),
            mac: "02:00:00:00:00:01".parse().unwrap(),
            permanent_mac: None,
            virtual_device: false,
            up: true,
            kind: InterfaceKind::Ethernet,
            guid: guid.map(|value| value.to_string()),
        }
    }

    #[test]
    fn finds_interface_by_name_or_guid() {
        let interfaces = vec![
            interface("eth0", None),
            interface("Ethernet 2", Some("{ABC}")),
        ];
        assert_eq!(find_interface(&interfaces, "ETH0").unwrap().name, "eth0");
        assert_eq!(
            find_interface(&interfaces, "{abc}").unwrap().name,
            "Ethernet 2"
        );
    }

    #[test]
    fn missing_interface_error_lists_choices() {
        let interfaces = vec![interface("eth0", None)];
        let error = find_interface(&interfaces, "eth9").unwrap_err().to_string();
        assert!(error.contains("eth0"), "{error}");
    }
}
