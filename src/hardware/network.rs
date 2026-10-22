//! Network adapter identification and MAC address handling.

use std::fmt;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn from_octets(octets: [u8; 6]) -> Self {
        MacAddress(octets)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Cryptographically secure, locally administered, unicast address.
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; 6];
        crate::random::fill(&mut bytes)?;
        bytes[0] = (bytes[0] & 0xFC) | 0x02;
        Ok(MacAddress(bytes))
    }

    pub fn is_unicast(&self) -> bool {
        self.0[0] & 0x01 == 0
    }

    /// Test assertion helper for locally administered generation.
    #[allow(dead_code)]
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 6]
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    /// Reject addresses the kernel or a peer would treat as invalid.
    pub fn validate_for_spoof(&self) -> Result<()> {
        if self.is_zero() {
            bail!("MAC address 00:00:00:00:00:00 is not assignable");
        }
        if self.is_broadcast() {
            bail!("broadcast MAC address ff:ff:ff:ff:ff:ff is not assignable");
        }
        if !self.is_unicast() {
            bail!("{self} is a multicast address; an interface MAC must be unicast");
        }
        Ok(())
    }

    /// 12 uppercase hex digits, the format Windows `NetworkAddress` expects.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn to_hex_upper(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02X}")).collect()
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let cleaned: String = input
            .trim()
            .chars()
            .filter(|character| !matches!(character, ':' | '-' | '.' | ' '))
            .collect();
        if cleaned.len() != 12 {
            bail!("invalid MAC address '{input}': expected 12 hex digits (e.g. 02:11:22:33:44:55)");
        }
        let mut octets = [0u8; 6];
        for (index, octet) in octets.iter_mut().enumerate() {
            let start = index * 2;
            *octet = u8::from_str_radix(&cleaned[start..start + 2], 16)
                .with_context(|| format!("invalid hex digits in MAC address '{input}'"))?;
        }
        Ok(MacAddress(octets))
    }
}

impl Serialize for MacAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Ethernet,
    Wifi,
    Other,
}

impl InterfaceKind {
    pub fn label(self) -> &'static str {
        match self {
            InterfaceKind::Ethernet => "ethernet",
            InterfaceKind::Wifi => "wifi",
            InterfaceKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    /// Stable user-facing handle: interface name on Linux, friendly name on Windows.
    pub name: String,
    /// Adapter description or driver.
    pub description: String,
    pub mac: MacAddress,
    pub permanent_mac: Option<MacAddress>,
    pub virtual_device: bool,
    pub up: bool,
    pub kind: InterfaceKind,
    /// Windows adapter GUID (`AdapterName`); `None` on Linux.
    pub guid: Option<String>,
}

impl NetworkInterface {
    pub fn mac_spoof_supported(&self) -> bool {
        !self.virtual_device && matches!(self.kind, InterfaceKind::Ethernet | InterfaceKind::Wifi)
    }
}

#[cfg(target_os = "linux")]
pub fn detect() -> Result<Vec<NetworkInterface>> {
    detect_with_root(std::path::Path::new("/sys/class/net"))
}

#[cfg(target_os = "linux")]
pub(crate) fn detect_with_root(root: &std::path::Path) -> Result<Vec<NetworkInterface>> {
    use std::fs;

    let entries = fs::read_dir(root)
        .with_context(|| format!("failed to list network interfaces in {}", root.display()))?;
    let mut interfaces = Vec::new();

    for entry in entries {
        let entry = entry.context("failed to enumerate a network interface")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let address = match fs::read_to_string(path.join("address")) {
            Ok(value) => value,
            Err(error) => {
                // Interfaces disappearing mid-scan are normal (VPN teardown).
                if error.kind() == std::io::ErrorKind::NotFound {
                    continue;
                }
                return Err(error)
                    .with_context(|| format!("failed to read MAC for interface {name}"));
            }
        };
        let Ok(mac) = address.trim().parse::<MacAddress>() else {
            continue;
        };
        let physical = path.join("device").exists();
        let wireless = path.join("wireless").exists() || path.join("phy80211").exists();
        let interface_type = fs::read_to_string(path.join("type"))
            .ok()
            .map(|value| value.trim().to_string());
        let kind = if wireless {
            InterfaceKind::Wifi
        } else if interface_type.as_deref() == Some("1") {
            InterfaceKind::Ethernet
        } else {
            InterfaceKind::Other
        };
        let flags = fs::read_to_string(path.join("flags"))
            .ok()
            .and_then(|value| u64::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let up = flags & 0x1 != 0;
        let permanent_mac = fs::read_to_string(path.join("permaddr"))
            .ok()
            .and_then(|value| value.trim().parse::<MacAddress>().ok());
        let driver = fs::read_link(path.join("device/driver"))
            .ok()
            .and_then(|target| {
                target
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            });
        let description = driver.unwrap_or_else(|| {
            if physical {
                "physical adapter".to_string()
            } else {
                "virtual interface".to_string()
            }
        });

        interfaces.push(NetworkInterface {
            name,
            description,
            mac,
            permanent_mac,
            virtual_device: !physical,
            up,
            kind,
            guid: None,
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

#[cfg(windows)]
pub fn detect() -> Result<Vec<NetworkInterface>> {
    crate::platform::windows::detect_interfaces()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn detect() -> Result<Vec<NetworkInterface>> {
    bail!("network interface inspection is not implemented on this platform")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_root(name: &str) -> PathBuf {
        let mut root = std::env::temp_dir();
        root.push(format!("hwid-spoofer-net-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_interface(
        root: &std::path::Path,
        name: &str,
        mac: &str,
        kind_type: &str,
        physical: bool,
        wireless: bool,
        up: bool,
    ) {
        let path = root.join(name);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("address"), mac).unwrap();
        fs::write(path.join("type"), kind_type).unwrap();
        fs::write(path.join("flags"), if up { "0x1003" } else { "0x1002" }).unwrap();
        if physical {
            fs::create_dir_all(path.join("device/driver")).unwrap();
        }
        if wireless {
            fs::create_dir_all(path.join("wireless")).unwrap();
        }
    }

    #[test]
    fn parses_supported_mac_formats() {
        let expected = MacAddress::from_octets([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        for input in [
            "02:11:22:33:44:55",
            "02-11-22-33-44-55",
            "021122334455",
            "0211.2233.4455",
            " 02:11:22:33:44:55 ",
        ] {
            assert_eq!(input.parse::<MacAddress>().unwrap(), expected, "{input}");
        }
        assert_eq!(expected.to_string(), "02:11:22:33:44:55");
        assert_eq!(expected.to_hex_upper(), "021122334455");
    }

    #[test]
    fn rejects_invalid_mac_values() {
        for input in ["", "02:11:22", "zz:11:22:33:44:55", "02:11:22:33:44:5"] {
            assert!(input.parse::<MacAddress>().is_err(), "{input}");
        }
        let multicast: MacAddress = "01:00:5e:00:00:01".parse().unwrap();
        assert!(multicast.validate_for_spoof().is_err());
        let broadcast: MacAddress = "ff:ff:ff:ff:ff:ff".parse().unwrap();
        assert!(broadcast.validate_for_spoof().is_err());
        let zero: MacAddress = "00:00:00:00:00:00".parse().unwrap();
        assert!(zero.validate_for_spoof().is_err());
    }

    #[test]
    fn generated_macs_are_unicast_and_locally_administered() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let mac = MacAddress::random().unwrap();
            mac.validate_for_spoof().unwrap();
            assert!(mac.is_locally_administered());
            assert!(mac.is_unicast());
            seen.insert(mac);
        }
        assert!(seen.len() > 250, "CSPRNG produced duplicate values");
    }

    #[test]
    fn classifies_physical_and_virtual_interfaces() {
        let root = fixture_root("classify");
        write_interface(&root, "lo", "00:00:00:00:00:00", "772", false, false, false);
        write_interface(&root, "wlp2s0", "1c:79:2d:82:a5:0d", "1", true, true, true);
        write_interface(&root, "veth0", "aa:bb:cc:dd:ee:ff", "1", false, false, true);

        let interfaces = detect_with_root(&root).unwrap();
        assert_eq!(interfaces.len(), 3);

        let wifi = interfaces.iter().find(|i| i.name == "wlp2s0").unwrap();
        assert_eq!(wifi.kind, InterfaceKind::Wifi);
        assert!(!wifi.virtual_device);
        assert!(wifi.mac_spoof_supported());
        assert!(wifi.up);

        let veth = interfaces.iter().find(|i| i.name == "veth0").unwrap();
        assert!(veth.virtual_device);
        assert!(!veth.mac_spoof_supported());

        let loopback = interfaces.iter().find(|i| i.name == "lo").unwrap();
        assert_eq!(loopback.kind, InterfaceKind::Other);
        assert!(!loopback.mac_spoof_supported());

        fs::remove_dir_all(root).unwrap();
    }
}
