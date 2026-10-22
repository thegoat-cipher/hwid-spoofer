//! Platform abstraction: all OS-specific reads and writes behind one trait.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;

use anyhow::Result;
use serde::Serialize;

use crate::hardware::network::{MacAddress, NetworkInterface};
use crate::hardware::{
    BiosInfo, BoardInfo, CpuInfo, DiskInfo, GpuInfo, Privilege, SystemInfo, Value,
};

#[derive(Debug, Clone, Serialize)]
pub struct SystemContext {
    pub os: String,
    pub arch: String,
    pub elevated: bool,
    /// Human readable current privilege: "root", "Administrator", "standard user".
    pub privilege: String,
    pub user: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityFormat {
    /// 32 lowercase hex characters (`/etc/machine-id`).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Hex32,
    /// RFC 4122 UUID (Windows `MachineGuid`).
    #[cfg_attr(not(windows), allow(dead_code))]
    Uuid,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineIdentity {
    pub value: Value,
    pub source: String,
    pub format: IdentityFormat,
}

/// A real machine identity change, expressed as actions the OS performed.
pub type Actions = Vec<String>;

pub trait Platform: Sync {
    fn context(&self) -> SystemContext;

    fn board(&self) -> BoardInfo;
    fn bios(&self) -> BiosInfo;
    fn system(&self) -> SystemInfo;
    fn cpu(&self) -> CpuInfo;
    fn gpus(&self) -> Vec<GpuInfo>;
    fn disks(&self) -> Vec<DiskInfo>;
    fn interfaces(&self) -> Result<Vec<NetworkInterface>>;

    fn machine_identity(&self) -> MachineIdentity;

    /// Whether this OS backend implements MAC modification.
    fn mac_supported(&self) -> bool;
    /// Whether this OS backend implements machine identity modification.
    fn identity_supported(&self) -> bool;
    fn mac_method(&self) -> &'static str;
    fn identity_method(&self) -> &'static str;
    fn mac_persistence_note(&self) -> &'static str;
    fn required_privilege(&self) -> Privilege;
    fn unsupported_reason(&self) -> &'static str {
        "not supported on this platform"
    }
    fn identity_requires_restart(&self) -> bool {
        true
    }

    /// Modify the adapter MAC. Implementations verify at the OS layer and must
    /// return an error, never a synthetic success.
    fn apply_mac(&self, iface: &NetworkInterface, mac: &MacAddress) -> Result<Actions>;

    /// Restore a backed-up MAC. `prior_override` is the pre-existing driver
    /// override on Windows, if any.
    fn restore_mac(
        &self,
        iface: &NetworkInterface,
        mac: &MacAddress,
        prior_override: Option<&str>,
    ) -> Result<Actions>;

    /// Existing driver-level MAC override, if one is present.
    fn existing_mac_override(&self, iface: &NetworkInterface) -> Result<Option<String>>;

    /// Replace the OS machine identity. Callers must back up and confirm first.
    fn apply_machine_identity(&self, value: &str) -> Result<()>;
}

#[cfg(target_os = "linux")]
pub fn current() -> &'static dyn Platform {
    static INSTANCE: std::sync::LazyLock<linux::Linux> =
        std::sync::LazyLock::new(linux::Linux::new);
    &*INSTANCE
}

#[cfg(windows)]
pub fn current() -> &'static dyn Platform {
    static INSTANCE: std::sync::LazyLock<windows::Windows> =
        std::sync::LazyLock::new(windows::Windows::new);
    &*INSTANCE
}
