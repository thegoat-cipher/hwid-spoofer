//! Privileged end-to-end test: creates a dummy Ethernet adapter, changes its
//! MAC through the real kernel interface, verifies it, restores it, and removes
//! the adapter.
//!
//! Ignored by default because it requires root. Run:
//!
//! ```text
//! sudo -E cargo test --test privileged -- --ignored --nocapture
//! ```
//!
//! The interface is virtual (created by the kernel's dummy driver) because
//! changing a physical adapter's MAC disconnects the machine from its network.
//! The ioctl, verification, backup, and restore paths are identical.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

const INTERFACE: &str = "hwidspoof0";

struct StateDir(PathBuf);

impl StateDir {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("hwid-spoofer-privileged-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create state dir");
        StateDir(path)
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(state: &StateDir, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hwid-spoofer"))
        .args(args)
        .env("HWID_SPOOFER_STATE_DIR", &state.0)
        .output()
        .expect("run hwid-spoofer")
}

fn current_mac() -> String {
    fs::read_to_string(format!("/sys/class/net/{INTERFACE}/address"))
        .expect("read live MAC from sysfs")
        .trim()
        .to_string()
}

fn delete_interface() {
    let _ = Command::new("ip").args(["link", "del", INTERFACE]).status();
}

#[test]
#[ignore = "requires root; creates and removes a dummy network interface"]
fn dummy_adapter_mac_round_trip() {
    assert!(
        nix::unistd::Uid::effective().is_root(),
        "run with sudo -E cargo test --test privileged -- --ignored"
    );
    let state = StateDir::new();
    delete_interface();

    let created = Command::new("ip")
        .args(["link", "add", INTERFACE, "type", "dummy"])
        .status()
        .expect("execute ip");
    assert!(created.success(), "failed to create the dummy interface");

    let original = current_mac();

    let output = run(
        &state,
        &[
            "spoof",
            "mac",
            "--interface",
            INTERFACE,
            "--allow-virtual",
            "--yes",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "spoof failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let outcome: Value = serde_json::from_slice(&output.stdout).expect("valid outcome JSON");
    assert_eq!(outcome["verified"], true);
    let applied = outcome["applied"].as_str().unwrap().to_string();
    assert_ne!(applied, original);

    // Independent read, not the tool's own bookkeeping.
    assert_eq!(current_mac(), applied, "kernel did not adopt the new MAC");

    let restored = run(&state, &["restore", "--yes", "--json"]);
    assert!(
        restored.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(
        current_mac(),
        original,
        "restore did not return the original MAC"
    );

    // The backup must now expect the original value again.
    let verified = run(&state, &["verify", "--json"]);
    assert!(verified.status.success(), "verify after restore failed");
    let verify_report: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verify_report["items"][0]["status"], "matches");

    delete_interface();
}
