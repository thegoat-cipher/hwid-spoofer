//! End-to-end tests that exercise the compiled binary against the live host.
//! These do not require root: privileged operations are checked for honest
//! refusal instead.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempState {
    path: PathBuf,
}

impl TempState {
    fn new(label: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hwid-spoofer-it-{}-{unique}-{label}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test state directory");
        TempState { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run(state: &TempState, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hwid-spoofer"))
        .args(args)
        .env("HWID_SPOOFER_STATE_DIR", state.path())
        .output()
        .expect("failed to execute hwid-spoofer")
}

fn run_json(state: &TempState, args: &[&str]) -> Value {
    let output = run(state, args);
    assert!(
        output.status.success(),
        "command {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON from {:?}: {error}\nstdout: {}",
            args,
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn find<'a>(items: &'a Value, id: &str) -> &'a Value {
    items
        .as_array()
        .expect("array")
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("missing identifier/capability '{id}'"))
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

#[cfg(windows)]
fn is_root() -> bool {
    let output = Command::new(env!("CARGO_BIN_EXE_hwid-spoofer"))
        .args(["scan", "--json"])
        .output()
        .expect("scan");
    serde_json::from_slice::<Value>(&output.stdout)
        .ok()
        .and_then(|report| report["system"]["elevated"].as_bool())
        .unwrap_or(false)
}

#[test]
fn scan_json_reports_live_identifiers_and_capabilities() {
    let state = TempState::new("scan");
    let report = run_json(&state, &["scan", "--json"]);

    assert!(report["system"]["os"].as_str().unwrap_or("").len() > 2);
    assert!(!report["system"]["arch"].as_str().unwrap_or("").is_empty());
    assert!(report["system"]["elevated"].is_boolean());

    let identifiers = &report["identifiers"];
    for id in [
        "motherboard_serial",
        "bios_serial",
        "system_uuid",
        "disk_serial",
        "cpu",
        "gpu",
        "mac",
        "machine_identity",
    ] {
        let identifier = find(identifiers, id);
        let state = identifier["value"]["state"].as_str().unwrap();
        assert!(
            state == "known" || state == "unavailable",
            "unexpected state {state} for {id}"
        );
    }

    let cpu = find(identifiers, "cpu");
    assert_eq!(
        cpu["value"]["state"], "known",
        "CPU identifier must be live"
    );
    assert!(!cpu["value"]["value"].as_str().unwrap_or("").is_empty());
    assert!(!report["capabilities"].as_array().unwrap().is_empty());
}

#[test]
fn capabilities_mark_firmware_identifiers_read_only_and_mac_supported() {
    let state = TempState::new("caps");
    let report = run_json(&state, &["capabilities", "--json"]);
    let capabilities = &report["capabilities"];

    let board = find(capabilities, "motherboard_serial");
    assert_eq!(board["supported"], false);
    assert_eq!(board["firmware_controlled"], true);

    let bios = find(capabilities, "bios_serial");
    assert_eq!(bios["supported"], false);
    assert_eq!(bios["firmware_controlled"], true);

    let mac = find(capabilities, "mac");
    assert_eq!(mac["firmware_controlled"], false);
    let expected_privilege = if cfg!(windows) {
        "administrator"
    } else {
        "root"
    };
    assert_eq!(mac["privileges"], expected_privilege);

    let identity = find(capabilities, "machine_identity");
    assert_eq!(identity["supported"], true);
    assert_eq!(identity["privileges"], expected_privilege);
}

#[test]
fn interfaces_json_is_consistent_with_spoof_support() {
    let state = TempState::new("interfaces");
    let interfaces = run_json(&state, &["interfaces", "--json"]);
    let interfaces = interfaces.as_array().expect("interface array");
    assert!(!interfaces.is_empty(), "host must expose at least loopback");

    for interface in interfaces {
        let mac = interface["mac"].as_str().unwrap();
        assert_eq!(mac.len(), 17, "unexpected MAC format: {mac}");
        assert_eq!(mac.matches(':').count(), 5, "unexpected MAC format: {mac}");
        assert!(interface["virtual_device"].is_boolean());
    }

    #[cfg(target_os = "linux")]
    {
        let loopback = interfaces
            .iter()
            .find(|interface| interface["name"] == "lo")
            .expect("loopback present on Linux");
        assert_eq!(loopback["virtual_device"], true);
        assert_eq!(loopback["kind"], "other");
    }
}

#[test]
fn generate_produces_valid_unique_values() {
    let state = TempState::new("generate");
    let generated = run_json(
        &state,
        &["generate", "--type", "mac", "--count", "8", "--json"],
    );
    let values = generated["values"].as_array().unwrap();
    assert_eq!(values.len(), 8);
    let mut seen = std::collections::HashSet::new();
    for item in values {
        assert_eq!(item["type"], "mac");
        let mac = item["value"].as_str().unwrap();
        let parsed: hwid_spoofer::hardware::network::MacAddress = mac.parse().unwrap();
        parsed.validate_for_spoof().unwrap();
        assert!(
            parsed.is_locally_administered(),
            "{mac} not locally administered"
        );
        assert!(seen.insert(mac.to_string()), "duplicate MAC {mac}");
    }

    let uuid = run_json(&state, &["generate", "--type", "uuid", "--json"]);
    let uuid = uuid["values"][0]["value"].as_str().unwrap();
    assert_eq!(uuid.split('-').count(), 5);
    assert_eq!(uuid.split('-').nth(2).unwrap().chars().next(), Some('4'));

    let machine_id = run_json(&state, &["generate", "--type", "machine-id", "--json"]);
    let machine_id = machine_id["values"][0]["value"].as_str().unwrap();
    assert_eq!(machine_id.len(), 32);
    assert!(machine_id
        .chars()
        .all(|character| character.is_ascii_hexdigit()));

    let serial = run_json(&state, &["generate", "--type", "serial", "--json"]);
    let serial = serial["values"][0]["value"].as_str().unwrap();
    assert_eq!(serial.len(), 12);
    assert!(serial
        .chars()
        .all(|character| character.is_ascii_alphanumeric()));

    let all = run_json(&state, &["generate", "--type", "all", "--json"]);
    let kinds: Vec<&str> = all["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["mac", "uuid", "machine-id", "serial"]);
}

#[test]
fn backup_create_and_list_record_original_values() {
    let state = TempState::new("backup");
    let created = run_json(&state, &["backup", "create", "--json"]);
    let path = PathBuf::from(created["path"].as_str().unwrap());
    assert!(
        path.exists(),
        "backup file must exist at {}",
        path.display()
    );
    assert_eq!(created["backup"]["schema"], 1);
    assert!(!created["backup"]["entries"].as_array().unwrap().is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "backup must be owner-only");
    }

    let listed = run_json(&state, &["backup", "list", "--json"]);
    assert_eq!(listed["path"], created["path"]);
    assert_eq!(
        listed["backup"]["entries"].as_array().unwrap().len(),
        created["backup"]["entries"].as_array().unwrap().len()
    );
}

#[test]
fn restore_and_verify_are_noops_when_nothing_changed() {
    let state = TempState::new("restore");
    run_json(&state, &["backup", "create", "--json"]);

    let restore = run_json(&state, &["restore", "--yes", "--json"]);
    let results = restore["results"].as_array().unwrap();
    assert!(!results.is_empty());
    for result in results {
        assert_ne!(result["status"], "failed");
        assert_ne!(result["status"], "restored");
    }

    let verify = run_json(&state, &["verify", "--json"]);
    for item in verify["items"].as_array().unwrap() {
        assert_eq!(item["status"], "matches", "unexpected drift: {item}");
    }
}

#[test]
fn unknown_interface_is_rejected_before_any_backup_is_written() {
    let state = TempState::new("missing");
    let output = run(
        &state,
        &[
            "spoof",
            "mac",
            "--interface",
            "hwid-spoofer-definitely-missing",
            "--yes",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_root() {
        assert!(
            stderr.contains("not found"),
            "expected missing interface error, got: {stderr}"
        );
    } else {
        assert!(
            stderr.to_ascii_lowercase().contains("privilege")
                || stderr.to_ascii_lowercase().contains("root")
                || stderr.to_ascii_lowercase().contains("administrator"),
            "expected privilege error, got: {stderr}"
        );
    }
    assert!(!state.path().join("backup.json").exists());
    assert!(!stderr.contains("Verification: passed"));
}

#[test]
fn privileged_spoof_is_refused_without_elevation() {
    if is_root() {
        return;
    }
    let state = TempState::new("privilege");
    let output = run(&state, &["spoof", "mac", "--interface", "lo", "--yes"]);
    assert!(!output.status.success());
    let stderr = output_stderr(&output).to_ascii_lowercase();
    if cfg!(windows) {
        assert!(stderr.contains("administrator"), "{stderr}");
    } else {
        assert!(stderr.contains("root privileges"), "{stderr}");
    }
    assert!(!stderr.contains("verification: passed"), "{stderr}");
    assert!(!state.path().join("backup.json").exists());
}

fn output_stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn malformed_mac_is_rejected() {
    let state = TempState::new("badmac");
    let output = run(
        &state,
        &[
            "spoof",
            "mac",
            "--interface",
            "lo",
            "--mac",
            "zz:11:22:33:44:55",
            "--yes",
        ],
    );
    assert!(!output.status.success());
    assert!(output_stderr(&output)
        .to_ascii_lowercase()
        .contains("invalid --mac value"));
}

#[test]
fn verify_without_backup_fails_clearly() {
    let state = TempState::new("verify-none");
    let output = run(&state, &["verify"]);
    assert!(!output.status.success());
    assert!(output_stderr(&output).contains("no backup found"));
}

#[test]
fn version_and_help_are_available() {
    let state = TempState::new("help");
    let version = run(&state, &["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("0.1.0"));

    let help = run(&state, &["scan", "--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--json"));
}
