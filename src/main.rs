use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Serialize;

use hwid_spoofer::{backup, cli, hardware, platform, spoof, verify};

use backup::{BackupFile, Entry, RestoreStatus};
use cli::{BackupCommand, Cli, Command, GenerateKind, IdentityCommand, SpoofCommand};
use hardware::network::{MacAddress, NetworkInterface};
use hardware::{Capability, Inventory, ScanReport};
use platform::SystemContext;
use verify::VerifyStatus;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let platform = platform::current();
    match cli.command {
        Command::Scan => {
            let inventory = Inventory::collect(platform)?;
            let report = inventory.scan_report(platform);
            if cli.json {
                print_json(&report)
            } else {
                print_scan(&report);
                Ok(())
            }
        }
        Command::Capabilities => {
            let inventory = Inventory::collect(platform)?;
            let report = inventory.capability_report(platform);
            if cli.json {
                print_json(&report)
            } else {
                print_capabilities(&report.system, &report.capabilities);
                Ok(())
            }
        }
        Command::Interfaces => {
            let interfaces = platform.interfaces()?;
            if cli.json {
                print_json(&interfaces)
            } else {
                banner();
                println!("NETWORK INTERFACES");
                separator();
                print_interfaces(&interfaces);
                Ok(())
            }
        }
        Command::Generate { kind, count } => generate(kind, count, cli.json),
        Command::Spoof(args) => match args.command {
            SpoofCommand::Mac {
                interface,
                mac,
                allow_virtual,
                yes,
            } => spoof_mac(&interface, mac, allow_virtual, yes, cli.json),
        },
        Command::Identity(args) => match args.command {
            IdentityCommand::Inspect => identity_inspect(cli.json),
            IdentityCommand::Regenerate { yes } => identity_regenerate(yes, cli.json),
        },
        Command::Backup(args) => match args.command {
            BackupCommand::Create => backup_create(cli.json),
            BackupCommand::List => backup_list(cli.json),
        },
        Command::Restore { yes } => restore(yes, cli.json),
        Command::Verify => verify_backup(cli.json),
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let serialized = serde_json::to_string_pretty(value).context("failed to serialize output")?;
    println!("{serialized}");
    Ok(())
}

fn banner() {
    println!("========================================");
    println!("          HWID SPOOFER v{}", env!("CARGO_PKG_VERSION"));
    println!("========================================\n");
}

fn separator() {
    println!("----------------------------------------");
}

fn print_system(system: &SystemContext) {
    println!("Platform: {}", system.os);
    println!("Architecture: {}", system.arch);
    println!(
        "Privileges: {}{}",
        system.privilege,
        if system.elevated {
            ""
        } else {
            " (elevated privileges are required for modifications)"
        }
    );
    println!("Host: {} / {}", system.hostname, system.user);
}

fn print_scan(report: &ScanReport) {
    banner();
    print_system(&report.system);
    println!();
    println!("HARDWARE IDENTIFIERS");
    separator();
    for identifier in &report.identifiers {
        println!(
            "{:<28}{}",
            format!("{}:", identifier.label),
            identifier.value.display()
        );
    }
    println!();
    println!("MODIFICATION CAPABILITIES");
    separator();
    for capability in &report.capabilities {
        let state = if capability.supported {
            let mut text = format!("Supported (requires {})", capability.privileges.label());
            if capability.requires_restart {
                text.push_str(", restart recommended");
            }
            text
        } else {
            "Unsupported".to_string()
        };
        println!("{:<28}{}", format!("{}:", capability.label), state);
    }
    println!();
    println!("NETWORK INTERFACES");
    separator();
    if report.hardware.interfaces.is_empty() {
        println!("none detected");
    } else {
        print_interfaces(&report.hardware.interfaces);
    }
    println!();
    println!("AVAILABLE COMMANDS");
    separator();
    for command in [
        "scan",
        "capabilities",
        "interfaces",
        "generate --type <mac|uuid|machine-id|serial|all>",
        "spoof mac --interface <name>",
        "identity inspect",
        "identity regenerate",
        "backup create",
        "restore",
        "verify",
    ] {
        println!("  {command}");
    }
}

fn print_capabilities(system: &SystemContext, capabilities: &[Capability]) {
    banner();
    print_system(system);
    println!();
    println!("MODIFICATION CAPABILITIES");
    separator();
    for capability in capabilities {
        if capability.supported {
            let mut details = vec![format!("requires {}", capability.privileges.label())];
            if capability.requires_restart {
                details.push("restart recommended".to_string());
            }
            details.push(format!(
                "firmware-controlled: {}",
                if capability.firmware_controlled {
                    "yes"
                } else {
                    "no"
                }
            ));
            println!(
                "{:<24}Supported ({})",
                format!("{}:", capability.label),
                details.join("; ")
            );
        } else {
            println!("{:<24}Unsupported", format!("{}:", capability.label));
        }
        println!("    current: {}", capability.current.display());
        if let Some(method) = &capability.method {
            println!("    mechanism: {method}");
        }
        for reason in &capability.reasons {
            println!("    reason: {reason}");
        }
        for note in &capability.notes {
            println!("    note: {note}");
        }
        println!();
    }
}

fn print_interfaces(interfaces: &[NetworkInterface]) {
    println!(
        "{:<16} {:<9} {:<6} {:<19} {:<14} DESCRIPTION",
        "NAME", "KIND", "UP", "MAC", "SPOOFABLE"
    );
    for interface in interfaces {
        let spoofable = if interface.mac_spoof_supported() {
            "yes"
        } else if interface.virtual_device {
            "no (virtual)"
        } else {
            "no"
        };
        println!(
            "{:<16} {:<9} {:<6} {:<19} {:<14} {}",
            interface.name,
            interface.kind.label(),
            if interface.up { "up" } else { "down" },
            interface.mac.to_string(),
            spoofable,
            interface.description
        );
    }
}

#[derive(Debug, Serialize)]
struct GeneratedValue {
    #[serde(rename = "type")]
    kind: &'static str,
    value: String,
}

fn generate(kind: GenerateKind, count: u32, json: bool) -> Result<()> {
    let mut values = Vec::new();
    for value_kind in kind.types() {
        for _ in 0..count {
            let value = match value_kind {
                GenerateKind::Mac => MacAddress::random()?.to_string(),
                GenerateKind::Uuid => spoof::identity::random_uuid_v4()?,
                GenerateKind::MachineId => spoof::identity::random_hex32()?,
                GenerateKind::Serial => spoof::random_serial()?,
                GenerateKind::All => unreachable!("All is expanded into concrete types"),
            };
            values.push(GeneratedValue {
                kind: value_kind.label(),
                value,
            });
        }
    }
    if json {
        print_json(&serde_json::json!({ "values": values }))
    } else {
        for generated in &values {
            println!("{:<12} {}", generated.kind, generated.value);
        }
        Ok(())
    }
}

fn spoof_mac(
    interface: &str,
    mac: Option<String>,
    allow_virtual: bool,
    yes: bool,
    json: bool,
) -> Result<()> {
    let platform = platform::current();
    let parsed = mac
        .as_deref()
        .map(str::parse::<MacAddress>)
        .transpose()
        .context("invalid --mac value")?;
    spoof::require_privilege(platform)?;

    eprintln!("WARNING: changing the MAC address of '{interface}' interrupts its network link.");
    eprintln!("  - Existing connections, DHCP leases, and VPN sessions may drop.");
    eprintln!("  - Networks using MAC filtering or 802.1X may reject the new address.");
    eprintln!("  - The previous address is backed up; use `hwid-spoofer restore` to revert.");
    confirm("Apply this change?", yes)?;

    let (mut backup_file, backup_path) = load_backup()?;
    backup_file.ensure_platform()?;
    let request = spoof::mac::MacSpoofRequest {
        interface: interface.to_string(),
        mac: parsed,
        allow_virtual,
    };
    let outcome = spoof::mac::spoof(platform, &request, &mut backup_file, &backup_path)?;

    if json {
        print_json(&outcome)
    } else {
        println!();
        for action in &outcome.actions {
            println!("  - {action}");
        }
        println!("Interface:    {}", outcome.interface);
        println!("Original MAC: {}", outcome.original);
        println!("New MAC:      {}", outcome.applied);
        println!("Verification: passed (independent adapter query)");
        println!("Backup:       {}", outcome.backup_path.display());
        Ok(())
    }
}

fn identity_inspect(json: bool) -> Result<()> {
    let platform = platform::current();
    let inspection = spoof::identity::inspect(platform);
    if json {
        return print_json(&inspection);
    }
    banner();
    println!("MACHINE IDENTITY");
    separator();
    println!("Value:     {}", inspection.value.display());
    println!("Source:    {}", inspection.source);
    println!(
        "Format:    {}",
        match inspection.format {
            platform::IdentityFormat::Hex32 => "32 hex characters",
            platform::IdentityFormat::Uuid => "UUID",
        }
    );
    println!(
        "Writable:  {}{}",
        if inspection.writable { "yes" } else { "no" },
        if inspection.elevated {
            ""
        } else {
            " (run elevated to change it)"
        }
    );
    Ok(())
}

fn identity_regenerate(yes: bool, json: bool) -> Result<()> {
    let platform = platform::current();
    spoof::require_privilege(platform)?;
    eprintln!("WARNING: regenerating the machine identity affects the whole operating system.");
    for consequence in spoof::identity::CONSEQUENCES {
        eprintln!("  - {consequence}");
    }
    confirm("Regenerate the machine identity?", yes)?;

    let (mut backup_file, backup_path) = load_backup()?;
    backup_file.ensure_platform()?;
    let outcome = spoof::identity::regenerate(platform, &mut backup_file, &backup_path)?;
    if json {
        print_json(&outcome)
    } else {
        println!();
        println!("Source:      {}", outcome.source);
        println!("Previous:    {}", outcome.previous);
        println!("New value:   {}", outcome.applied);
        println!("Verification passed (identity re-read from the OS).");
        println!("Backup:      {}", backup_path.display());
        println!("Restart or re-login for every consumer to observe the new identity.");
        Ok(())
    }
}

fn load_backup() -> Result<(BackupFile, PathBuf)> {
    let path = backup::backup_path();
    let file = BackupFile::load(&path)?.unwrap_or_else(|| BackupFile::new(std::env::consts::OS));
    Ok((file, path))
}

#[derive(Debug, Serialize)]
struct BackupSummary {
    path: PathBuf,
    added: usize,
    warnings: Vec<String>,
    backup: BackupFile,
}

fn backup_create(json: bool) -> Result<()> {
    let platform = platform::current();
    let (mut file, path) = load_backup()?;
    file.ensure_platform()?;
    let interfaces = platform.interfaces()?;
    let mut added = 0usize;
    let mut warnings = Vec::new();

    for interface in interfaces
        .iter()
        .filter(|iface| iface.mac_spoof_supported())
    {
        let prior_override = match platform.existing_mac_override(interface) {
            Ok(prior) => prior,
            Err(error) => {
                warnings.push(format!(
                    "could not read the existing MAC override for {}: {error:#}",
                    interface.name
                ));
                None
            }
        };
        if file.record_mac_original(interface, prior_override) {
            added += 1;
        }
    }

    let identity = platform.machine_identity();
    if identity.value.as_str().is_some() {
        if file.record_identity_original(&identity) {
            added += 1;
        }
    } else {
        warnings.push(format!(
            "machine identity unavailable at {}; not recorded",
            identity.source
        ));
    }

    file.save(&path)?;
    if json {
        print_json(&BackupSummary {
            path,
            added,
            warnings,
            backup: file,
        })
    } else {
        println!("Backup: {}", path.display());
        if added == 0 {
            println!("No new entries; existing original values are preserved.");
        } else {
            println!(
                "{added} new entr{} recorded.",
                if added == 1 { "y" } else { "ies" }
            );
        }
        print_backup_entries(&file);
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        Ok(())
    }
}

fn backup_list(json: bool) -> Result<()> {
    let path = backup::backup_path();
    let Some(file) = BackupFile::load(&path)? else {
        bail!(
            "no backup found at {}; run `hwid-spoofer backup create`",
            path.display()
        );
    };
    if json {
        print_json(&serde_json::json!({ "path": path, "backup": file }))
    } else {
        println!("Backup: {}", path.display());
        println!(
            "Created: {}   Updated: {}   Platform: {}",
            file.created_at, file.updated_at, file.platform
        );
        print_backup_entries(&file);
        Ok(())
    }
}

fn print_backup_entries(file: &BackupFile) {
    if file.entries.is_empty() {
        println!("  (no entries)");
        return;
    }
    for entry in &file.entries {
        match entry {
            Entry::Mac(mac) => {
                println!(
                    "  mac               {:<16} original {}  applied {}",
                    mac.interface,
                    mac.original,
                    mac.applied.as_deref().unwrap_or("-")
                );
                if let Some(prior) = &mac.prior_override {
                    println!("  {:<17} pre-existing driver override: {prior}", "");
                }
            }
            Entry::MachineIdentity(identity) => println!(
                "  machine_identity  {:<16} original {}  applied {}",
                identity.target,
                identity.original,
                identity.applied.as_deref().unwrap_or("-")
            ),
        }
    }
}

fn restore(yes: bool, json: bool) -> Result<()> {
    let platform = platform::current();
    let path = backup::backup_path();
    let Some(mut file) = BackupFile::load(&path)? else {
        bail!("no backup found at {}; nothing to restore", path.display());
    };
    file.ensure_platform()?;
    if file.entries.is_empty() {
        bail!("backup {} contains no entries", path.display());
    }

    if !json {
        println!("Backup: {}", path.display());
        print_backup_entries(&file);
    }
    confirm("Restore these values?", yes)?;

    let results = backup::restore_all(platform, &file);
    for result in &results {
        if !matches!(result.status, RestoreStatus::Failed) {
            file.mark_restored(result.kind, &result.target);
        }
    }
    file.save(&path)
        .context("restoration finished, but updating the backup bookkeeping failed")?;
    if json {
        print_json(&serde_json::json!({ "path": path, "results": results }))?;
    } else {
        println!();
        for result in &results {
            let status = match result.status {
                RestoreStatus::Restored => "restored",
                RestoreStatus::AlreadyOriginal => "already original",
                RestoreStatus::Failed => "FAILED",
            };
            println!(
                "{:<16} {:<16} {status}: {}",
                result.kind, result.target, result.message
            );
            for action in &result.actions {
                println!("    - {action}");
            }
        }
    }

    let failed = results
        .iter()
        .filter(|result| matches!(result.status, RestoreStatus::Failed))
        .count();
    if failed > 0 {
        bail!("{failed} restoration(s) failed; see output above");
    }
    Ok(())
}

fn verify_backup(json: bool) -> Result<()> {
    let platform = platform::current();
    let path = backup::backup_path();
    let Some(file) = BackupFile::load(&path)? else {
        bail!(
            "no backup found at {}; run `hwid-spoofer backup create` first",
            path.display()
        );
    };
    file.ensure_platform()?;
    if file.entries.is_empty() {
        bail!("backup {} contains no entries", path.display());
    }
    let items = verify::verify_backup(platform, &file);

    if json {
        print_json(&serde_json::json!({ "path": path, "items": items }))?;
    } else {
        println!("Backup: {}", path.display());
        println!(
            "{:<16} {:<16} {:<10} {:<19} ACTUAL",
            "KIND", "TARGET", "STATUS", "EXPECTED"
        );
        for item in &items {
            let status = match item.status {
                VerifyStatus::Matches => "match",
                VerifyStatus::Drift => "DRIFT",
                VerifyStatus::TargetMissing => "missing",
            };
            println!(
                "{:<16} {:<16} {:<10} {:<19} {}",
                item.kind,
                item.target,
                status,
                item.expected,
                item.actual.as_deref().unwrap_or("-")
            );
            if item.expected_is_applied {
                println!("  (expected value is the override applied by this tool)");
            }
        }
    }

    let problems = items
        .iter()
        .filter(|item| item.status != VerifyStatus::Matches)
        .count();
    if problems > 0 {
        bail!("{problems} value(s) do not match the backup");
    }
    Ok(())
}

fn confirm(prompt: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        bail!("confirmation required in non-interactive mode: pass --yes");
    }
    eprint!("{prompt} Type 'yes' to continue: ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read confirmation from stdin")?;
    if input.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("aborted: confirmation was not given")
    }
}
