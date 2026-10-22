//! Command-line interface definition.

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "hwid-spoofer",
    version,
    about = "Physical hardware identifier inspection and supported spoofing",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Emit machine-readable JSON on stdout (warnings stay on stderr).
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Inspect hardware identifiers, capabilities, and permissions.
    Scan,
    /// Report per-identifier modification support and required privileges.
    Capabilities,
    /// List network adapters and whether their MAC can be changed.
    Interfaces,
    /// Generate cryptographically secure replacement identifiers.
    Generate {
        /// Identifier type to generate.
        #[arg(long = "type", value_enum, default_value_t = GenerateKind::All)]
        kind: GenerateKind,
        /// Number of values to generate per selected type (1-1000).
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=1000))]
        count: u32,
    },
    /// Apply a supported identifier change.
    Spoof(SpoofArgs),
    /// Inspect or regenerate the OS machine identity.
    Identity(IdentityArgs),
    /// Create or list identifier backups.
    Backup(BackupArgs),
    /// Restore every value in the backup and verify the result.
    Restore {
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Compare live identifiers with the backup using independent queries.
    Verify,
}

#[derive(Args, Debug)]
pub struct SpoofArgs {
    #[command(subcommand)]
    pub command: SpoofCommand,
}

#[derive(Subcommand, Debug)]
pub enum SpoofCommand {
    /// Change a physical adapter's MAC address.
    Mac {
        /// Interface name (Linux) or adapter friendly name/GUID (Windows).
        #[arg(long)]
        interface: String,
        /// Explicit MAC address; a secure random locally administered MAC is used when omitted.
        #[arg(long)]
        mac: Option<String>,
        /// Allow changing a virtual interface. Testing only; physical adapters are the supported target.
        #[arg(long)]
        allow_virtual: bool,
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommand,
}

#[derive(Subcommand, Debug)]
pub enum IdentityCommand {
    /// Show the current machine identity, its source, and whether it is writable.
    Inspect,
    /// Replace the machine identity with a new random value (backup + confirmation required).
    Regenerate {
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub command: BackupCommand,
}

#[derive(Subcommand, Debug)]
pub enum BackupCommand {
    /// Save the original value of every configurable identifier.
    Create,
    /// List the entries recorded in the backup.
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GenerateKind {
    /// Locally administered unicast MAC address.
    Mac,
    /// RFC 4122 version 4 UUID (valid for Windows MachineGuid).
    Uuid,
    /// 32 lowercase hex characters (valid for /etc/machine-id).
    MachineId,
    /// Plausible OEM-style serial candidate (informational only; firmware identifiers are read-only).
    Serial,
    /// One of each type.
    All,
}

impl GenerateKind {
    pub fn types(self) -> &'static [GenerateKind] {
        const MAC: &[GenerateKind] = &[GenerateKind::Mac];
        const UUID: &[GenerateKind] = &[GenerateKind::Uuid];
        const MACHINE_ID: &[GenerateKind] = &[GenerateKind::MachineId];
        const SERIAL: &[GenerateKind] = &[GenerateKind::Serial];
        const ALL: &[GenerateKind] = &[
            GenerateKind::Mac,
            GenerateKind::Uuid,
            GenerateKind::MachineId,
            GenerateKind::Serial,
        ];
        match self {
            GenerateKind::Mac => MAC,
            GenerateKind::Uuid => UUID,
            GenerateKind::MachineId => MACHINE_ID,
            GenerateKind::Serial => SERIAL,
            GenerateKind::All => ALL,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            GenerateKind::Mac => "mac",
            GenerateKind::Uuid => "uuid",
            GenerateKind::MachineId => "machine-id",
            GenerateKind::Serial => "serial",
            GenerateKind::All => "all",
        }
    }
}
