# HWID Spoofer

A Rust command-line tool that inspects hardware identifiers on physical
Windows and Linux machines, reports which ones can genuinely be changed, applies
the supported changes through documented OS interfaces, verifies them
independently, and restores originals from a backup.

Version 0.1.0. Linux x86-64 is the tested runtime target; Windows x86-64 is
implemented and compile-verified with the Win32 backend (see
[`TEST_REPORT.md`](TEST_REPORT.md) for exact runtime coverage).

## What it can and cannot change

| Identifier | Read | Change | How |
|---|---|---|---|
| Motherboard serial | Yes | No | SMBIOS/firmware; no OS write interface |
| SMBIOS system UUID | Yes | No | Firmware-controlled |
| BIOS serial | Not exposed | No | SMBIOS Type 0 has no serial field; vendor/version/date are read-only |
| Disk serial | Yes | No | ATA/NVMe identify data |
| CPU identifier | Yes | No | Silicon/CPUID |
| GPU identifier | Yes | No | PCI/VBIOS |
| MAC address | Yes | **Yes**, physical Ethernet/Wi-Fi | Linux `ioctl(SIOCSIFHWADDR)`; Windows `NetworkAddress` registry + adapter restart |
| OS machine identity | Yes | **Yes** | Linux `/etc/machine-id`; Windows `MachineGuid` |

The tool never claims a firmware identifier was spoofed. Virtual adapters are
rejected unless `--allow-virtual` is explicitly passed (testing only).

## Requirements

- Rust 1.85 or newer (`rustup` recommended).
- Linux: a C linker/`build-essential`; no extra runtime libraries beyond glibc.
- Windows: Visual Studio Build Tools with the C++ workload and Windows SDK.
- Root (Linux) or Administrator (Windows) for writes.

## Build

Complete platform-specific steps, including prerequisites, upgrade, uninstall,
and troubleshooting, are in [`INSTALL.md`](INSTALL.md).

Linux:

```bash
cargo build --release
sudo install -m 755 target/release/hwid-spoofer /usr/local/bin/hwid-spoofer
```

Windows (Developer PowerShell / x64 Native Tools shell):

```powershell
cargo build --release
# Binary: .\target\release\hwid-spoofer.exe
```

Cross-check the Windows backend from Linux (no linker required for `check`):

```bash
rustup target add x86_64-pc-windows-msvc
cargo check --target x86_64-pc-windows-msvc --all-targets
cargo clippy --target x86_64-pc-windows-msvc --all-targets -- -D warnings
```

## Usage

```bash
# Full inventory, capabilities, adapters, and hints
hwid-spoofer scan
hwid-spoofer scan --json

# Capability truth table with mechanisms and required privileges
hwid-spoofer capabilities

# Adapter listing
hwid-spoofer interfaces

# Secure replacement values
hwid-spoofer generate --type mac --count 3
hwid-spoofer generate --type uuid
hwid-spoofer generate --type machine-id
hwid-spoofer generate --type serial

# Back up originals first
hwid-spoofer backup create
hwid-spoofer backup list

# Change a physical adapter MAC (root/Administrator)
sudo hwid-spoofer spoof mac --interface wlp2s0 --yes
sudo hwid-spoofer spoof mac --interface eth0 --mac 02:11:22:33:44:55 --yes

# Verify through fresh OS queries
sudo hwid-spoofer verify

# Restore everything recorded in the backup
sudo hwid-spoofer restore --yes

# OS machine identity
hwid-spoofer identity inspect
sudo hwid-spoofer identity regenerate --yes
```

`--json` is global and may be placed after any subcommand. Warnings and errors
go to stderr, so stdout remains valid JSON.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (for `verify`: every value matches the backup) |
| 1 | Operational failure: unsupported hardware, missing privilege, failed verification, drift, failed restore |
| 2 | CLI usage error |

## How it works

### Detection

- **Linux:** sysfs DMI (`/sys/class/dmi/id`), `/proc/cpuinfo`, `/sys/block` disk
  serials (including SCSI VPD page 80 and `wwid`), DRM PCI IDs, and
  `/sys/class/net` adapter data. DMI serials are root-only on common
  distributions; a non-root scan reports exactly why a value is unavailable.
- **Windows:** the raw SMBIOS table via `GetSystemFirmwareTable('RSMB')`,
  `GetAdaptersAddresses`, `IOCTL_STORAGE_QUERY_PROPERTY` for disk descriptors,
  and documented registry keys for CPU, GPU, and `MachineGuid`.

### MAC changes

**Linux:** `ioctl(SIOCSIFHWADDR)` on an `AF_INET` control socket. If the driver
returns `EBUSY`, the link is brought down, the address set, and the original
flags restored. The change is runtime-only and is lost on reboot.

**Windows:** writes the adapter's `NetworkAddress` value under its
`{4d36e972-e325-11ce-bfc1-08002be10318}` class key, then restarts the adapter
with `Restart-NetAdapter` (fallback: `netsh interface set interface
admin=disable/enable`). This is the vendor-supported override mechanism; it
survives reboot. `restore` removes the override, or restores a pre-existing
one.

Both platforms re-enumerate adapters after the write. A mismatch triggers a
rollback attempt and a non-zero exit; success is never printed without a fresh
read.

### Machine identity

- Linux: atomic replacement of `/etc/machine-id` with 32 random hex characters,
  mode `0444`; `/var/lib/dbus/machine-id` is updated only if it is a regular
  file. A reboot is recommended so all services observe the new value.
- Windows: `MachineGuid` (`REG_SZ`) under
  `HKLM\SOFTWARE\Microsoft\Cryptography`, with a restart recommended.

Identity regeneration prints activation, service, and networking consequences
and requires confirmation. The original is backed up before the write, and a
failed verification triggers rollback.

## Backups

| Context | Path |
|---|---|
| Linux root | `/var/lib/hwid-spoofer/backup.json` |
| Linux non-root | `$XDG_STATE_HOME/hwid-spoofer/backup.json` or `~/.local/state/hwid-spoofer/backup.json` |
| Windows | `%ProgramData%\hwid-spoofer\backup.json` |
| Override | `HWID_SPOOFER_STATE_DIR=/some/dir` |

On Unix the directory is `0700` and the file `0600`. Originals are immutable;
later `backup create` runs never overwrite the first recorded value. A backup
is bound to its OS family and is refused on a different one.

Use the same elevation for backup, spoof, and restore so all commands see the
same file. `HWID_SPOOFER_STATE_DIR` pins one location if needed.

## Testing

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo check --target x86_64-pc-windows-msvc --all-targets
```

A root-only end-to-end MAC test creates a dummy interface, changes its MAC,
verifies through sysfs, restores it, and removes the interface:

```bash
sudo -E cargo test --test privileged -- --ignored --nocapture
```

It is ignored by default because it needs root and creates/deletes a network
interface. It exercises the same ioctl, backup, verification, and restore code
as a physical adapter. Changing a physical WiFi adapter can disconnect the
machine, so the automated test deliberately uses a kernel dummy device.

## Troubleshooting

**`permission denied reading /sys/class/dmi/id/board_serial`**
Run the scan with `sudo`; DMI identity files are root-only on most Linux
systems.

**`EBUSY` / driver rejects the MAC change**
Some drivers do not implement address changes. The tool reports the OS error
and restores the link state. Virtual adapters are refused by design.

**Windows: MAC did not change after the restart**
Not every driver honors `NetworkAddress`. The tool waits for the adapter to
report the new address for 20 seconds and then fails with an explicit error.
Check the adapter vendor's documentation and the registry
`NetCfgInstanceId` mapping.

**`confirmation required in non-interactive mode`**
Pass `--yes` in scripts. Without it, destructive operations require a terminal
confirmation.

**`verify` reports drift**
The live value no longer matches the last applied value (or the original, after
a restore). Re-apply or restore, then verify again.

## Safety and scope

Use this only on hardware you own or are authorized to administer. It does not
write firmware, load drivers, hook the kernel, or bypass anti-cheat, licensing,
or endpoint security. MAC changes can interrupt connectivity and identity
changes can affect activation and services.

## License

MIT.
