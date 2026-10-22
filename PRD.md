# HWID Spoofer CLI — Product Requirements Document

| Field | Value |
|---|---|
| Product | HWID Spoofer CLI |
| Version | 0.1.0 (MVP) |
| Language | Rust |
| Platforms | Windows 10/11 x86-64, Linux x86-64 |
| Interface | Command line |
| Status | Implemented; runtime verification is documented per feature in `TEST_REPORT.md` |
| Owner | Systems engineering |
| Date | 2026-10-22 |

## 1. Summary

HWID Spoofer is a lightweight command-line utility that inspects hardware
identifiers on a physical computer, reports which identifiers can actually be
changed on the running platform, generates valid replacement values with a
cryptographically secure random source, applies the supported changes, verifies
the result through an independent system query, and restores the original
values from a persisted backup.

The MVP deliberately changes only identifiers for which the operating system
exposes a documented, user-space interface:

- Physical network adapter MAC addresses.
- The OS machine identity (`/etc/machine-id` on Linux, `MachineGuid` on Windows).

Every other identifier in the required list (motherboard serial, SMBIOS system
UUID, BIOS serial, disk serial, CPU identity, GPU identity) is reported as
firmware-controlled and read-only. The tool does not pretend to spoof them.

## 2. Problem

Administrators, privacy researchers, and hardware test labs need to understand
how a machine presents itself to software, and sometimes need to change the
identifiers that the operating system legitimately exposes. Existing tools in
this space frequently fail one or more of these requirements:

- They report identifiers that are not actually present or fail silently.
- They claim success without reading the value back from the OS.
- They rely on kernel hooks, unsigned drivers, or firmware exploits.
- They have no safe restore path.
- They confuse a software-level adapter override with a hardware change.

This product addresses those gaps with a narrow, auditable feature set, explicit
capability reporting, and verification after every write.

## 3. Goals

1. Detect real hardware identifiers from the OS, never from hardcoded tables.
2. Determine, per identifier, whether modification is supported on this machine.
3. Generate replacement values that satisfy the platform's format rules, using
   the OS CSPRNG.
4. Apply supported changes with the required privileges.
5. Verify every change through an independent query path.
6. Persist original values before writing and support reliable restoration.
7. Handle unsupported hardware, missing permissions, and virtual adapters with
   clear errors and no false success.
8. Build cleanly on Windows 10/11 and Linux x86-64.

## 4. Non-goals

- Writing firmware, NVRAM, SMBIOS, disk controller data, VBIOS, or CPU
  microcode.
- Loading kernel drivers or hooking kernel functions.
- Bypassing anti-cheat, endpoint protection, licensing, or authentication.
- Spoofing identifiers of virtual machines as if they were physical hardware.
- Changing identifiers that require vendor manufacturing tools.
- Providing a GUI, service, or background agent in the MVP.
- Guaranteeing that a specific third-party application will accept a changed
  identifier. The tool reports and changes OS-visible values; downstream
  acceptance is out of scope.

## 5. Users and use cases

**System administrator.** Inventories hardware identity before and after a
motherboard replacement; confirms which identifiers are firmware-fixed.

**Privacy-conscious user.** Rotates a physical adapter's MAC address on a
network that permits it, and restores the original later.

**Hardware validation lab.** Re-runs onboarding and provisioning tests with a
new OS machine identity, then restores the original identity.

**Support engineer.** Diagnoses whether a reported "HWID change" is possible at
all on a given platform and prompts for the correct privilege level.

## 6. Supported platforms

| Platform | Version | Architecture | Status |
|---|---|---|---|
| Linux | Current kernels with sysfs, procfs, DMI, and standard networking | x86-64 | Primary development and runtime target |
| Windows | Windows 10 and Windows 11 | x86-64 | Implemented with Win32 APIs; compilation verified, runtime verification pending physical Windows hardware |

Building for any other OS/architecture is not supported by the MVP. The
codebase compiles conditionally for the two targets above.

## 7. Identifier support matrix

| Identifier | Inspection source (Linux) | Inspection source (Windows) | Modifiable | Mechanism / reason |
|---|---|---|---|---|
| Motherboard serial | `/sys/class/dmi/id/board_serial` (SMBIOS Type 2) | SMBIOS Type 2 via `GetSystemFirmwareTable('RSMB')` | No | Firmware data; no supported OS write interface. Vendor firmware procedure only. |
| SMBIOS system UUID | `/sys/class/dmi/id/product_uuid` (SMBIOS Type 1) | SMBIOS Type 1 | No | Firmware data; writing is vendor-specific and outside scope. |
| BIOS serial | SMBIOS Type 0 fields (`bios_vendor`, `bios_version`, `bios_date`) | SMBIOS Type 0 | No | SMBIOS Type 0 defines no serial-number field. Vendor/version/date are exposed and read-only. |
| HDD/SSD serial | `/sys/block/*/device/serial`, SCSI VPD page 80, or `wwid` | `IOCTL_STORAGE_QUERY_PROPERTY` (`STORAGE_DEVICE_DESCRIPTOR`) | No | Controller/firmware data; no supported OS write interface. |
| CPU identification | `/proc/cpuinfo` | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` | No | Fixed silicon/CPUID and firmware data. |
| GPU identification | `/sys/class/drm/card*/device` PCI IDs and driver | Display class registry (`DriverDesc`, `MatchingDeviceId`) | No | PCI/VBIOS identity is firmware-controlled. |
| Network MAC address | `/sys/class/net/*/address`, `permaddr`, link flags | `GetAdaptersAddresses` | Yes, physical Ethernet/Wi-Fi only | Linux: `ioctl(SIOCSIFHWADDR)` on an `AF_INET` control socket. Windows: vendor-supported `NetworkAddress` registry value plus adapter restart. |
| OS machine identity | `/etc/machine-id` (+ `/var/lib/dbus/machine-id`) | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | Yes | Linux: atomic file replacement. Windows: `REG_SZ` rewrite. Both require elevation. |

### 7.1 Accuracy rules

- A value is either `known` with the exact string read from the OS, or
  `unavailable` with a reason (not exposed, permission denied, read error).
- A read-only identifier is never reported as successfully spoofed.
- Virtual interfaces are detected and excluded from MAC spoofing unless the
  operator explicitly overrides that safety check for controlled testing.
- The tool does not derive a synthetic hardware serial and present it as a
  current value.

## 8. Functional requirements

### F1 — Hardware scanner

Command: `hwid-spoofer scan [--json]`

Requirements:

1. Report OS, architecture, current user, hostname, and whether the process is
   elevated.
2. Report the current value or explicit unavailability reason for every
   identifier in section 7.
3. Report modification support for each identifier with required privileges.
4. List network adapters with MAC, kind, state, virtual/physical classification,
   and whether spoofing is supported.
5. JSON output must be valid, stable, and machine-readable.
6. A failure to read one source must not crash the scan; it becomes an
   `unavailable` value with the underlying reason.

### F2 — Identifier generation

Command: `hwid-spoofer generate --type <mac|uuid|machine-id|serial|all> [--count N] [--json]`

Requirements:

1. Use the OS CSPRNG (`getrandom`), not a userspace PRNG seeded from time.
2. MAC: unicast, locally administered (first octet `x2`, `x6`, `xA`, or `xE`),
   not all-zero, not broadcast.
3. UUID: RFC 4122 version 4, lowercase, correct variant bits.
4. Machine ID: exactly 32 lowercase hexadecimal characters.
5. Serial: 12 uppercase alphanumeric characters, plausible as an OEM serial
   candidate. This is informational only because firmware serials are
   read-only; the command never implies the value was applied.
6. `--count` applies per selected type, range 1-1000.

### F3 — Physical network adapter spoofing

Commands: `hwid-spoofer interfaces`, `hwid-spoofer spoof mac --interface <name>`

Requirements:

1. Support Linux physical Ethernet and Wi-Fi adapters using
   `ioctl(SIOCSIFHWADDR)`. If the driver returns `EBUSY`, bring the link down,
   set the address, and restore the original link flags.
2. Support Windows adapters using the documented per-adapter `NetworkAddress`
   registry value under the network class key, then restart the adapter with
   `Restart-NetAdapter` (fallback: `netsh` disable/enable).
3. Require root (Linux) or Administrator (Windows) before any write.
4. Reject non-existent interfaces with a list of available interfaces.
5. Reject virtual interfaces, and reject adapters that are not Ethernet/Wi-Fi.
6. Reject multicast, broadcast, and all-zero MAC addresses.
7. Refuse an address already assigned to another interface.
8. Persist the original MAC before writing.
9. Verify the change with a fresh adapter enumeration/sysfs read. On mismatch,
   attempt rollback and return an error. Never print success without
   verification.
10. Record the applied value in the backup so `restore` and `verify` reflect the
    current state.
11. On Windows, preserve a pre-existing `NetworkAddress` value and restore it
    exactly; if none existed, remove the value on restore.
12. On Linux, document that the change is runtime-only and does not survive
    reboot.

### F4 — System identity management

Commands: `hwid-spoofer identity inspect`, `hwid-spoofer identity regenerate`

Requirements:

1. Inspect the current machine identity, its source, its format, and whether it
   is writable at the current privilege level.
2. Refuse regeneration without elevation.
3. Print explicit consequences: activation/licensing, service registration,
   backup/monitoring association, DHCP/VPN/domain identity, reboot requirement.
4. Require explicit confirmation (`--yes` or an interactive `yes`).
5. Persist the original identity before writing.
6. Generate a new value in the platform format (32 hex for Linux, UUID for
   Windows).
7. Verify by re-reading the identity. On mismatch, attempt rollback and return
   an error.
8. Linux writes `/etc/machine-id` atomically with mode `0444` and updates
   `/var/lib/dbus/machine-id` only when it is a regular file (not a symlink).
9. Windows rewrites `MachineGuid` as `REG_SZ` and recommends a restart.

### F5 — Backup and restore

Commands: `hwid-spoofer backup create`, `hwid-spoofer backup list`,
`hwid-spoofer restore [--yes]`

Requirements:

1. Save original values before modification; never overwrite an existing
   recorded original with a later snapshot.
2. Include the OS family in the backup and refuse to restore a backup created
   on a different OS family.
3. Store the file owner-only (`0600`) in an owner-only directory (`0700`) on
   Unix.
4. Write atomically (temporary file + rename).
5. Restore each entry, then verify independently. Report per-entry status:
   restored, already original, or failed.
6. Clear the "applied" marker after a successful restore so `verify` expects the
   original value again.
7. Return a non-zero exit status if any restore fails.
8. Require confirmation unless `--yes` is supplied.

Default backup locations:

- Linux root: `/var/lib/hwid-spoofer/backup.json`
- Linux non-root: `$XDG_STATE_HOME/hwid-spoofer/backup.json` or
  `~/.local/state/hwid-spoofer/backup.json`
- Windows: `%ProgramData%\hwid-spoofer\backup.json`
- Override: `HWID_SPOOFER_STATE_DIR`

The override is documented, used by tests, and does not contain secrets.

### F6 — Capability report

Command: `hwid-spoofer capabilities [--json]`

For each identifier, report:

- Current value or unavailability reason.
- Whether it is firmware-controlled.
- Whether modification is supported by this tool on this platform.
- The mechanism used when supported.
- Required privileges.
- Whether a restart/reboot is required or recommended.
- Reasons for lack of support and operational notes.

## 9. CLI specification

### 9.1 Global options

- `--json`: emit pretty-printed JSON on stdout. Warnings and errors go to
  stderr, so stdout remains valid JSON.
- `--help`, `--version`.

### 9.2 Commands

```
hwid-spoofer scan [--json]
hwid-spoofer capabilities [--json]
hwid-spoofer interfaces [--json]
hwid-spoofer generate --type <mac|uuid|machine-id|serial|all> [--count N] [--json]
hwid-spoofer spoof mac --interface <name> [--mac <addr>] [--allow-virtual] [--yes] [--json]
hwid-spoofer identity inspect [--json]
hwid-spoofer identity regenerate [--yes] [--json]
hwid-spoofer backup create [--json]
hwid-spoofer backup list [--json]
hwid-spoofer restore [--yes] [--json]
hwid-spoofer verify [--json]
```

### 9.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | Operation completed and verified |
| 1 | Operational failure (unsupported hardware, permission denied, verification failure, drift, failed restore) |
| 2 | CLI usage error (clap) |

### 9.4 Output requirements

- Human output is advisory; JSON output is the stable automation contract.
- Every MAC and identity write is followed by an independent read.
- Errors state what failed and what rollback action was attempted.
- Unknown interfaces are listed with valid choices.
- A non-elevated process never attempts a privileged write.

### 9.5 JSON shapes (summary)

- `scan`: `{ system, identifiers[], capabilities[], hardware{...} }`
- `capabilities`: `{ system, capabilities[] }`
- `interfaces`: array of `{ name, description, mac, permanent_mac, virtual_device, up, kind, guid }`
- `generate`: `{ values: [{ type, value }] }`
- `spoof mac`: `{ interface, guid, original, applied, verified, actions[], backup_path }`
- `identity inspect`: `{ value, source, format, writable, elevated }`
- `identity regenerate`: `{ source, previous, applied, verified }`
- `backup create`: `{ path, added, warnings[], backup{...} }`
- `restore`: `{ path, results[{ kind, target, status, message, actions[] }] }`
- `verify`: `{ path, items[{ kind, target, expected, actual, status, expected_is_applied }] }`

Values use `{ "state": "known", "value": "..." }` or
`{ "state": "unavailable", "reason": "..." }`.

## 10. Safety, legal, and ethical requirements

1. The tool must be used only on systems the operator owns or is authorized to
   administer.
2. No kernel hooks, no unsigned drivers, no firmware exploits, no anti-cheat or
   EDR bypass.
3. Changing a MAC address can interrupt connectivity; changing the machine
   identity can affect licensing and services. Both require explicit
   confirmation and a backup.
4. The tool never reports unsupported identifiers as changed.
5. The tool never hides a failed operation; failures are surfaced with the
   underlying OS error where available.
6. Backups contain identifiers, not credentials; they are still protected with
   owner-only permissions.

## 11. Architecture

```
src/
├── main.rs              CLI dispatch and human/JSON rendering
├── lib.rs               library exports for integration tests
├── cli.rs               clap command model
├── random.rs            CSPRNG wrapper (getrandom)
├── hardware/
│   ├── mod.rs           value/capability model, aggregation, report types
│   ├── smbios.rs        pure SMBIOS table parser (Windows data, Linux tests)
│   ├── motherboard.rs   DMI/SMBIOS Type 2
│   ├── bios.rs          SMBIOS Type 0
│   ├── cpu.rs           /proc/cpuinfo, Windows registry
│   ├── gpu.rs           DRM sysfs, display driver registry class
│   ├── disk.rs          sysfs serial/VPD 80/wwid, storage IOCTL
│   └── network.rs       MAC type/validation, adapter enumeration
├── platform/
│   ├── mod.rs           Platform trait, context, machine identity types
│   ├── linux.rs         sysfs/DMI/procfs reads, SIOCSIFHWADDR, machine-id
│   └── windows.rs       Win32 reads, registry, adapter restart, MachineGuid
├── spoof/
│   ├── mod.rs           privilege gate, serial generation
│   ├── mac.rs           safe MAC change orchestration + verification
│   └── identity.rs      identity generation, change, verification
├── backup.rs            backup schema, persistence, restore execution
└── verify.rs            independent comparison against backup expectations
```

### 11.1 Platform abstraction

A single `Platform` trait exposes:

- System context and elevated state.
- Board/BIOS/system/CPU/GPU/disk/adapter detection.
- Current machine identity.
- MAC apply, MAC restore, and existing driver override lookup.
- Machine identity apply.
- Capability metadata: mechanism, privilege, persistence, restart requirement.

All write operations live behind this trait. Detection modules are shared by
both backends where the API permits (for example, the SMBIOS parser).

### 11.2 Change pipeline

1. Validate request and privilege.
2. Enumerate targets and reject unsupported ones.
3. Snapshot and persist the original value.
4. Apply through the platform interface.
5. Re-enumerate from the OS.
6. Compare observed with requested.
7. Mark the backup as applied.
8. On failure, attempt rollback and return a non-zero exit.

## 12. Backup data model

```json
{
  "schema": 1,
  "created_at": "2026-10-22T20:37:10Z",
  "updated_at": "2026-10-22T20:37:10Z",
  "platform": "linux",
  "entries": [
    {
      "kind": "mac",
      "interface": "wlp2s0",
      "guid": null,
      "original": "1c:79:2d:82:a5:0d",
      "applied": null,
      "prior_override": null,
      "updated_at": "2026-10-22T20:37:10Z"
    },
    {
      "kind": "machine_identity",
      "target": "/etc/machine-id",
      "original": "1f07a41354de4e93a86a315bf5697111",
      "applied": null,
      "updated_at": "2026-10-22T20:37:10Z"
    }
  ]
}
```

Rules:

- `original` is immutable once recorded.
- `applied` is the last value this tool wrote, cleared after a verified restore.
- `prior_override` preserves a Windows driver override that predated this tool.
- Schema mismatch is rejected with an error rather than guessed.

## 13. Error handling and permissions

| Condition | Behavior |
|---|---|
| Missing root/Administrator | Fail before any write with an actionable hint |
| Unknown interface | Fail and list valid interfaces |
| Virtual/non-Ethernet adapter | Explicit refusal |
| Invalid or multicast MAC | Fail validation before backup or write |
| Duplicate MAC on another adapter | Refuse |
| Driver rejects address change | Surface the OS error; restore link state/override |
| Verification mismatch | Attempt rollback; return non-zero |
| Missing/unreadable DMI file | Report `unavailable` with reason; scan continues |
| Unsupported firmware identifier | Report unsupported; never write |
| No backup for restore/verify | Fail with a clear instruction |
| Backup from another OS family | Refuse to restore |
| Corrupt/unknown backup schema | Refuse to load |
| Non-interactive destructive command without `--yes` | Fail with confirmation hint |

## 14. Testing and acceptance criteria

### 14.1 Automated

- Unit tests for MAC parsing/validation/generation, SMBIOS parsing, CPU/disk/DMI
  parsers, machine-id writing/validation, backup round-trips and schema checks,
  restore bookkeeping, and verification comparison.
- Integration tests that run the compiled binary on the host, validate JSON
  shapes, verify capability truthfulness, exercise backup/restore/verify, and
  assert honest refusal without privileges.
- An ignored root-only test that creates a dummy interface, changes its MAC via
  the real kernel ioctl, restores it, and verifies the result.
- Windows cross-compilation with `cargo check`/`cargo clippy` for
  `x86_64-pc-windows-msvc`.

### 14.2 MVP acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | Compiles on Windows and Linux | Met: Linux build/tests; Windows `cargo check --target x86_64-pc-windows-msvc --all-targets` and clippy pass. |
| 2 | Runs on physical PCs | Met on Linux physical hardware. Windows runtime pending physical Windows execution. |
| 3 | Detects actual hardware identifiers | Met on Linux (disk, CPU, GPU, MAC, machine-id, BIOS; DMI serials require root). |
| 4 | Correctly identifies modification capabilities | Met: only MAC and machine identity are supported. |
| 5 | Changes MAC addresses on tested compatible adapters | Mechanism implemented; privileged execution not possible in this environment. Root-only harness included. |
| 6 | Verifies changes independently | Implemented and exercised for restore/verify paths; MAC write verification runs inside the same pipeline. |
| 7 | Supports backups and restoration | Met and tested on Linux. |
| 8 | Handles unsupported hardware without crashing | Met: explicit `unavailable`/unsupported reporting and tested refusal paths. |
| 9 | Includes automated tests | Met: 44 executed tests plus one privileged ignored test. |
| 10 | Includes installation and usage documentation | Met: `INSTALL.md`, `README.md`, this PRD, and `TEST_REPORT.md`. |

## 15. Risks and limitations

1. **Firmware identifiers are not writable.** This is intentional and the main
   difference from tools that make unrealistic claims.
2. **Adapter/driver variance.** Some drivers ignore or partially honor
   `NetworkAddress`; some WiFi drivers refuse MAC changes while associated.
   Errors are surfaced, and rollback is attempted.
3. **Network disruption.** Changing a live adapter's MAC can drop connectivity.
4. **Identity side effects.** Changing the machine identity can affect
   activation, clustering, backup agents, and domain trust.
5. **Linux MAC changes are not persistent.** Reapply after reboot or use an
   operator-managed unit.
6. **Windows escaped from the lab.** The Windows backend is compile-verified
   but was not executed on physical Windows hardware in this environment.
7. **Root-only reads.** DMI serials are root-only on common Linux
   configurations; non-root scans report this explicitly.
8. **Bypassing security controls is out of scope.** The tool does not defeat
   anti-cheat, licensing, or endpoint agents.

## 16. Future work (post-MVP)

- Persistent Linux MAC configuration helper (network manager integration).
- Additional vendor-specific MAC mechanisms only where documented.
- Richer GPU names via a PCI ID database.
- Structured restore transaction log and crash-recovery journal.
- PowerShell-free Windows adapter restart via SetupAPI device property change.
- Signed Windows release artifacts and MSI packaging.
- Optional integrity hashing of the backup file.
