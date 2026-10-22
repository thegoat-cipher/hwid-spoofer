# Test and Verification Report

Product: HWID Spoofer CLI 0.1.0
Report date: 2026-10-22
Report scope: implementation verification on the available physical Linux host,
Windows cross-compilation, automated tests, and live CLI smoke tests.

## 1. Environment

| Item | Value |
|---|---|
| Host | Physical laptop, `systemd-detect-virt` reports `none` |
| OS | Ubuntu 25.10 (kernel 6.17.0-41-generic) |
| Architecture | x86-64 |
| CPU | AMD Ryzen 7 6800H with Radeon Graphics |
| Disk | NVMe, serial `SZSM32010700009407` |
| Wi-Fi adapter | `wlp2s0`, MAC `1c:79:2d:82:a5:0d`, driver `rtw89_8852be` |
| Rust | rustc 1.99.1, cargo 1.99.1 |
| Privileges during testing | Standard user; no passwordless sudo; unprivileged user namespaces blocked (`/proc/self/uid_map: Operation not permitted`) |
| Windows target | `x86_64-pc-windows-msvc` cross-check (compile + clippy only) |

The lack of root is the reason privileged write operations could not be executed
on this host. It is not reported as a pass.

## 2. Automated verification

### 2.1 Commands and results

```text
$ cargo fmt --check
(no output)                                         PASS

$ cargo test
lib unit tests:          33 passed, 0 failed
binary unit tests:        0 passed
CLI integration tests:   11 passed, 0 failed
privileged suite:         0 passed, 1 ignored (requires root)
doctests:                 0

$ cargo clippy --all-targets -- -D warnings
Finished                                            PASS (no warnings)

$ cargo clippy --target x86_64-pc-windows-msvc --all-targets -- -D warnings
Finished                                            PASS (no warnings)

$ cargo build --release
Finished release profile
Binary: target/release/hwid-spoofer (ELF x86-64, stripped)
```

Windows compilation was verified for the library, binary, integration tests, and
test harness:

```text
$ cargo check --target x86_64-pc-windows-msvc --all-targets
Finished                                            PASS
```

### 2.2 What the 44 executed tests cover

- MAC parsing (colon, dash, plain, Cisco dotted), normalization, rejection of
  invalid, multicast, broadcast, and all-zero addresses.
- 256 generated MACs: CSPRNG uniqueness, unicast bit, locally administered bit.
- SMBIOS parser: BIOS/system/board/CPU fields, SMBIOS little-endian UUID,
  all-0xFF UUID suppression, truncated-table safety. Synthetic firmware tables.
- CPU `/proc/cpuinfo` parser: family/model/stepping/microcode, logical CPU count,
  missing-field tolerance.
- Disk sysfs parser: NVMe serial/model/size/rotational, SCSI VPD page 80
  fallback, explicit missing-serial reason, virtual block-device filtering.
- DMI reader: trimming, empty values, missing files (via temporary fixtures).
- GPU DRM card-name filtering and PCI vendor mapping.
- Linux network sysfs classification: physical Wi-Fi, virtual veth, loopback,
  administrative link flags.
- Machine-id: 32-hex validation, atomic write, `0444` mode, restore path,
  malformed values, oversized interface names.
- Backup: JSON round-trip, immutable originals, schema rejection, platform
  guard, applied-marker clearing after restore, Unix `0600` mode.
- Verification: MAC comparison across formatting variants.
- MAC orchestration: interface lookup by name and GUID, unknown-interface error
  listing valid choices.
- CLI integration: real `scan`, `capabilities`, `interfaces`, `generate` for all
  types, `backup create/list`, `restore`, `verify`, JSON validity, permission
  refusal, malformed input, missing-interface handling, `--version`, `--help`.
- Root-only ignored test: dummy interface MAC round trip through the real
  kernel ioctl, sysfs verification, restore, and post-restore `verify`.

## 3. Live smoke tests on this Linux host

### 3.1 Hardware scan (non-root)

```text
Platform: Ubuntu 25.10
Architecture: x86_64
Privileges: standard user (elevated privileges are required for modifications)
Host: cifera / vib

Motherboard Serial:         unavailable (permission denied reading
                            /sys/class/dmi/id/board_serial; DMI identity files
                            are root-only, run as root)
BIOS (Vendor/Version/Date): American Megatrends International, LLC.
                            CT_BI_AMI_RX16_ARN79C_A-002 (02/08/2025)
BIOS Serial:                unavailable (SMBIOS Type 0 defines no serial field)
System UUID:                unavailable (permission denied; root-only)
Disk Serial:                nvme0n1: SZSM32010700009407
CPU Identifier:             AMD Ryzen 7 6800H with Radeon Graphics
                            [family 25, model 68, stepping 1]
GPU Identifier:             AMD [0x1002:0x1681] (card1)
MAC Address:                wlp2s0: 1c:79:2d:82:a5:0d
Machine Identity:           1f07a41354de4e93a86a315bf5697111
```

Result: PASS for values the current privilege can read. DMI serials and the
system UUID correctly report the root-only permission boundary instead of a
fabricated value. CPU, disk, GPU, MAC, BIOS version, and machine identity are
real host values.

### 3.2 Capability report

```text
Motherboard Serial:  Unsupported (SMBIOS firmware, no OS write interface)
BIOS Serial:         Unsupported (no SMBIOS Type 0 serial field)
System UUID:         Unsupported (firmware, vendor-specific)
Disk Serial:         Unsupported (ATA/NVMe identify data)
CPU Identifier:      Unsupported (silicon/CPUID)
GPU Identifier:      Unsupported (PCI/VBIOS)
MAC Address:         Supported (requires root)
Machine Identity:    Supported (requires root, restart recommended)
```

Result: PASS. Only the two implemented mechanisms are advertised as supported.

### 3.3 Network interface listing

```text
NAME      KIND   UP  MAC                SPOOFABLE     DESCRIPTION
lo        other  up  00:00:00:00:00:00  no (virtual)  virtual interface
wlp2s0    wifi   up  1c:79:2d:82:a5:0d  yes           rtw89_8852be
```

Result: PASS. Physical adapter identified as spoofable; loopback classified as
virtual and excluded.

### 3.4 Identifier generation

```text
mac          2a:aa:bb:13:40:86
uuid         f72e5828-b10e-4461-852a-42b702f4dcc2
machine-id   3ef9d4d08e4b16a83b9b9b5e8ece72cd
serial       8ABSX3987W6T
```

Result: PASS. MAC is locally administered and unicast; UUID is version 4 with
the RFC 4122 variant; machine-id is 32 hex; serial is 12 alphanumeric.

### 3.5 Identity inspection

```text
Value:     1f07a41354de4e93a86a315bf5697111
Source:    /etc/machine-id
Format:    32 hex characters
Writable:  no (run elevated to change it)
```

Result: PASS (read-only mode).

### 3.6 Backup, verify, restore

```text
$ HWID_SPOOFER_STATE_DIR=/tmp/... hwid-spoofer backup create
Backup: /tmp/.../backup.json
2 new entries recorded.
  mac               wlp2s0           original 1c:79:2d:82:a5:0d  applied -
  machine_identity  /etc/machine-id  original 1f07a413...1111     applied -

$ ... verify
mac              wlp2s0           match      1c:79:2d:82:a5:0d  1c:79:2d:82:a5:0d
machine_identity /etc/machine-id  match      1f07a413...1111    1f07a413...1111

$ ... restore --yes
mac              wlp2s0           already original: 1c:79:2d:82:a5:0d already active
machine_identity /etc/machine-id  already original: original identity already active

$ ... verify --json   (after restore)
[('mac', 'matches'), ('machine_identity', 'matches')]
```

Backup file mode: `-rw-------` (`0600`), directory created with `0700`.
JSON outputs for `scan`, `capabilities`, `interfaces`, `generate`, `backup`,
`restore`, and `verify` parsed successfully with Python's JSON parser.

Result: PASS.

### 3.7 Privilege enforcement and failure honesty

```text
$ hwid-spoofer spoof mac --interface wlp2s0 --yes
error: root privileges are required for this operation; re-run with sudo
exit=1

$ hwid-spoofer spoof mac --interface lo --yes
error: root privileges are required for this operation; re-run with sudo
exit=1

$ hwid-spoofer identity regenerate --yes
error: root privileges are required for this operation; re-run with sudo
exit=1
```

No backup file was created before the privilege failure, no write was attempted,
and no success or verification message was printed.

Malformed MAC input:

```text
$ hwid-spoofer spoof mac --interface lo --mac zz:11:22:33:44:55 --yes
error: invalid --mac value: invalid MAC address 'zz:11:22:33:44:55' ...
exit=1
```

Result: PASS.

## 4. Feature verification matrix

| Feature | Linux runtime | Windows runtime |
|---|---|---|
| Compiles | PASS (build, tests, release) | PASS (`cargo check`, clippy, all targets) |
| Detects disk/CPU/GPU/MAC/BIOS/machine-id | PASS | NOT EXECUTED |
| Detects motherboard serial / system UUID | BLOCKED (root-only files, no root on test host) | NOT EXECUTED |
| Interface classification | PASS | NOT EXECUTED |
| MAC spoof on physical adapter | NOT EXECUTED (root unavailable) | NOT EXECUTED |
| MAC verification/rollback | Implemented; exercised structurally by tests; privileged path NOT EXECUTED | NOT EXECUTED |
| Machine identity inspect | PASS | NOT EXECUTED |
| Machine identity regenerate | NOT EXECUTED (root unavailable); file logic unit-tested | NOT EXECUTED |
| Backup create/list | PASS | NOT EXECUTED |
| Restore + independent verification | PASS (no-op restore and bookkeeping path) | NOT EXECUTED |
| `verify` drift detection | PASS (matching path); drift path covered by comparison unit test | NOT EXECUTED |
| JSON output | PASS | Code shared; binary NOT EXECUTED on Windows |
| Privilege refusal | PASS | Tests exist; NOT EXECUTED on Windows |

## 5. Not verified, and why

1. **Physical MAC change on Linux.** The test account has no passwordless sudo,
   `sudo -n` requires interactive authentication, and unprivileged user
   namespaces are disabled, so no interface with `CAP_NET_ADMIN` could be
   created. Every other part of the pipeline (validation, backup persistence,
   independent verification, restore, error handling) is covered by tests.
2. **Machine identity change on Linux.** Writing `/etc/machine-id` requires
   root, which was unavailable. The atomic write, permission, validation, and
   restore logic were executed against temporary files.
3. **Windows runtime.** No physical Windows machine or Windows VM was available.
   The Win32 backend compiles cleanly for `x86_64-pc-windows-msvc`, including
   integration tests, but behavior on real adapters and the registry has not
   been observed.
4. **Vendor-specific adapter quirks.** Whether a specific NIC driver honors
   `NetworkAddress` or permits `SIOCSIFHWADDR` depends on the driver/firmware.
   The code reports these failures explicitly and attempts rollback.

## 6. Reproducing the privileged tests

On a Linux host where you can use root:

```bash
cargo build --release
sudo -E cargo test --test privileged -- --ignored --nocapture
```

This creates a kernel dummy Ethernet interface named `hwidspoof0`, changes its
MAC through `ioctl(SIOCSIFHWADDR)`, reads the address back from sysfs, runs
`restore`, confirms the original address and a matching `verify`, then removes
the interface. It does not touch the active physical network.

Manual physical-adapter test, with the understanding that it will interrupt
connectivity:

```bash
sudo hwid-spoofer scan
sudo hwid-spoofer interfaces
sudo hwid-spoofer backup create
sudo hwid-spoofer spoof mac --interface <physical-interface> --yes
ip link show <physical-interface>          # independent confirmation
sudo hwid-spoofer verify
sudo hwid-spoofer restore --yes
ip link show <physical-interface>
```

Windows (elevated PowerShell):

```powershell
.\hwid-spoofer.exe scan
.\hwid-spoofer.exe interfaces
.\hwid-spoofer.exe backup create
.\hwid-spoofer.exe spoof mac --interface "<adapter friendly name>" --yes
Get-NetAdapter -Name "<adapter friendly name>" | Format-List Name,MacAddress
.\hwid-spoofer.exe verify
.\hwid-spoofer.exe restore --yes
```

## 7. Release artifact

```text
target/release/hwid-spoofer
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
1,370,520 bytes
SHA-256: fea4166aabb09a4d25c2cb16232a4e5bfeef9dabc2fedd751570044c8f061cd6
```

## 8. Conclusion

The implementation is complete for the two mechanisms the operating systems
actually support, and every unsupported firmware identifier is reported as
read-only. On this physical Linux machine, inspection, capability truthfulness,
generation, backup, verification, restore, JSON output, and privilege refusal
were exercised successfully.

The MVP is **not declared fully finished** against the original acceptance
criteria because two required proof points could not be executed here: a real
privileged MAC change and any runtime execution on Windows. The dedicated
root-only harness and the manual procedures above exist to close those gaps on
appropriate hardware.
