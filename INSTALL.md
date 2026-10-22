# Installation Guide

This guide installs `hwid-spoofer` 0.1.0 from source on a physical Linux or
Windows machine. There are no published installer packages or signed release
binaries; building from the repository is the supported path.

For what the tool can and cannot change, read [`README.md`](README.md) first.
For test evidence and known runtime gaps, read [`TEST_REPORT.md`](TEST_REPORT.md).

## 1. Before you start

| Requirement | Details |
|---|---|
| Hardware | Physical PC. Virtual machines expose virtual firmware and are not a supported target. |
| OS | Linux x86-64 or Windows 10/11 x86-64. |
| Rust | 1.85 or newer, installed with `rustup`. |
| Linux build tools | A C linker (`cc`/`gcc`) and `make`. No runtime libraries beyond glibc. |
| Windows build tools | Visual Studio 2022 Build Tools with the C++ workload and Windows SDK. |
| Privileges | Root on Linux, Administrator on Windows, for any write operation. |
| Disk | About 500 MB for the build tree; the release binary is roughly 1.4 MB. |

Installation itself does not change any identifier. The first write happens only
when you explicitly run `spoof` or `identity regenerate`.

## 2. Linux installation

### 2.1 Install build prerequisites

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential curl git
```

Fedora:

```bash
sudo dnf install -y gcc make curl git
```

Arch Linux:

```bash
sudo pacman -S --needed base-devel curl git
```

openSUSE:

```bash
sudo zypper install -y gcc make curl git
```

### 2.2 Install Rust

Use `rustup`; distribution Rust packages are often older than 1.85.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
rustc --version
cargo --version
```

The reported Rust version must be 1.85 or newer.

### 2.3 Build and test

```bash
git clone https://github.com/thegoat-cipher/hwid-spoofer.git
cd hwid-spoofer
cargo build --release --locked
cargo test --locked
```

`--locked` uses the committed `Cargo.lock`. The release profile enables thin
LTO and strips symbols.

### 2.4 Install the binary

```bash
sudo install -m 755 target/release/hwid-spoofer /usr/local/bin/hwid-spoofer
```

Verify:

```bash
hwid-spoofer --version
hwid-spoofer scan
```

A non-root scan reports DMI serials and the system UUID as permission-denied.
That is expected: those sysfs files are root-only. Use `sudo hwid-spoofer scan`
for the complete inventory.

### 2.5 Optional: run the full test suite

```bash
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

A privileged end-to-end MAC test is included but ignored by default:

```bash
sudo -E cargo test --test privileged -- --ignored --nocapture
```

It creates a kernel dummy interface named `hwidspoof0`, changes its MAC through
the real ioctl, verifies through sysfs, restores it, and removes the interface.
It does not use the active network adapter.

## 3. Windows installation

### 3.1 Install the C++ build tools

1. Download Visual Studio 2022 Build Tools:
   <https://visualstudio.microsoft.com/visual-cpp-build-tools/>
2. In the installer, select **Desktop development with C++**.
3. Confirm these components are selected:
   - MSVC v143 x64/x86 build tools
   - Windows 10 or Windows 11 SDK
4. Complete the installation and reboot if prompted.

### 3.2 Install Rust

1. Download `rustup-init.exe` from <https://rustup.rs/>.
2. Run it and choose the default **stable-x86_64-pc-windows-msvc** toolchain.
3. Open a new PowerShell window and verify:

```powershell
rustc --version
cargo --version
```

The version must be 1.85 or newer.

If `link.exe` is not found during the build, open **x64 Native Tools Command
Prompt for VS 2022** (or the Developer PowerShell) and build there. That shell
has the Visual Studio linker on `PATH`.

### 3.3 Build and test

```powershell
git clone https://github.com/thegoat-cipher/hwid-spoofer.git
cd hwid-spoofer
cargo build --release --locked
cargo test --locked
```

The binary is `.\target\release\hwid-spoofer.exe`.

### 3.4 Install the binary

```powershell
$dir = "$env:LOCALAPPDATA\Programs\hwid-spoofer"
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item .\target\release\hwid-spoofer.exe $dir
```

Run it with the full path:

```powershell
& "$env:LOCALAPPDATA\Programs\hwid-spoofer\hwid-spoofer.exe" --version
```

Optional per-user `PATH` entry:

```powershell
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
[Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
```

Open a new terminal after changing `PATH`.

Windows marks locally built unsigned executables with SmartScreen warnings if
they are copied from another machine. If you downloaded a prebuilt binary,
choose **More info → Run anyway** only after verifying its source and hash.
Building from source avoids that trust question.

### 3.5 Run elevated

Inventory reads mostly work as a standard user. MAC and machine-identity writes
require an elevated process:

```powershell
Start-Process -FilePath "$env:LOCALAPPDATA\Programs\hwid-spoofer\hwid-spoofer.exe" -Verb RunAs -ArgumentList "scan"
```

That opens a new Administrator console. Use the same pattern with
`"interfaces"`, `"backup create"`, or `"spoof mac --interface <name> --yes"`.

## 4. First-run verification

These commands do not modify anything:

```bash
hwid-spoofer --version
hwid-spoofer scan
hwid-spoofer capabilities
hwid-spoofer interfaces
hwid-spoofer generate --type mac
```

On Linux, repeat the inventory with `sudo` to see root-only DMI values.

A capability report is correct when:

- Motherboard serial, BIOS serial, system UUID, disk serial, CPU, and GPU are
  reported as unsupported.
- MAC address and machine identity are reported as supported.
- The privilege required is `root` on Linux and `Administrator` on Windows.

Create and verify a backup before changing anything:

```bash
sudo hwid-spoofer backup create
sudo hwid-spoofer verify
sudo hwid-spoofer restore --yes     # no-op if nothing changed
```

On Windows, run those from the elevated console.

## 5. Permissions and state locations

| Item | Linux | Windows |
|---|---|---|
| Binary (suggested) | `/usr/local/bin/hwid-spoofer` | `%LOCALAPPDATA%\Programs\hwid-spoofer\hwid-spoofer.exe` |
| State directory (root/Administrator) | `/var/lib/hwid-spoofer` | `%ProgramData%\hwid-spoofer` |
| State directory (non-root) | `$XDG_STATE_HOME/hwid-spoofer` or `~/.local/state/hwid-spoofer` | `%ProgramData%\hwid-spoofer` |
| Backup file | `backup.json` in the state directory | `backup.json` in the state directory |
| Override | `HWID_SPOOFER_STATE_DIR=/some/dir` | same variable |

On Unix the state directory is `0700` and the backup file is `0600`.

Use the same elevation for `backup create`, `spoof`, `restore`, and `verify`.
A non-root backup lives in your home directory; a later `sudo` command uses
`/var/lib/hwid-spoofer` and will not see it. Pin one path with
`HWID_SPOOFER_STATE_DIR` if you need to switch between them.

Do not run the binary with `setcap` as a substitute for root. The tool checks
for effective UID 0, and machine-identity changes also require write access to
system files. Use `sudo` or an elevated Windows process.

## 6. Upgrading

1. Restore any active changes if you intend to remove the tool afterward.
2. Keep the existing state directory; backups are schema-versioned.
3. Fetch and rebuild:

```bash
cd hwid-spoofer
git pull --ff-only
cargo build --release --locked
sudo install -m 755 target/release/hwid-spoofer /usr/local/bin/hwid-spoofer
```

On Windows, rebuild and replace the `.exe` after closing any running instance.

Do not delete `backup.json` during an upgrade. It is the only record of the
values that `restore` expects.

## 7. Uninstalling

Restore first, while the binary and state directory still exist:

```bash
sudo hwid-spoofer restore --yes
```

Verify the restoration:

```bash
sudo hwid-spoofer verify
```

Then remove the binary and state:

```bash
sudo rm -f /usr/local/bin/hwid-spoofer
sudo rm -rf /var/lib/hwid-spoofer
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/hwid-spoofer"
```

Windows (elevated PowerShell):

```powershell
& "$env:LOCALAPPDATA\Programs\hwid-spoofer\hwid-spoofer.exe" restore --yes
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Programs\hwid-spoofer"
Remove-Item -Recurse -Force "$env:ProgramData\hwid-spoofer"
```

Remove the user `PATH` entry if you added one. A Linux MAC change is runtime-only
and disappears on reboot; a Windows change persists until `restore` removes the
`NetworkAddress` override.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `error: linker 'cc' not found` | Install `build-essential` (Debian/Ubuntu), `gcc make` (Fedora), or `base-devel` (Arch). |
| `rustc 1.x is not supported` | `rustup update stable`; the minimum is 1.85. |
| `link.exe not found` or `LNK1181` on Windows | Install VS Build Tools with the C++ workload and Windows SDK; build from Developer PowerShell / x64 Native Tools. |
| `Permission denied` reading `/sys/class/dmi/id/...` | Expected for non-root. Run `sudo hwid-spoofer scan`. |
| `root privileges are required` / `Administrator privileges are required` | Re-run under `sudo` or from an elevated Windows terminal. |
| MAC change fails with `EBUSY` | The driver requires the link down; the tool does this automatically when the kernel reports `EBUSY`. If the retry fails, the adapter/driver does not support the change. |
| MAC change fails on a virtual adapter | Virtual adapters are refused. `--allow-virtual` exists only for controlled testing. |
| Windows MAC did not change after restart | Not every driver honors `NetworkAddress`. The tool waits 20 seconds, then reports the mismatch instead of claiming success. |
| `Restart-NetAdapter` not recognized | Run in elevated Windows PowerShell with the NetAdapter module; the tool falls back to `netsh` automatically. |
| `confirmation required in non-interactive mode` | Add `--yes` in scripts. Destructive commands require a terminal confirmation otherwise. |
| `verify` reports drift | The live value no longer matches the applied value or restored original. Re-apply or restore, then verify again. |
| `backup was created on ... but this host is ...` | Backups are OS-family specific. Create a new backup on this OS. |
| Backup file not found under `sudo` | The earlier backup was made as a normal user in `~/.local/state`. Use the same elevation or pin `HWID_SPOOFER_STATE_DIR`. |
| `cargo test` skips the privileged test | Expected: it is `#[ignore]` and must be run with `sudo -E ... --ignored`. |
| SmartScreen blocks the `.exe` | The binary is unsigned. Build from source, or inspect the source and choose **More info → Run anyway**. |
| Tool behaves oddly inside a VM | Firmware identifiers reflect the VM. The tool does not simulate physical hardware. |

## 9. Runtime dependencies and network access

- Linux: glibc and the kernel interfaces used by the tool (sysfs, procfs, DMI,
  netlink/ioctl). No external daemon is required.
- Windows: system DLLs only (iphlpapi, advapi32, kernel32, and the PowerShell
  or `netsh` used for adapter restart). No redistributable runtime is required.
- At runtime the tool makes no network connections and collects no telemetry.
- Cargo fetches build dependencies from crates.io during the build. The
  `Cargo.lock` pins exact versions.

## 10. Verifying the build

After building, record the binary hash:

```bash
sha256sum target/release/hwid-spoofer
```

On Windows:

```powershell
Get-FileHash .\target\release\hwid-spoofer.exe -Algorithm SHA256
```

Compare it with the commit you built. The repository does not publish signed
release assets, so the source commit and your local build are the trust anchor.

## 11. Getting help

- Inventory and capability questions: `hwid-spoofer scan --json` and
  `hwid-spoofer capabilities --json` include the underlying reason for every
  unavailable value.
- Usage reference: [`README.md`](README.md)
- Requirement and design details: [`PRD.md`](PRD.md)
- Test coverage and unverified paths: [`TEST_REPORT.md`](TEST_REPORT.md)
- Bugs and feature requests: open an issue in the repository.
