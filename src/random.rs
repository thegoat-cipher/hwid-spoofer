//! CSPRNG access. `getrandom` errors are mapped to `anyhow` here because the
//! crate's error type is not part of its public std error surface on all
//! targets.

use anyhow::Result;

pub fn fill(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes).map_err(|error| anyhow::anyhow!("OS CSPRNG unavailable: {error}"))
}
