//! HWID Spoofer library: hardware inspection and supported identifier changes.
//!
//! The binary in `main.rs` is a thin CLI over these modules so integration
//! tests can exercise the same types the CLI uses.

pub mod backup;
pub mod cli;
pub mod hardware;
pub mod platform;
mod random;
pub mod spoof;
pub mod verify;
