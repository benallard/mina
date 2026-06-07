/// Mina — passive SSH session auditor
///
/// Module layout mirrors the architecture documented in AGENTS.md.
/// Each module has a single responsibility; see AGENTS.md for the
/// boundary rules.

pub mod bundle;
pub mod command_log;
pub mod config;
pub mod file_capture;
pub mod pam_hook;
pub mod transport;
