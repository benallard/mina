use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/mina.toml";

/// Top-level Mina configuration, loaded from /etc/mina.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub nest: NestConfig,
    pub capture: CaptureConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestConfig {
    /// "ssh" or "https"
    pub transport: TransportKind,

    /// e.g. "mina@nest.example.com:/var/mina"  (SSH transport)
    pub ssh_destination: Option<String>,

    /// e.g. "https://nest.example.com/ingest"  (HTTPS transport)
    pub https_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Ssh,
    Https,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Skip files larger than this (kilobytes). Default: 512.
    #[serde(default = "default_size_limit")]
    pub text_size_limit_kb: u64,

    /// Path prefixes to never capture.
    #[serde(default = "default_skip_paths")]
    pub skip_paths: Vec<PathBuf>,
}

fn default_size_limit() -> u64 {
    512
}

fn default_skip_paths() -> Vec<PathBuf> {
    ["/proc", "/sys", "/dev", "/tmp", "/run"]
        .iter()
        .map(PathBuf::from)
        .collect()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&text)?;
        Ok(config)
    }
}

// ── Example config rendered as a &str (used by `mina install`) ──────────────

pub const EXAMPLE_CONFIG: &str = r#"
[nest]
transport = "ssh"                         # "ssh" or "https"
ssh_destination = "mina@nest.example.com:/var/mina"
# https_endpoint = "https://nest.example.com/ingest"

[capture]
text_size_limit_kb = 512
skip_paths = ["/proc", "/sys", "/dev", "/tmp", "/run"]
"#;

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_example_config() {
        let config: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config.nest.transport, TransportKind::Ssh);
        assert_eq!(config.capture.text_size_limit_kb, 512);
    }

    #[test]
    fn default_skip_paths_are_set_when_absent() {
        let minimal = r#"
            [nest]
            transport = "ssh"
            ssh_destination = "mina@host:/var/mina"
            [capture]
        "#;
        let config: Config = toml::from_str(minimal).unwrap();
        assert!(config.capture.skip_paths.contains(&PathBuf::from("/proc")));
    }
}
