use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/mina.toml";

/// Top-level Mina configuration, loaded from /etc/mina.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub nest: NestConfig,
    pub capture: CaptureConfig,

    /// Which PAM services open a session. Default: sshd and login.
    #[serde(default)]
    pub session: SessionConfig,

    /// Staging directory where bundles are assembled before being shipped.
    /// Default: /tmp/mina-staging
    #[serde(default = "default_staging_dir")]
    pub staging_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestConfig {
    /// "ssh", "https", or "local"
    pub transport: TransportKind,

    /// e.g. "mina@nest.example.com:/var/mina"  (SSH transport)
    pub ssh_destination: Option<String>,

    /// Path to the SSH private key used by rsync.  Default: /etc/mina/nest_key
    #[serde(default = "default_ssh_key_path")]
    pub ssh_key_path: String,

    /// e.g. "https://nest.example.com/ingest"  (HTTPS transport)
    pub https_endpoint: Option<String>,

    /// Local directory to copy bundles into, read-only.  (local transport)
    /// e.g. "/var/mina"
    pub local_destination: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Ssh,
    Https,
    Local,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConfig {
    /// `PAM_SERVICE` values for which `session-open` / `session-close` act.
    /// Every other service (cron, su, sudo, systemd --user, ...) is ignored.
    #[serde(default = "default_pam_services")]
    pub pam_services: Vec<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            pam_services: default_pam_services(),
        }
    }
}

impl SessionConfig {
    /// Read only the `[session]` table, so that `session-open` does not
    /// depend on the rest of the file being valid.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct SessionOnly {
            #[serde(default)]
            session: SessionConfig,
        }
        let only: SessionOnly = toml::from_str(text)?;
        Ok(only.session)
    }
}

fn default_pam_services() -> Vec<String> {
    vec!["sshd".to_owned(), "login".to_owned()]
}

fn default_size_limit() -> u64 {
    512
}

fn default_staging_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/tmp/mina-staging")
}

fn default_ssh_key_path() -> String {
    "/etc/mina/nest_key".to_owned()
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
transport = "ssh"                         # "ssh", "https", or "local"
ssh_destination = "mina@nest.example.com:/var/mina"
ssh_key_path = "/etc/mina/nest_key"
# https_endpoint = "https://nest.example.com/ingest"
# local_destination = "/var/mina"         # local transport: copy bundles here, read-only

[capture]
text_size_limit_kb = 512
skip_paths = ["/proc", "/sys", "/dev", "/tmp", "/run"]

[session]
pam_services = ["sshd", "login"]          # PAM services that open a session (SSH, console)

# staging_dir = "/tmp/mina-staging"       # where bundles are assembled before shipping
"#;

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let config: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config.nest.transport, TransportKind::Ssh);
        assert_eq!(config.capture.text_size_limit_kb, 512);
        assert_eq!(config.session.pam_services, ["sshd", "login"]);
    }

    #[test]
    fn example_file_parses() {
        let text = include_str!("../mina.toml.example");
        let config: Config = toml::from_str(text).unwrap();
        assert_eq!(config.session, SessionConfig::default());
    }

    #[test]
    fn session_defaults_when_section_missing() {
        let minimal = r#"
            [nest]
            transport = "ssh"
            [capture]
        "#;
        let config: Config = toml::from_str(minimal).unwrap();
        assert_eq!(config.session.pam_services, ["sshd", "login"]);
        assert_eq!(
            SessionConfig::parse(minimal).unwrap(),
            SessionConfig::default()
        );
    }

    #[test]
    fn session_defaults_when_key_missing() {
        let session = SessionConfig::parse("[session]").unwrap();
        assert_eq!(session.pam_services, ["sshd", "login"]);
    }

    #[test]
    fn session_pam_services_configurable() {
        let text = r#"
            [session]
            pam_services = ["sshd"]
        "#;
        let session = SessionConfig::parse(text).unwrap();
        assert_eq!(session.pam_services, ["sshd"]);
    }

    #[test]
    fn session_section_read_even_if_rest_is_incomplete() {
        // No [nest]: the full Config does not load, the session part does.
        let text = r#"
            [session]
            pam_services = ["login"]
        "#;
        assert!(toml::from_str::<Config>(text).is_err());
        assert_eq!(SessionConfig::parse(text).unwrap().pam_services, ["login"]);
    }

    #[test]
    fn session_broken_toml_is_an_error() {
        assert!(SessionConfig::parse("[session").is_err());
        assert!(SessionConfig::parse("[session]\npam_services = \"sshd\"").is_err());
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
