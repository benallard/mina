use anyhow::{bail, Context, Result};
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

    /// Reading commands from the audit log (sessions without a shell).
    #[serde(default)]
    pub audit: AuditConfig,

    /// Staging directory where bundles are assembled before being shipped.
    /// Default: /var/lib/mina/staging. Created `0700` if missing; must be a
    /// real directory (not a symlink) owned by root and not writable by
    /// group or other, or `session-close` refuses to write the bundle.
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

    /// Client certificate (PEM, full chain leaf first) presented to the
    /// nest — mutual TLS. Set together with `https_client_key`, or neither.
    #[serde(default)]
    pub https_client_cert: Option<PathBuf>,

    /// Unencrypted private key (PEM) of `https_client_cert`.
    #[serde(default)]
    pub https_client_key: Option<PathBuf>,

    /// CA certificate(s) (PEM) to verify the nest with, instead of the
    /// system CA store.
    #[serde(default)]
    pub https_ca_cert: Option<PathBuf>,

    /// Local directory to copy bundles into, read-only.  (local transport)
    /// e.g. "/var/mina"
    pub local_destination: Option<String>,
}

/// The validated `https_*` keys of `[nest]`, for the HTTPS transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsSettings {
    pub endpoint: String,
    /// `Some` exactly when `client_key` is `Some`.
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub ca_cert: Option<PathBuf>,
}

impl NestConfig {
    /// Validate the `https_*` keys. Called only when `transport = "https"`,
    /// so leftover keys never break another transport. Paths are not
    /// checked for existence: the transport reads them on every ship.
    pub fn https_settings(&self) -> Result<HttpsSettings> {
        let endpoint = self
            .https_endpoint
            .clone()
            .context("nest.https_endpoint is required when transport = \"https\"")?;
        let uri: ureq::http::Uri = endpoint
            .parse()
            .with_context(|| format!("nest.https_endpoint {endpoint:?} is not a valid URL"))?;
        if !uri
            .scheme_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("https"))
        {
            bail!("nest.https_endpoint {endpoint:?} must start with https://");
        }
        if uri.host().is_none_or(str::is_empty) {
            bail!("nest.https_endpoint {endpoint:?} has no host");
        }
        if self.https_client_cert.is_some() != self.https_client_key.is_some() {
            bail!("nest.https_client_cert and nest.https_client_key must be set together");
        }
        Ok(HttpsSettings {
            endpoint,
            client_cert: self.https_client_cert.clone(),
            client_key: self.https_client_key.clone(),
            ca_cert: self.https_ca_cert.clone(),
        })
    }
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

/// `[audit]`: the auditd command source, used for sessions in which no
/// login shell loaded the shell hook (`ssh host cmd`, scp, sftp).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditConfig {
    /// The audit log. Default: `log_file` from /etc/audit/auditd.conf.
    #[serde(default)]
    pub log_file: Option<PathBuf>,

    /// How long session-close waits for auditd to write the session's last
    /// records (milliseconds). Default: 1000.
    #[serde(default = "default_wait_ms")]
    pub wait_ms: u64,

    /// At most this many commands from the audit log per bundle; the rest
    /// are dropped and `commands_truncated` is set. Default: 10000.
    #[serde(default = "default_max_commands")]
    pub max_commands: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_file: None,
            wait_ms: default_wait_ms(),
            max_commands: default_max_commands(),
        }
    }
}

impl AuditConfig {
    /// Read only the `[audit]` table, so that `session-open` does not
    /// depend on the rest of the file being valid.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct AuditOnly {
            #[serde(default)]
            audit: AuditConfig,
        }
        let only: AuditOnly = toml::from_str(text)?;
        Ok(only.audit)
    }
}

fn default_wait_ms() -> u64 {
    1000
}

fn default_max_commands() -> usize {
    10_000
}

fn default_size_limit() -> u64 {
    512
}

fn default_staging_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/lib/mina/staging")
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
# Where bundles are assembled before shipping; removed once shipped. Created
# 0700 if missing. Must be owned by root, not group/other-writable and not a
# symlink, or session-close refuses to use it. Top-level key: keep it above
# the first [table].
# staging_dir = "/var/lib/mina/staging"

[nest]
transport = "ssh"                         # "ssh", "https", or "local"
ssh_destination = "mina@nest.example.com:/var/mina"
ssh_key_path = "/etc/mina/nest_key"
# https_endpoint = "https://nest.example.com/ingest"
# https_client_cert = "/etc/mina/client.crt"  # mTLS: PEM chain, leaf first; with the key
# https_client_key  = "/etc/mina/client.key"  # unencrypted PEM key
# https_ca_cert     = "/etc/mina/nest-ca.crt" # verify the nest with this CA, not the system store
# local_destination = "/var/mina"         # local transport: copy bundles here, read-only

[capture]
text_size_limit_kb = 512
skip_paths = ["/proc", "/sys", "/dev", "/tmp", "/run"]

[session]
pam_services = ["sshd", "login"]          # PAM services that open a session (SSH, console)

[audit]
# Commands of sessions without a login shell (ssh host cmd, scp, sftp) come
# from the audit log; needs auditd and `mina install-audit`.
# log_file = "/var/log/audit/audit.log"   # default: log_file from auditd.conf
# wait_ms = 1000                          # wait for auditd at session close
# max_commands = 10000                    # per bundle
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
    fn staging_dir_defaults_outside_tmp() {
        let config: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config.staging_dir, PathBuf::from("/var/lib/mina/staging"));
    }

    #[test]
    fn staging_dir_configurable() {
        let text = EXAMPLE_CONFIG.replace(
            "# staging_dir = \"/var/lib/mina/staging\"",
            "staging_dir = \"/srv/mina-staging\"",
        );
        let config: Config = toml::from_str(&text).unwrap();
        assert_eq!(config.staging_dir, PathBuf::from("/srv/mina-staging"));
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
    fn audit_defaults() {
        let config: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config.audit, AuditConfig::default());
        assert_eq!(config.audit.wait_ms, 1000);
        assert_eq!(config.audit.max_commands, 10_000);
        assert_eq!(config.audit.log_file, None);
        assert_eq!(AuditConfig::parse("").unwrap(), AuditConfig::default());
    }

    #[test]
    fn audit_configurable_on_its_own() {
        // No [nest]: the full Config does not load, the audit part does.
        let text = r#"
            [audit]
            log_file = "/srv/audit.log"
            wait_ms = 200
        "#;
        let audit = AuditConfig::parse(text).unwrap();
        assert_eq!(audit.log_file, Some(PathBuf::from("/srv/audit.log")));
        assert_eq!(audit.wait_ms, 200);
        assert_eq!(audit.max_commands, 10_000);
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

    // ── https_settings ──────────────────────────────────────────────────

    /// Parse a `[nest]` table body (transport = "https" is prepended).
    fn nest(body: &str) -> NestConfig {
        let text = format!("[nest]\ntransport = \"https\"\n{body}\n[capture]\n");
        toml::from_str::<Config>(&text).unwrap().nest
    }

    fn err(body: &str) -> String {
        format!("{:#}", nest(body).https_settings().unwrap_err())
    }

    #[test]
    fn https_settings_requires_endpoint() {
        assert!(err("").contains("https_endpoint"));
    }

    #[test]
    fn https_settings_rejects_plain_http() {
        assert!(err(r#"https_endpoint = "http://nest.example.com/ingest""#).contains("https://"));
    }

    #[test]
    fn endpoint_scheme_is_case_insensitive() {
        assert!(
            nest(r#"https_endpoint = "HTTPS://nest.example.com/ingest""#)
                .https_settings()
                .is_ok()
        );
    }

    #[test]
    fn endpoint_without_host_rejected() {
        for endpoint in ["https://", "https:///ingest"] {
            let body = format!("https_endpoint = \"{endpoint}\"");
            assert!(nest(&body).https_settings().is_err(), "{endpoint}");
        }
    }

    #[test]
    fn https_settings_rejects_cert_without_key() {
        let e = err(r#"
            https_endpoint = "https://nest.example.com/ingest"
            https_client_cert = "/etc/mina/client.crt"
        "#);
        assert!(
            e.contains("https_client_cert") && e.contains("https_client_key"),
            "{e}"
        );
    }

    #[test]
    fn https_settings_rejects_key_without_cert() {
        let e = err(r#"
            https_endpoint = "https://nest.example.com/ingest"
            https_client_key = "/etc/mina/client.key"
        "#);
        assert!(
            e.contains("https_client_cert") && e.contains("https_client_key"),
            "{e}"
        );
    }

    #[test]
    fn https_settings_accepts_mtls() {
        let settings = nest(
            r#"
            https_endpoint = "https://nest.example.com/ingest"
            https_client_cert = "/etc/mina/client.crt"
            https_client_key = "/etc/mina/client.key"
            https_ca_cert = "/etc/mina/nest-ca.crt"
        "#,
        )
        .https_settings()
        .unwrap();
        assert_eq!(
            settings,
            HttpsSettings {
                endpoint: "https://nest.example.com/ingest".to_owned(),
                client_cert: Some(PathBuf::from("/etc/mina/client.crt")),
                client_key: Some(PathBuf::from("/etc/mina/client.key")),
                ca_cert: Some(PathBuf::from("/etc/mina/nest-ca.crt")),
            }
        );
    }

    #[test]
    fn https_settings_accepts_no_client_cert() {
        let settings = nest(r#"https_endpoint = "https://nest.example.com/ingest""#)
            .https_settings()
            .unwrap();
        assert_eq!(settings.client_cert, None);
        assert_eq!(settings.client_key, None);
        assert_eq!(settings.ca_cert, None);
    }

    #[test]
    fn stray_https_keys_do_not_break_load() {
        let text = r#"
            [nest]
            transport = "ssh"
            ssh_destination = "mina@host:/var/mina"
            https_endpoint = "http://x"
            https_client_cert = "/etc/mina/client.crt"
            [capture]
        "#;
        assert!(toml::from_str::<Config>(text).is_ok());
    }
}
