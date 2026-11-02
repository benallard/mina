/// HTTPS transport.
///
/// Ships the bundle as one POST of a gzipped tarball (`transport::tarball`)
/// to the nest endpoint. TLS only — plain HTTP is rejected by
/// `NestConfig::https_settings`, and there is no way to skip verification.
///
/// Optionally presents a client certificate (mutual TLS) and verifies the
/// nest against a configured CA instead of the system store. Certificate,
/// key and CA are read from disk on every ship, so a renewal is picked up
/// without restarting anything.
///
/// Wire contract: `Content-Type: application/gzip`,
/// `User-Agent: mina/<version>`, `X-Mina-Bundle-Digest: sha256=<hex>`;
/// any 2xx is success. The digest lets the nest recognise a resend after
/// `ship_with_retry` retried a bundle it had already stored.
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use ureq::tls::{Certificate, ClientCert, PemItem, PrivateKey, RootCerts, TlsConfig, TlsProvider};

use super::{tarball, Transport};
use crate::config::HttpsSettings;

/// Time allowed to connect to the nest.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for the whole request. Spent at logout, so keep it bounded.
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Bytes of a non-2xx response body quoted in the error.
const MAX_ERROR_BODY: usize = 512;

/// TLS material read from disk for one ship attempt.
pub(crate) struct TlsMaterial {
    /// Client certificate chain (leaf first) and its key, for mutual TLS.
    pub client: Option<(Vec<Certificate<'static>>, PrivateKey<'static>)>,
    /// Trust anchors for the nest; `None` means the system CA store.
    pub roots: Option<Vec<Certificate<'static>>>,
}

/// Read the configured client cert, key and CA files. Called on every ship,
/// so a certificate renewed on disk is used by the next session close.
pub(crate) fn load_tls_material(s: &HttpsSettings) -> Result<TlsMaterial> {
    let client = match (&s.client_cert, &s.client_key) {
        (Some(cert), Some(key)) => Some((
            read_certs(cert, "nest.https_client_cert")?,
            read_key(key, "nest.https_client_key")?,
        )),
        _ => None,
    };
    let roots = match &s.ca_cert {
        Some(ca) => Some(read_certs(ca, "nest.https_ca_cert")?),
        None => None,
    };
    Ok(TlsMaterial { client, roots })
}

/// Turn loaded material into ureq's TLS config: rustls, the client cert if
/// any, and explicit roots — never ureq's default compiled-in roots.
pub(crate) fn tls_config(m: TlsMaterial) -> TlsConfig {
    let roots = match m.roots {
        Some(certs) => RootCerts::new_with_certs(&certs),
        None => RootCerts::PlatformVerifier,
    };
    TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .client_cert(
            m.client
                .map(|(chain, key)| ClientCert::new_with_certs(&chain, key)),
        )
        .root_certs(roots)
        .build()
}

/// Every certificate in the PEM file at `path`; at least one.
fn read_certs(path: &Path, key: &str) -> Result<Vec<Certificate<'static>>> {
    let pem = read(path, key)?;
    let mut certs = Vec::new();
    for item in ureq::tls::parse_pem(&pem) {
        let item = item.with_context(|| format!("{key}: cannot parse {}", path.display()))?;
        if let PemItem::Certificate(cert) = item {
            certs.push(cert);
        }
    }
    if certs.is_empty() {
        bail!("{key}: no certificate found in {}", path.display());
    }
    Ok(certs)
}

/// The first private key in the PEM file at `path`.
fn read_key(path: &Path, key: &str) -> Result<PrivateKey<'static>> {
    let pem = read(path, key)?;
    for item in ureq::tls::parse_pem(&pem) {
        let item = item.with_context(|| format!("{key}: cannot parse {}", path.display()))?;
        if let PemItem::PrivateKey(k) = item {
            return Ok(k);
        }
    }
    bail!(
        "{key}: no unencrypted private key found in {}",
        path.display()
    )
}

fn read(path: &Path, key: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("{key}: cannot read {}", path.display()))
}

pub struct HttpsTransport {
    pub settings: HttpsSettings,
}

impl Transport for HttpsTransport {
    fn ship(&self, bundle_root: &Path) -> Result<()> {
        let body = tarball::build(bundle_root)?;
        let digest = tarball::digest(&body);
        // Before any connection: a missing key fails here, not mid-handshake.
        let tls = tls_config(load_tls_material(&self.settings)?);
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(GLOBAL_TIMEOUT))
            .http_status_as_error(false)
            .tls_config(tls)
            .build()
            .into();
        let endpoint = &self.settings.endpoint;
        let mut response = agent
            .post(endpoint)
            .header("Content-Type", "application/gzip")
            .header("User-Agent", concat!("mina/", env!("CARGO_PKG_VERSION")))
            .header("X-Mina-Bundle-Digest", &digest)
            .send(&body[..])
            .with_context(|| format!("POST {endpoint} failed"))?;
        let status = response.status().as_u16();
        let mut snippet = Vec::new();
        if !response.status().is_success() {
            // Best effort: the status alone is enough to report.
            let _ = response
                .body_mut()
                .as_reader()
                .take(MAX_ERROR_BODY as u64)
                .read_to_end(&mut snippet);
        }
        check_status(status, &snippet).with_context(|| format!("POST {endpoint}"))
    }
}

/// Any 2xx is success; otherwise an error quoting the status and at most
/// `MAX_ERROR_BODY` bytes of the body, decoded lossily.
fn check_status(status: u16, body: &[u8]) -> Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let body = &body[..body.len().min(MAX_ERROR_BODY)];
    let text = String::from_utf8_lossy(body);
    bail!("nest answered HTTP {status}: {}", text.trim())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const CHAIN: &[u8] = include_bytes!("testdata/chain.pem");
    const KEY: &[u8] = include_bytes!("testdata/client.key");
    const CA: &[u8] = include_bytes!("testdata/ca.pem");

    /// Fixtures copied into a temp dir, so the paths are real files.
    struct Fixtures {
        dir: TempDir,
    }

    impl Fixtures {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            fs::write(dir.path().join("chain.pem"), CHAIN).unwrap();
            fs::write(dir.path().join("client.key"), KEY).unwrap();
            fs::write(dir.path().join("ca.pem"), CA).unwrap();
            Self { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn settings(&self, cert: &str, key: &str, ca: Option<&str>) -> HttpsSettings {
            HttpsSettings {
                endpoint: "https://127.0.0.1:9/ingest".to_owned(),
                client_cert: Some(self.path(cert)),
                client_key: Some(self.path(key)),
                ca_cert: ca.map(|c| self.path(c)),
            }
        }
    }

    fn err(settings: &HttpsSettings) -> String {
        match load_tls_material(settings) {
            Ok(_) => panic!("expected an error"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn loads_chain_and_key() {
        let f = Fixtures::new();
        let m = load_tls_material(&f.settings("chain.pem", "client.key", None)).unwrap();
        let (certs, _key) = m.client.unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn loads_ca_as_specific_roots() {
        let f = Fixtures::new();
        let m = load_tls_material(&f.settings("chain.pem", "client.key", Some("ca.pem"))).unwrap();
        assert_eq!(m.roots.unwrap().len(), 1);
    }

    #[test]
    fn no_ca_means_platform_verifier() {
        let f = Fixtures::new();
        let m = load_tls_material(&f.settings("chain.pem", "client.key", None)).unwrap();
        assert!(m.roots.is_none());
        assert!(matches!(
            tls_config(m).root_certs(),
            ureq::tls::RootCerts::PlatformVerifier
        ));
    }

    #[test]
    fn no_client_cert_means_no_client_auth() {
        let f = Fixtures::new();
        let mut s = f.settings("chain.pem", "client.key", None);
        s.client_cert = None;
        s.client_key = None;
        let m = load_tls_material(&s).unwrap();
        assert!(m.client.is_none());
        assert!(tls_config(m).client_cert().is_none());
    }

    #[test]
    fn missing_cert_file_names_path_and_key() {
        let f = Fixtures::new();
        let s = f.settings("absent.pem", "client.key", None);
        let e = err(&s);
        assert!(e.contains("https_client_cert"), "{e}");
        assert!(
            e.contains(&f.path("absent.pem").display().to_string()),
            "{e}"
        );
    }

    #[test]
    fn garbage_key_file_errors() {
        let f = Fixtures::new();
        fs::write(f.path("client.key"), b"not a key").unwrap();
        let e = err(&f.settings("chain.pem", "client.key", None));
        assert!(e.contains("https_client_key"), "{e}");
    }

    #[test]
    fn cert_file_without_certificates_errors() {
        let f = Fixtures::new();
        let e = err(&f.settings("client.key", "client.key", None));
        assert!(e.contains("no certificate"), "{e}");
    }

    #[test]
    fn reads_files_on_every_call() {
        let f = Fixtures::new();
        let s = f.settings("chain.pem", "client.key", None);
        assert_eq!(load_tls_material(&s).unwrap().client.unwrap().0.len(), 2);
        fs::write(f.path("chain.pem"), CA).unwrap();
        assert_eq!(load_tls_material(&s).unwrap().client.unwrap().0.len(), 1);
    }

    // ── ship / status ───────────────────────────────────────────────────

    #[test]
    fn status_2xx_is_ok() {
        assert!(check_status(200, b"").is_ok());
        assert!(check_status(201, b"x").is_ok());
    }

    #[test]
    fn status_error_names_code_and_body() {
        let e = format!(
            "{:#}",
            check_status(403, b"client cert required").unwrap_err()
        );
        assert!(
            e.contains("403") && e.contains("client cert required"),
            "{e}"
        );
    }

    #[test]
    fn status_error_truncates_body() {
        let body = "é".repeat(2000);
        let e = format!("{:#}", check_status(500, body.as_bytes()).unwrap_err());
        let shown = e.matches('é').count();
        assert!(
            shown > 0 && shown * 2 <= MAX_ERROR_BODY,
            "{shown} chars shown"
        );
    }

    #[test]
    fn ship_fails_before_network_when_key_missing() {
        let f = Fixtures::new();
        let root = f.path("host1").join("2026-11-02_10-00-00_alice");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("session.json"), "{}\n").unwrap();
        let transport = HttpsTransport {
            settings: f.settings("chain.pem", "absent.key", None),
        };
        let e = format!("{:#}", transport.ship(&root).unwrap_err());
        assert!(e.contains("https_client_key"), "{e}");
    }
}
