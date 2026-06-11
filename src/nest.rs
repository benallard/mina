//! mina-nest — optional HTTPS ingest endpoint.
//!
//! Receives bundle tarballs from mina agents and unpacks them into
//! the nest directory tree.
//!
//! Usage: mina-nest serve --dir /var/mina --port 8765
//!
//! For production: run behind nginx/Caddy with TLS termination.
//!
//! TODO: implement HTTP server (likely with a minimal framework or
//!       raw std::net::TcpListener to keep deps minimal).

fn main() {
    println!(
        "mina-nest v{} — not yet implemented",
        env!("CARGO_PKG_VERSION")
    );
}
