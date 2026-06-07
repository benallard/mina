use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // TODO: parse subcommands:
    //   mina install-pam
    //   mina uninstall-pam
    //   mina install-audit
    //   mina session-open   (called by PAM)
    //   mina session-close  (called by PAM)
    //   mina version

    println!("mina v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
