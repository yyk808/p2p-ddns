use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_p2p-ddns"))
}

#[test]
fn cli_requires_exactly_one_mode() {
    let out = bin().output().expect("run p2p-ddns");
    assert!(!out.status.success(), "missing mode should fail");

    let out = bin()
        .args(["--daemon", "--client"])
        .output()
        .expect("run p2p-ddns");
    assert!(!out.status.success(), "conflicting modes should fail");
}

#[test]
fn client_mode_requires_subcommand() {
    let out = bin()
        .args(["--client", "--ticket", "abc"])
        .output()
        .expect("run p2p-ddns");
    assert!(
        !out.status.success(),
        "missing client subcommand should fail"
    );
}

#[test]
fn daemon_help_succeeds() {
    let out = bin()
        .args(["--daemon", "--help"])
        .output()
        .expect("run p2p-ddns");
    assert!(out.status.success());
}
