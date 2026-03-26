use std::process::Command;

fn daemon_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_p2p-ddns"))
}

fn client_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_p2p-ddnsctl"))
}

#[test]
fn daemon_help_succeeds() {
    let out = daemon_bin().arg("--help").output().expect("run p2p-ddns");
    assert!(out.status.success());
}

#[test]
fn client_help_succeeds() {
    let out = client_bin()
        .arg("--help")
        .output()
        .expect("run p2p-ddnsctl");
    assert!(out.status.success());
}

#[test]
fn client_requires_subcommand() {
    let out = client_bin().output().expect("run p2p-ddnsctl");
    assert!(
        !out.status.success(),
        "missing client subcommand should fail"
    );
}

#[test]
fn client_node_subcommand_help_succeeds() {
    let out = client_bin()
        .args(["node", "--help"])
        .output()
        .expect("run p2p-ddnsctl node --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("add"), "should list 'add' subcommand");
    assert!(stdout.contains("remove"), "should list 'remove' subcommand");
}
