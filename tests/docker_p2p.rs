use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context as _, Result};
use iroh::TransportAddr;
use p2p_ddns::domain::ticket::Ticket;
use rand::{Rng as _, distr::Alphanumeric};
use testcontainers::{
    GenericBuildableImage, GenericImage, ImageExt,
    core::ExecCommand,
    runners::{AsyncBuilder, AsyncRunner},
};
use tokio::time::{Instant, sleep};

static DOCKER_SERIAL: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
static IMAGES_BUILT: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

#[derive(Debug, Clone)]
struct Case {
    name: String,
    subnet_count: usize,
    daemon_count: usize,
    gateway: bool,
    partition_recover: bool,
    converge_timeout: Duration,
    primary_multihome: bool,
    expectation: Expectation,
}

#[derive(Debug, Clone)]
enum Expectation {
    /// Expect the primary to eventually list every daemon.
    ConvergeAllDaemons,
    /// Expect the primary to list `must_include`, and never list `must_exclude` for `observe`.
    ConvergeSubset {
        must_include: Vec<String>,
        must_exclude: Vec<String>,
        observe: Duration,
    },
}

async fn docker_serial_guard() -> tokio::sync::OwnedSemaphorePermit {
    DOCKER_SERIAL
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
        .acquire_owned()
        .await
        .expect("semaphore closed")
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn image_tag() -> String {
    env::var("P2P_DDNS_IT_IMAGE_TAG").unwrap_or_else(|_| "tc".to_string())
}

fn env_bool(key: &str) -> bool {
    matches!(
        env::var(key)
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("on")
    )
}

fn env_usize(key: &str) -> Result<Option<usize>> {
    let Ok(value) = env::var(key) else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = value
        .parse::<usize>()
        .with_context(|| format!("invalid {key}={value} (expected usize)"))?;
    Ok(Some(parsed))
}

fn env_csv_usize(key: &str) -> Result<Option<Vec<usize>>> {
    let Ok(value) = env::var(key) else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }

    let mut out = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let n = part
            .parse::<usize>()
            .with_context(|| format!("invalid {key} entry: {part} (expected usize)"))?;
        out.push(n);
    }

    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(out))
}

fn unique_suffix() -> String {
    let rng = rand::rng();
    rng.sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}

async fn ensure_images_built() -> Result<String> {
    let tag = image_tag();
    let tag = IMAGES_BUILT
        .get_or_try_init(|| async move {
            if env_bool("P2P_DDNS_IT_NO_BUILD") {
                return Ok::<String, anyhow::Error>(tag);
            }
            let _guard = docker_serial_guard().await;
            build_images(&tag).await?;
            Ok::<String, anyhow::Error>(tag)
        })
        .await?;
    Ok(tag.clone())
}

async fn build_images(tag: &str) -> Result<()> {
    let root = project_root();

    let base = GenericBuildableImage::new("p2p-ddns-test-base", "latest")
        .with_dockerfile(root.join("tests/integration/nodes/base/Dockerfile"))
        // Keep the build context minimal: `target/` is often huge and would make the build
        // painfully slow (or even fail) when streamed via the Docker API.
        .with_file(root.join("Cargo.toml"), "Cargo.toml")
        .with_file(root.join("Cargo.lock"), "Cargo.lock")
        .with_file(root.join("src"), "src")
        .with_file(
            root.join("tests/integration/scripts/health-check.sh"),
            "tests/integration/scripts/health-check.sh",
        );
    let _ = base
        .build_image()
        .await
        .context("build docker image: p2p-ddns-test-base:latest")?;

    let primary = GenericBuildableImage::new("p2p-ddns-test-primary", tag)
        .with_dockerfile(root.join("tests/integration/nodes/primary/Dockerfile"))
        .with_file(
            root.join("tests/integration/nodes/primary/entrypoint.sh"),
            "tests/integration/nodes/primary/entrypoint.sh",
        );
    let _ = primary
        .build_image()
        .await
        .with_context(|| format!("build docker image: p2p-ddns-test-primary:{tag}"))?;

    let daemon = GenericBuildableImage::new("p2p-ddns-test-daemon", tag)
        .with_dockerfile(root.join("tests/integration/nodes/daemon/Dockerfile"))
        .with_file(
            root.join("tests/integration/nodes/daemon/entrypoint.sh"),
            "tests/integration/nodes/daemon/entrypoint.sh",
        );
    let _ = daemon
        .build_image()
        .await
        .with_context(|| format!("build docker image: p2p-ddns-test-daemon:{tag}"))?;

    Ok(())
}

fn networks_for(project: &str, subnet_count: usize) -> Result<Vec<String>> {
    anyhow::ensure!(subnet_count >= 1, "subnet_count must be >= 1");
    Ok((1..=subnet_count)
        .map(|i| format!("{project}-subnet-{i:02}"))
        .collect())
}

fn daemon_networks_for(networks: &[String]) -> Result<&[String]> {
    if networks.is_empty() {
        anyhow::bail!("missing networks");
    }
    Ok(networks)
}

fn case_name(subnets: usize, daemons: usize, gateway: bool, partition: bool) -> String {
    let mut name = format!("s{subnets}-d{daemons}");
    if gateway {
        name.push_str("-gw");
    }
    if partition {
        name.push_str("-partition");
    }
    name
}

fn daemon_name(i: usize) -> String {
    format!("daemon-{i:02}")
}

fn daemon_names(daemon_count: usize) -> Vec<String> {
    (1..=daemon_count).map(daemon_name).collect()
}

fn daemon_network_index(daemon_index: usize, subnet_count: usize) -> usize {
    (daemon_index - 1) % subnet_count
}

fn daemon_names_in_network(
    daemon_count: usize,
    subnet_count: usize,
    network_index: usize,
) -> Vec<String> {
    assert!(subnet_count >= 1, "subnet_count must be >= 1");
    assert!(
        network_index < subnet_count,
        "network_index must be < subnet_count"
    );
    (1..=daemon_count)
        .filter(|i| daemon_network_index(*i, subnet_count) == network_index)
        .map(daemon_name)
        .collect()
}

fn docker_network_create(network: &str) -> Result<()> {
    let exists = Command::new("docker")
        .args(["network", "inspect", network])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if exists {
        return Ok(());
    }

    let status = Command::new("docker")
        // Use internal networks to ensure subnets are truly isolated (some Docker backends can
        // route between user-defined bridge networks by default).
        .args(["network", "create", "--internal", network])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("run docker network create")?;
    if !status.success() {
        anyhow::bail!("docker network create failed: {network}");
    }
    Ok(())
}

fn docker_container_ipv4_in_network(container_id: &str, network: &str) -> Result<Option<String>> {
    // Avoid brittle DNS lookups: Docker container names can exceed the 63-char DNS label limit.
    let template = format!(
        "{{{{with (index .NetworkSettings.Networks \"{network}\")}}}}{{{{.IPAddress}}}}{{{{end}}}}"
    );
    let output = Command::new("docker")
        .args(["inspect", "-f", &template, container_id])
        .output()
        .context("run docker inspect")?;
    if !output.status.success() {
        return Ok(None);
    }
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ip.is_empty() {
        return Ok(None);
    }
    Ok(Some(ip))
}

fn ticket_with_primary_net_ips(
    ticket: &str,
    primary_id: &str,
    networks: &[String],
) -> Result<String> {
    let parsed: Ticket = ticket.parse().context("parse ticket")?;
    let (topic, rnum, mut invitor) = parsed.flatten();

    let port = invitor
        .addr
        .ip_addrs()
        .next()
        .map(|sock| sock.port())
        .unwrap_or(7777);

    for net in networks {
        let Some(ip) = docker_container_ipv4_in_network(primary_id, net)? else {
            continue;
        };
        let ip: IpAddr = ip.parse().context("parse primary IPv4")?;
        invitor
            .addr
            .addrs
            .insert(TransportAddr::Ip(SocketAddr::new(ip, port)));
    }

    Ok(Ticket::from_parts(topic, rnum, invitor).to_string())
}

fn docker_network_rm(network: &str) -> Result<()> {
    let status = Command::new("docker")
        .args(["network", "rm", network])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("run docker network rm")?;
    if !status.success() {
        anyhow::bail!("docker network rm failed: {network}");
    }
    Ok(())
}

fn docker_logs_tail(container_id: &str, lines: usize) -> Result<String> {
    let output = Command::new("docker")
        .args(["logs", "--tail", &lines.to_string(), container_id])
        .output()
        .context("run docker logs")?;
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

async fn exec_stdout(
    container: &testcontainers::ContainerAsync<GenericImage>,
    cmd: Vec<String>,
) -> Result<String> {
    let mut res = container
        .exec(ExecCommand::new(cmd))
        .await
        .context("exec in container")?;
    let stdout = res.stdout_to_vec().await.context("read exec stdout")?;
    Ok(String::from_utf8_lossy(&stdout).to_string())
}

fn extract_ticket(text: &str) -> Option<String> {
    fn extract_after_prefix(line: &str, prefix: &str) -> Option<String> {
        let idx = line.find(prefix)?;
        let mut out = String::new();
        for ch in line[idx + prefix.len()..].chars() {
            if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' {
                out.push(ch);
            } else {
                break;
            }
        }
        if out.is_empty() { None } else { Some(out) }
    }

    for line in text.lines().rev() {
        if let Some(t) = extract_after_prefix(line, "New Ticket: ") {
            return Some(t);
        }
        if let Some(t) = extract_after_prefix(line, "Ticket: ") {
            return Some(t);
        }
    }
    None
}

async fn wait_for_primary_ticket(
    primary: &testcontainers::ContainerAsync<GenericImage>,
    timeout: Duration,
) -> Result<String> {
    let deadline = Instant::now() + timeout;
    let mut last_tail = String::new();

    loop {
        if let Ok(tail) = exec_stdout(
            primary,
            vec![
                "bash".to_string(),
                "-lc".to_string(),
                "tail -n 200 /app/logs/primary.log 2>/dev/null || true".to_string(),
            ],
        )
        .await
        {
            if !tail.trim().is_empty() {
                last_tail = tail.clone();
            }
            if let Some(ticket) = extract_ticket(&tail) {
                return Ok(ticket);
            }
        }

        if Instant::now() >= deadline {
            let docker_tail = docker_logs_tail(primary.id(), 200).unwrap_or_default();
            anyhow::bail!(
                "primary ticket not available after {}s.\n\
tail -n 200 /app/logs/primary.log (from exec):\n{}\n\
docker logs --tail 200:\n{}",
                timeout.as_secs(),
                last_tail,
                docker_tail
            );
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn primary_list(
    primary: &testcontainers::ContainerAsync<GenericImage>,
    ticket: &str,
) -> Result<String> {
    exec_stdout(
        primary,
        vec![
            "p2p-ddns".to_string(),
            "--client".to_string(),
            "--socket-path".to_string(),
            "/tmp/p2p-ddns.sock".to_string(),
            "--ticket".to_string(),
            ticket.to_string(),
            "list".to_string(),
        ],
    )
    .await
}

async fn wait_for_primary_converged(
    primary: &testcontainers::ContainerAsync<GenericImage>,
    ticket: &str,
    expected_names: &[String],
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_out = String::new();
    loop {
        match primary_list(primary, ticket).await {
            Ok(out) => {
                last_out = out.clone();
                if expected_names.iter().all(|n| out.contains(n)) {
                    return Ok(());
                }
            }
            Err(_) => {}
        }

        if Instant::now() >= deadline {
            let missing = expected_names
                .iter()
                .filter(|n| !last_out.contains(n.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            anyhow::bail!(
                "primary membership did not converge after {}s, missing={:?}, last output:\n{}",
                timeout.as_secs(),
                missing,
                last_out
            );
        }
        sleep(Duration::from_millis(500)).await;
    }
}

fn docker_network_disconnect(network: &str, container_id: &str) -> Result<()> {
    let status = Command::new("docker")
        .args(["network", "disconnect", network, container_id])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("run docker network disconnect")?;
    if !status.success() {
        anyhow::bail!("docker network disconnect failed: {network} {container_id}");
    }
    Ok(())
}

fn docker_network_connect(network: &str, container_id: &str) -> Result<()> {
    let status = Command::new("docker")
        .args(["network", "connect", network, container_id])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("run docker network connect")?;
    if !status.success() {
        anyhow::bail!("docker network connect failed: {network} {container_id}");
    }
    Ok(())
}

struct NetworkGuard {
    names: Vec<String>,
}

impl NetworkGuard {
    fn new(names: Vec<String>) -> Result<Self> {
        for n in &names {
            docker_network_create(n)?;
        }
        Ok(Self { names })
    }
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        for n in self.names.iter().rev() {
            let _ = docker_network_rm(n);
        }
    }
}

async fn assert_primary_missing_for(
    primary: &testcontainers::ContainerAsync<GenericImage>,
    ticket: &str,
    forbidden_names: &[String],
    duration: Duration,
) -> Result<()> {
    let deadline = Instant::now() + duration;
    let mut last_out = String::new();
    loop {
        match primary_list(primary, ticket).await {
            Ok(out) => {
                last_out = out.clone();
                if forbidden_names.iter().any(|n| out.contains(n)) {
                    anyhow::bail!(
                        "primary unexpectedly listed a forbidden node; forbidden={:?}\n{}",
                        forbidden_names,
                        out
                    );
                }
            }
            Err(_) => {}
        }

        if Instant::now() >= deadline {
            if !last_out.is_empty() {
                eprintln!("primary list output (final):\n{last_out}");
            }
            return Ok(());
        }
        sleep(Duration::from_millis(500)).await;
    }
}

async fn run_case(case: Case, tag: &str) -> Result<()> {
    let _guard = docker_serial_guard().await;
    let keep = env_bool("P2P_DDNS_IT_KEEP_DOCKER");

    let project = format!(
        "p2pddns-it-{}-{}",
        case.name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>(),
        unique_suffix()
    );
    eprintln!(
        "Case {} (project={project}, subnets={}, daemons={}, gateway={}, partition_recover={})",
        case.name, case.subnet_count, case.daemon_count, case.gateway, case.partition_recover
    );

    let networks = networks_for(&project, case.subnet_count)?;
    let daemon_networks = daemon_networks_for(&networks)?;
    let networks_guard = NetworkGuard::new(networks.clone())?;

    let primary_container_name = format!("{project}-primary");
    let primary_expected_ipv4 = if case.primary_multihome {
        case.subnet_count
    } else {
        1
    };
    let primary = {
        GenericImage::new("p2p-ddns-test-primary", tag)
            .with_container_name(primary_container_name.clone())
            .with_env_var("NODE_NAME", "primary-node")
            .with_env_var("P2P_DDNS_LOG_LEVEL", "debug")
            .with_env_var("P2P_DDNS_DOMAIN", "primary-node")
            .with_env_var("P2P_DDNS_BIND_ADDRESS", "0.0.0.0:7777")
            .with_env_var("P2P_DDNS_EXPECT_IPV4", primary_expected_ipv4.to_string())
            .with_env_var("XDG_RUNTIME_DIR", "/tmp")
            .with_network(networks.first().context("missing primary network")?.clone())
            .start()
            .await
            .context("start primary container")?
    };

    // testcontainers-rs only attaches to one network at creation time; multi-home here.
    if case.primary_multihome {
        for net in networks.iter().skip(1) {
            docker_network_connect(net, primary.id())?;
        }
    }

    let mut ticket_for_debug: Option<String> = None;
    let mut daemons = Vec::with_capacity(case.daemon_count);
    let res: Result<()> = async {
        let ticket = wait_for_primary_ticket(&primary, Duration::from_secs(10)).await?;
        let ticket = ticket_with_primary_net_ips(&ticket, primary.id(), &networks)?;
        ticket_for_debug = Some(ticket.clone());

        for i in 1..=case.daemon_count {
            let name = format!("daemon-{i:02}");
            let container_name = format!("{project}-{name}");

            let idx = (i - 1) % daemon_networks.len();
            let initial_network = daemon_networks
                .get(idx)
                .context("missing daemon network")?
                .clone();

            // `PRIMARY_HOST` is used only by the entrypoint script for a best-effort `ping` check.
            // When the primary is intentionally *not* connected to a daemon's network, make the ping
            // succeed quickly to avoid waiting 60s before starting p2p-ddns.
            let primary_host_for_ping = if case.primary_multihome || idx == 0 {
                docker_container_ipv4_in_network(primary.id(), &initial_network)?
                    .unwrap_or_else(|| "127.0.0.1".to_string())
            } else {
                "127.0.0.1".to_string()
            };

            let expected_ipv4 = if case.gateway && case.subnet_count > 1 && i == 1 {
                case.subnet_count
            } else {
                1
            };

            let container = GenericImage::new("p2p-ddns-test-daemon", tag)
                .with_container_name(container_name)
                .with_env_var("NODE_NAME", name.clone())
                .with_env_var("P2P_DDNS_LOG_LEVEL", "info")
                .with_env_var("P2P_DDNS_DOMAIN", name.clone())
                .with_env_var("P2P_DDNS_BIND_ADDRESS", "0.0.0.0:7777")
                .with_env_var("P2P_DDNS_TICKET", ticket.clone())
                .with_env_var("PRIMARY_HOST", primary_host_for_ping)
                .with_env_var("P2P_DDNS_EXPECT_IPV4", expected_ipv4.to_string())
                .with_env_var("XDG_RUNTIME_DIR", "/tmp")
                .with_network(initial_network.clone())
                .start()
                .await
                .with_context(|| format!("start daemon container: {name}"))?;

            if case.gateway && case.subnet_count > 1 && i == 1 {
                for net in daemon_networks {
                    if net == &initial_network {
                        continue;
                    }
                    docker_network_connect(net, container.id())?;
                }
            }
            daemons.push(container);
        }

        let all_daemons = daemon_names(case.daemon_count);
        match &case.expectation {
            Expectation::ConvergeAllDaemons => {
                wait_for_primary_converged(&primary, &ticket, &all_daemons, case.converge_timeout)
                    .await?;
            }
            Expectation::ConvergeSubset {
                must_include,
                must_exclude,
                observe,
            } => {
                wait_for_primary_converged(&primary, &ticket, must_include, case.converge_timeout)
                    .await?;
                assert_primary_missing_for(&primary, &ticket, must_exclude, *observe).await?;
            }
        }

        if case.partition_recover {
            let subnet_b = networks
                .get(1)
                .context("partition test requires at least 2 networks")?;
            docker_network_disconnect(subnet_b, primary.id())?;
            sleep(Duration::from_secs(10)).await;
            docker_network_connect(subnet_b, primary.id())?;
            // After reconnect, rerun the same expectation checks.
            match &case.expectation {
                Expectation::ConvergeAllDaemons => {
                    wait_for_primary_converged(
                        &primary,
                        &ticket,
                        &all_daemons,
                        case.converge_timeout,
                    )
                    .await?;
                }
                Expectation::ConvergeSubset {
                    must_include,
                    must_exclude,
                    observe,
                } => {
                    wait_for_primary_converged(
                        &primary,
                        &ticket,
                        must_include,
                        case.converge_timeout,
                    )
                    .await?;
                    assert_primary_missing_for(&primary, &ticket, must_exclude, *observe).await?;
                }
            }
        }

        Ok(())
    }
    .await;

    if res.is_err() {
        if let Some(ticket) = ticket_for_debug.as_deref() {
            if let Ok(out) = primary_list(&primary, ticket).await {
                let expected = daemon_names(case.daemon_count);
                let missing = expected
                    .iter()
                    .filter(|n| !out.contains(n.as_str()))
                    .cloned()
                    .collect::<Vec<_>>();
                eprintln!("Primary list (debug):\n{out}");

                for name in missing {
                    let idx = name
                        .strip_prefix("daemon-")
                        .and_then(|s| s.parse::<usize>().ok())
                        .and_then(|n| n.checked_sub(1));
                    let Some(idx) = idx else {
                        continue;
                    };
                    let Some(daemon) = daemons.get(idx) else {
                        continue;
                    };
                    let tail = docker_logs_tail(daemon.id(), 200).unwrap_or_else(|e| {
                        format!("(failed to read docker logs for {name}: {e:#})")
                    });
                    let mut excerpt = String::new();
                    for line in tail.lines() {
                        if line.contains("p2p_ddns") || line.contains("Timeout joining gossip") {
                            excerpt.push_str(line);
                            excerpt.push('\n');
                        }
                    }
                    if excerpt.trim().is_empty() {
                        excerpt = tail
                            .lines()
                            .rev()
                            .take(40)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect::<Vec<_>>()
                            .join("\n");
                    }
                    eprintln!("----- {name} logs (filtered) -----\n{excerpt}");
                }
            }
        }
    }

    if keep {
        eprintln!("Keeping docker resources for debugging (project prefix: {project}).");
        std::mem::forget(daemons);
        std::mem::forget(primary);
        std::mem::forget(networks_guard);
        return res;
    }

    drop(daemons);
    drop(primary);
    drop(networks_guard);

    res
}

#[tokio::test]
async fn docker_p2p_smoke() -> Result<()> {
    anyhow::ensure!(docker_available(), "docker is not available");

    let tag = ensure_images_built().await?;

    let subnet_count = env_usize("P2P_DDNS_IT_SUBNETS")?.unwrap_or(1);
    let daemon_count = env_usize("P2P_DDNS_IT_DAEMONS")?.unwrap_or(4);
    let gateway = env_bool("P2P_DDNS_IT_GATEWAY");
    let partition_recover = env_bool("P2P_DDNS_IT_PARTITION_RECOVER");

    let name = case_name(subnet_count, daemon_count, gateway, partition_recover);

    run_case(
        Case {
            name,
            subnet_count,
            daemon_count,
            gateway,
            partition_recover,
            converge_timeout: Duration::from_secs(10),
            primary_multihome: true,
            expectation: Expectation::ConvergeAllDaemons,
        },
        &tag,
    )
    .await
}

#[tokio::test]
async fn docker_p2p_matrix() -> Result<()> {
    anyhow::ensure!(docker_available(), "docker is not available");

    let tag = ensure_images_built().await?;

    let subnet_counts_env = env_csv_usize("P2P_DDNS_IT_MATRIX_SUBNETS")?;
    let daemon_counts_env = env_csv_usize("P2P_DDNS_IT_MATRIX_DAEMONS")?;
    let dynamic = env_bool("P2P_DDNS_IT_MATRIX_DYNAMIC")
        || subnet_counts_env.is_some()
        || daemon_counts_env.is_some();

    let mut cases = if dynamic {
        let subnet_counts = subnet_counts_env.unwrap_or_else(|| vec![1, 2, 3]);
        let daemon_counts = daemon_counts_env.unwrap_or_else(|| vec![2, 4, 8]);
        let include_gateway = env_bool("P2P_DDNS_IT_MATRIX_GATEWAY");
        let include_partition = env_bool("P2P_DDNS_IT_MATRIX_PARTITION_RECOVER");

        let mut cases = Vec::new();
        for subnets in subnet_counts {
            for daemons in &daemon_counts {
                cases.push(Case {
                    name: case_name(subnets, *daemons, false, false),
                    subnet_count: subnets,
                    daemon_count: *daemons,
                    gateway: false,
                    partition_recover: false,
                    converge_timeout: Duration::from_secs(20),
                    primary_multihome: true,
                    expectation: Expectation::ConvergeAllDaemons,
                });

                if include_gateway && subnets > 1 {
                    cases.push(Case {
                        name: case_name(subnets, *daemons, true, false),
                        subnet_count: subnets,
                        daemon_count: *daemons,
                        gateway: true,
                        partition_recover: false,
                        converge_timeout: Duration::from_secs(20),
                        primary_multihome: true,
                        expectation: Expectation::ConvergeAllDaemons,
                    });
                }

                if include_partition && subnets > 1 {
                    cases.push(Case {
                        name: case_name(subnets, *daemons, false, true),
                        subnet_count: subnets,
                        daemon_count: *daemons,
                        gateway: false,
                        partition_recover: true,
                        converge_timeout: Duration::from_secs(20),
                        primary_multihome: true,
                        expectation: Expectation::ConvergeAllDaemons,
                    });
                }
            }
        }
        cases
    } else {
        vec![
            Case {
                name: "flat-2".to_string(),
                subnet_count: 1,
                daemon_count: 2,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(20),
                primary_multihome: true,
                expectation: Expectation::ConvergeAllDaemons,
            },
            Case {
                name: "flat-4".to_string(),
                subnet_count: 1,
                daemon_count: 4,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(20),
                primary_multihome: true,
                expectation: Expectation::ConvergeAllDaemons,
            },
            Case {
                name: "flat-8".to_string(),
                subnet_count: 1,
                daemon_count: 8,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(20),
                primary_multihome: true,
                expectation: Expectation::ConvergeAllDaemons,
            },
            Case {
                name: "two-subnet-3x3".to_string(),
                subnet_count: 2,
                daemon_count: 6,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(20),
                primary_multihome: true,
                expectation: Expectation::ConvergeAllDaemons,
            },
            Case {
                name: "two-subnet-6x6".to_string(),
                subnet_count: 2,
                daemon_count: 12,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(20),
                primary_multihome: true,
                expectation: Expectation::ConvergeAllDaemons,
            },
            Case {
                name: "two-subnet-gw".to_string(),
                subnet_count: 2,
                daemon_count: 5,
                gateway: true,
                partition_recover: false,
                converge_timeout: Duration::from_secs(20),
                primary_multihome: true,
                expectation: Expectation::ConvergeAllDaemons,
            },
            Case {
                name: "three-subnet-2x2x2".to_string(),
                subnet_count: 3,
                daemon_count: 6,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(20),
                primary_multihome: true,
                expectation: Expectation::ConvergeAllDaemons,
            },
            Case {
                name: "partition-recover".to_string(),
                subnet_count: 2,
                daemon_count: 6,
                gateway: false,
                partition_recover: true,
                converge_timeout: Duration::from_secs(20),
                primary_multihome: true,
                expectation: Expectation::ConvergeAllDaemons,
            },
        ]
    };

    if let Ok(filter) = env::var("P2P_DDNS_IT_CASE") {
        let filter = filter.trim();
        if !filter.is_empty() {
            cases.retain(|c| c.name == filter);
            if cases.is_empty() {
                anyhow::bail!("Unknown P2P_DDNS_IT_CASE={filter}");
            }
        }
    }

    eprintln!("Running {} cases...", cases.len());
    for case in cases {
        run_case(case, &tag).await?;
    }
    Ok(())
}

#[tokio::test]
async fn docker_p2p_expected_failures() -> Result<()> {
    anyhow::ensure!(docker_available(), "docker is not available");

    let tag = ensure_images_built().await?;

    // Primary is only connected to subnet-01. Daemons are round-robin assigned across subnets.
    // Expect: only daemons on subnet-01 become visible; others must remain absent.
    let subnet_count = env_usize("P2P_DDNS_IT_NEGATIVE_SUBNETS")?.unwrap_or(2);
    anyhow::ensure!(
        subnet_count >= 2,
        "P2P_DDNS_IT_NEGATIVE_SUBNETS must be >= 2"
    );
    let daemon_count = env_usize("P2P_DDNS_IT_NEGATIVE_DAEMONS")?.unwrap_or(4);
    anyhow::ensure!(
        daemon_count >= 2,
        "P2P_DDNS_IT_NEGATIVE_DAEMONS must be >= 2"
    );

    let must_include = daemon_names_in_network(daemon_count, subnet_count, 0);
    let must_exclude = (1..=daemon_count)
        .filter(|i| daemon_network_index(*i, subnet_count) != 0)
        .map(daemon_name)
        .collect::<Vec<_>>();

    let name = format!("expected-fail-isolated-primary-s{subnet_count}-d{daemon_count}");

    run_case(
        Case {
            name,
            subnet_count,
            daemon_count,
            gateway: false,
            partition_recover: false,
            converge_timeout: Duration::from_secs(10),
            primary_multihome: false,
            expectation: Expectation::ConvergeSubset {
                must_include,
                must_exclude,
                observe: Duration::from_secs(10),
            },
        },
        &tag,
    )
    .await
}
