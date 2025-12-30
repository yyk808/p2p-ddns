use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context as _, Result};
use rand::{Rng as _, distr::Alphanumeric};
use tempfile::TempDir;
use testcontainers::{
    GenericBuildableImage, GenericImage, ImageExt,
    core::{ExecCommand, Mount},
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
    let context_dir = std::fs::canonicalize(&root).context("canonicalize project root")?;

    let base = GenericBuildableImage::new("p2p-ddns-test-base", "latest")
        .with_dockerfile(root.join("tests/integration/nodes/base/Dockerfile"))
        .with_file(context_dir.clone(), ".");
    let _ = base
        .build_image()
        .await
        .context("build docker image: p2p-ddns-test-base:latest")?;

    let primary = GenericBuildableImage::new("p2p-ddns-test-primary", tag)
        .with_dockerfile(root.join("tests/integration/nodes/primary/Dockerfile"))
        .with_file(context_dir.clone(), ".");
    let _ = primary
        .build_image()
        .await
        .with_context(|| format!("build docker image: p2p-ddns-test-primary:{tag}"))?;

    let daemon = GenericBuildableImage::new("p2p-ddns-test-daemon", tag)
        .with_dockerfile(root.join("tests/integration/nodes/daemon/Dockerfile"))
        .with_file(context_dir, ".");
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
        .args(["network", "create", network])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("run docker network create")?;
    if !status.success() {
        anyhow::bail!("docker network create failed: {network}");
    }
    Ok(())
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

async fn wait_for_ticket(shared: &Path, timeout: Duration) -> Result<String> {
    let ticket_path = shared.join("ticket.txt");
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(ticket) = std::fs::read_to_string(&ticket_path) {
            let ticket = ticket.trim().to_string();
            if !ticket.is_empty() {
                return Ok(ticket);
            }
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "primary ticket not available after {}s (expected at {})",
                timeout.as_secs(),
                ticket_path.display()
            );
        }
        sleep(Duration::from_millis(200)).await;
    }
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
            anyhow::bail!(
                "primary membership did not converge after {}s, last output:\n{}",
                timeout.as_secs(),
                last_out
            );
        }
        sleep(Duration::from_secs(2)).await;
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

async fn run_case(case: Case, tag: &str) -> Result<()> {
    let _guard = docker_serial_guard().await;

    let project = format!(
        "p2pddns-it-{}-{}",
        case.name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>(),
        unique_suffix()
    );

    let networks = networks_for(&project, case.subnet_count)?;
    let daemon_networks = daemon_networks_for(&networks)?;
    let _networks = NetworkGuard::new(networks.clone())?;

    let shared = TempDir::new().context("create shared temp dir")?;

    let primary_container_name = format!("{project}-primary");
    let primary = {
        GenericImage::new("p2p-ddns-test-primary", tag)
            .with_container_name(primary_container_name.clone())
            .with_mount(Mount::bind_mount(
                shared.path().to_string_lossy().into_owned(),
                "/shared",
            ))
            .with_env_var("NODE_NAME", "primary-node")
            .with_env_var("P2P_DDNS_LOG_LEVEL", "debug")
            .with_env_var("P2P_DDNS_DOMAIN", "primary-node")
            .with_env_var("P2P_DDNS_BIND_ADDRESS", "0.0.0.0:7777")
            .with_env_var("XDG_RUNTIME_DIR", "/tmp")
            .with_network(networks.first().context("missing primary network")?.clone())
            .start()
            .await
            .context("start primary container")?
    };

    // testcontainers-rs only attaches to one network at creation time; multi-home here.
    for net in networks.iter().skip(1) {
        docker_network_connect(net, primary.id())?;
    }

    let ticket = wait_for_ticket(shared.path(), Duration::from_secs(120)).await?;

    let mut daemons = Vec::with_capacity(case.daemon_count);
    for i in 1..=case.daemon_count {
        let name = format!("daemon-{i:02}");
        let container_name = format!("{project}-{name}");

        let idx = (i - 1) % daemon_networks.len();
        let initial_network = daemon_networks
            .get(idx)
            .context("missing daemon network")?
            .clone();

        let container = GenericImage::new("p2p-ddns-test-daemon", tag)
            .with_container_name(container_name)
            .with_mount(Mount::bind_mount(
                shared.path().to_string_lossy().into_owned(),
                "/shared",
            ))
            .with_env_var("NODE_NAME", name.clone())
            .with_env_var("P2P_DDNS_LOG_LEVEL", "info")
            .with_env_var("P2P_DDNS_DOMAIN", name.clone())
            .with_env_var("P2P_DDNS_BIND_ADDRESS", "0.0.0.0:7777")
            .with_env_var("TICKET_FILE", "/shared/ticket.txt")
            .with_env_var("PRIMARY_HOST", primary_container_name.clone())
            .with_env_var("XDG_RUNTIME_DIR", "/tmp")
            .with_network(initial_network)
            .start()
            .await
            .with_context(|| format!("start daemon container: {name}"))?;

        if case.gateway && case.subnet_count > 1 && i == 1 {
            for net in daemon_networks {
                docker_network_connect(net, container.id())?;
            }
        }
        daemons.push(container);
    }

    let expected = (1..=case.daemon_count)
        .map(|i| format!("daemon-{i:02}"))
        .collect::<Vec<_>>();

    wait_for_primary_converged(&primary, &ticket, &expected, case.converge_timeout).await?;

    if case.partition_recover {
        let subnet_b = networks
            .get(1)
            .context("partition test requires at least 2 networks")?;
        docker_network_disconnect(subnet_b, primary.id())?;
        sleep(Duration::from_secs(10)).await;
        docker_network_connect(subnet_b, primary.id())?;
        wait_for_primary_converged(&primary, &ticket, &expected, case.converge_timeout).await?;
    }

    if env_bool("P2P_DDNS_IT_KEEP_DOCKER") {
        eprintln!(
            "Keeping docker resources for debugging (project prefix: {project}). \
Set P2P_DDNS_IT_KEEP_DOCKER=0 to enable cleanup."
        );
        std::mem::forget(daemons);
        std::mem::forget(primary);
        std::mem::forget(_networks);
        std::mem::forget(shared);
        return Ok(());
    }

    drop(daemons);
    drop(primary);

    if env_bool("P2P_DDNS_IT_KEEP_TMPDIR") {
        std::mem::forget(shared);
    }

    Ok(())
}

#[tokio::test]
async fn docker_p2p_smoke() -> Result<()> {
    if !env_bool("P2P_DDNS_IT") {
        eprintln!("Skipping docker_p2p_smoke: set P2P_DDNS_IT=1 to enable");
        return Ok(());
    }
    if !docker_available() {
        eprintln!("Skipping docker_p2p_smoke: docker is not available");
        return Ok(());
    }

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
            converge_timeout: Duration::from_secs(180),
        },
        &tag,
    )
    .await
}

#[tokio::test]
async fn docker_p2p_matrix() -> Result<()> {
    if !env_bool("P2P_DDNS_IT_MATRIX") {
        eprintln!("Skipping docker_p2p_matrix: set P2P_DDNS_IT_MATRIX=1 to enable");
        return Ok(());
    }
    if !docker_available() {
        eprintln!("Skipping docker_p2p_matrix: docker is not available");
        return Ok(());
    }

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
                    converge_timeout: Duration::from_secs(180),
                });

                if include_gateway && subnets > 1 {
                    cases.push(Case {
                        name: case_name(subnets, *daemons, true, false),
                        subnet_count: subnets,
                        daemon_count: *daemons,
                        gateway: true,
                        partition_recover: false,
                        converge_timeout: Duration::from_secs(180),
                    });
                }

                if include_partition && subnets > 1 {
                    cases.push(Case {
                        name: case_name(subnets, *daemons, false, true),
                        subnet_count: subnets,
                        daemon_count: *daemons,
                        gateway: false,
                        partition_recover: true,
                        converge_timeout: Duration::from_secs(180),
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
                converge_timeout: Duration::from_secs(180),
            },
            Case {
                name: "flat-4".to_string(),
                subnet_count: 1,
                daemon_count: 4,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(180),
            },
            Case {
                name: "flat-8".to_string(),
                subnet_count: 1,
                daemon_count: 8,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(180),
            },
            Case {
                name: "two-subnet-3x3".to_string(),
                subnet_count: 2,
                daemon_count: 6,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(180),
            },
            Case {
                name: "two-subnet-6x6".to_string(),
                subnet_count: 2,
                daemon_count: 12,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(180),
            },
            Case {
                name: "two-subnet-gw".to_string(),
                subnet_count: 2,
                daemon_count: 5,
                gateway: true,
                partition_recover: false,
                converge_timeout: Duration::from_secs(180),
            },
            Case {
                name: "three-subnet-2x2x2".to_string(),
                subnet_count: 3,
                daemon_count: 6,
                gateway: false,
                partition_recover: false,
                converge_timeout: Duration::from_secs(180),
            },
            Case {
                name: "partition-recover".to_string(),
                subnet_count: 2,
                daemon_count: 6,
                gateway: false,
                partition_recover: true,
                converge_timeout: Duration::from_secs(180),
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

    for case in cases {
        run_case(case, &tag).await?;
    }
    Ok(())
}
