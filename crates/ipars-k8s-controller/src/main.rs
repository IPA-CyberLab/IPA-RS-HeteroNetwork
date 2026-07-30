mod agones;
mod controller;
mod node_reporter;
mod webhook;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use ipars_k8s_controller::LOAD_BALANCER_CLASS;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "ipars-k8s-controller")]
#[command(about = "HeteroNetwork Kubernetes integration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Controller(ControllerArgs),
    NodeReporter(NodeReporterArgs),
}

#[derive(Debug, Clone, Args)]
struct ControllerArgs {
    #[arg(long, default_value = LOAD_BALANCER_CLASS)]
    load_balancer_class: String,
    #[arg(long, default_value_t = 30)]
    reconcile_interval_seconds: u64,
    #[arg(long)]
    agent_pod_namespace: String,
    #[arg(long)]
    agent_pod_label_selector: String,
    #[arg(long, default_value = "0.0.0.0:9443")]
    webhook_bind: SocketAddr,
    #[arg(long)]
    tls_cert_path: PathBuf,
    #[arg(long)]
    tls_key_path: PathBuf,
    #[arg(long, default_value_t = 20_000)]
    agones_port_range_start: u16,
    #[arg(long, default_value_t = 65_535)]
    agones_port_range_end: u16,
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    enable_agones_integration: bool,
}

#[derive(Debug, Clone, Args)]
struct NodeReporterArgs {
    #[arg(long, env = "NODE_NAME")]
    node_name: String,
    #[arg(
        long,
        env = "HETERONETWORK_AGENT_STATE_PATH",
        default_value = "/var/lib/heteronetwork/agent.json"
    )]
    agent_state_path: PathBuf,
    #[arg(
        long,
        env = "HETERONETWORK_AGENT_STATUS_URL",
        default_value = "http://127.0.0.1:9780/v1/status"
    )]
    agent_status_url: String,
    #[arg(long, env = "HETERONETWORK_AGENT_API_BEARER_TOKEN")]
    agent_api_bearer_token: Option<String>,
    #[arg(long, default_value_t = 10)]
    reconcile_interval_seconds: u64,
    #[arg(long, default_value_t = 300)]
    full_reconcile_interval_seconds: u64,
    #[arg(long, default_value_t = 180)]
    public_candidate_max_age_seconds: i64,
    #[arg(long, default_value = "0.0.0.0:19089")]
    health_bind: SocketAddr,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    publish_node_external_ip: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("ipars_k8s_controller=info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Controller(args) => {
            validate_controller_args(&args)?;
            controller::run(args).await
        }
        Command::NodeReporter(args) => {
            validate_node_reporter_args(&args)?;
            node_reporter::run(args).await
        }
    }
}

async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("failed to listen for SIGTERM")?;
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for SIGINT")?;
            }
            _ = terminate.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to listen for shutdown signal")
    }
}

fn validate_controller_args(args: &ControllerArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.load_balancer_class.trim().is_empty(),
        "--load-balancer-class must not be empty"
    );
    anyhow::ensure!(
        (1..=86_400).contains(&args.reconcile_interval_seconds),
        "--reconcile-interval-seconds must be between 1 and 86400"
    );
    anyhow::ensure!(
        !args.agent_pod_namespace.trim().is_empty(),
        "--agent-pod-namespace must not be empty"
    );
    anyhow::ensure!(
        !args.agent_pod_label_selector.trim().is_empty(),
        "--agent-pod-label-selector must not be empty"
    );
    anyhow::ensure!(
        args.agones_port_range_start > 0
            && args.agones_port_range_start <= args.agones_port_range_end,
        "Agones port range must be non-zero and ordered"
    );
    std::fs::metadata(&args.tls_cert_path).with_context(|| {
        format!(
            "TLS certificate {} is not readable",
            args.tls_cert_path.display()
        )
    })?;
    std::fs::metadata(&args.tls_key_path)
        .with_context(|| format!("TLS key {} is not readable", args.tls_key_path.display()))?;
    Ok(())
}

fn validate_node_reporter_args(args: &NodeReporterArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.node_name.trim().is_empty(),
        "--node-name must not be empty"
    );
    anyhow::ensure!(
        (1..=86_400).contains(&args.reconcile_interval_seconds),
        "--reconcile-interval-seconds must be between 1 and 86400"
    );
    anyhow::ensure!(
        (args.reconcile_interval_seconds..=86_400).contains(&args.full_reconcile_interval_seconds),
        "--full-reconcile-interval-seconds must be between --reconcile-interval-seconds and 86400"
    );
    anyhow::ensure!(
        (30..=86_400).contains(&args.public_candidate_max_age_seconds),
        "--public-candidate-max-age-seconds must be between 30 and 86400"
    );
    reqwest::Url::parse(&args.agent_status_url)
        .context("--agent-status-url must be a valid URL")?;
    Ok(())
}
