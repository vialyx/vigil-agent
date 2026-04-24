use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use vigil_agent::{
    agent::run_agent,
    collector::PlatformCollector,
    config::Config,
    ipc::{run_unix_server, AgentState},
    storage::AgentDb,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Load config.
    let config_path =
        PathBuf::from(std::env::var("VIGIL_CONFIG").unwrap_or_else(|_| "agent.toml".to_string()));
    let config = Config::load(&config_path)?;

    // 2. Initialise logging.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.agent.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!(
        "vigil-agent starting (version {})",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("Config: {:?}", config_path);

    // 3. Open database.
    let db = Arc::new(AgentDb::open(&config.agent.db_path)?);

    // 4. Build shared IPC state.
    let state = Arc::new(RwLock::new(AgentState::default()));

    // 5. Start IPC server.
    let ipc_path = config.agent.ipc_path.clone();
    let state_ipc = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = run_unix_server(&ipc_path, state_ipc).await {
            tracing::error!("IPC server error: {e}");
        }
    });

    // 6. Run the agent loop (blocking until shutdown signal).
    let collector = PlatformCollector::new();
    run_agent(config, collector, db, state).await?;

    Ok(())
}
