use crate::collector::Collector;
use crate::config::Config;
use crate::ipc::SharedState;
use crate::risk::{build_risk_event, compute_score, merged_weights, BaselineStore, RiskBand};
use crate::storage::AgentDb;
use crate::telemetry::TelemetryEmitter;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// Resolve the device identifier (hardware UUID or hostname fallback).
pub fn device_id() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/machine-id")
            .unwrap_or_default()
            .trim()
            .to_string()
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok();
        out.and_then(|o| {
            String::from_utf8(o.stdout).ok().and_then(|s| {
                s.lines()
                    .find(|l| l.contains("IOPlatformUUID"))
                    .and_then(|l| l.split('"').nth(3).map(str::to_string))
            })
        })
        .unwrap_or_else(get_hostname)
    }
    #[cfg(target_os = "windows")]
    {
        get_hostname()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        get_hostname()
    }
}

#[allow(dead_code)]
fn get_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn user_id() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Main agent execution loop.
///
/// Runs until the process is killed or `ctrl_c` is received.
pub async fn run_agent<C: Collector + 'static>(
    config: Config,
    collector: C,
    db: Arc<AgentDb>,
    state: SharedState,
) -> anyhow::Result<()> {
    let weights = merged_weights(&config.policy);
    let dev_id = device_id();
    let usr_id = user_id();

    // Load persisted baseline or start fresh.
    let baseline_key = format!("{dev_id}/{usr_id}");
    let mut baseline: BaselineStore = db
        .load_baseline(&baseline_key)?
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    // Set up telemetry emitter.
    let emitter = Arc::new(TelemetryEmitter::new(config.telemetry.clone())?);
    let emitter_clone = Arc::clone(&emitter);
    let emit_interval = config.telemetry.emit_interval_secs;

    // Spawn telemetry flush task.
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(emit_interval));
        loop {
            interval.tick().await;
            emitter_clone.flush().await;
        }
    });

    let scoring_interval = Duration::from_secs(config.agent.scoring_interval_secs);
    let mut ticker = time::interval(scoring_interval);
    let mut last_score: Option<u32> = None;

    let thresholds = &config.thresholds;

    loop {
        ticker.tick().await;

        // Check for manual rescore request.
        {
            let mut st = state.write().await;
            st.rescore_requested = false;
        }

        // 1. Collect features.
        let features = match collector.collect().await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("Collector error: {e}");
                continue;
            }
        };

        // 2. Update baseline.
        baseline.update_from_features(&features);

        // 3. Score.
        let (score, contributions, anomalies) = compute_score(&features, &baseline, &weights);

        let delta = last_score
            .map(|prev| score as i32 - prev as i32)
            .unwrap_or(0);
        last_score = Some(score);

        let band = RiskBand::from_score(
            score,
            thresholds.medium,
            thresholds.high,
            thresholds.critical,
        );

        tracing::info!(
            score,
            band = %band,
            delta,
            anomalies = ?anomalies,
            "Risk score computed"
        );

        // 4. Build risk event.
        let event = build_risk_event(
            score,
            band,
            delta,
            contributions,
            anomalies,
            &dev_id,
            &usr_id,
        );

        // 5. Persist.
        let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        if let Err(e) = db.insert_event(&event) {
            tracing::warn!("DB insert_event error: {e}");
        }
        if let Err(e) = db.insert_features(&ts, &features) {
            tracing::warn!("DB insert_features error: {e}");
        }

        // 6. Save baseline periodically.
        if let Ok(json) = serde_json::to_string(&baseline) {
            let _ = db.save_baseline(&baseline_key, &json);
        }

        // 7. Update shared state for IPC consumers.
        {
            let mut st = state.write().await;
            st.latest_event = Some(event.clone());
            st.latest_features = Some(features.clone());
            st.baseline = baseline.clone();
        }

        // 8. Enqueue for remote telemetry.
        emitter.enqueue(event).await;

        // 9. Enforce retention policy.
        if let Err(e) = db.purge_old_events(config.agent.baseline_window_days) {
            tracing::warn!("Purge error: {e}");
        }
    }
}
