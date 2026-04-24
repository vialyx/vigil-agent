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
    let mut policy = config.policy.clone();
    let mut weights = merged_weights(&policy);
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
    let rescore_notify = {
        let st = state.read().await;
        Arc::clone(&st.rescore_notify)
    };

    let thresholds = &config.thresholds;

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = rescore_notify.notified() => {
                tracing::info!("Manual rescore requested");
            }
            signal = tokio::signal::ctrl_c() => {
                if let Err(error) = signal {
                    tracing::warn!("Failed to listen for ctrl-c: {error}");
                }
                tracing::info!("Shutdown signal received, flushing telemetry and exiting");
                emitter.flush().await;
                if let Ok(json) = serde_json::to_string(&baseline) {
                    let _ = db.save_baseline(&baseline_key, &json);
                }
                break;
            }
        }

        let pending_policy = {
            let mut st = state.write().await;
            st.rescore_requested = false;
            st.pending_policy.take()
        };

        if let Some(new_policy) = pending_policy {
            collector.update_policy(new_policy.clone())?;
            weights = merged_weights(&new_policy);
            policy = new_policy;
            tracing::info!("Applied runtime policy update");
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
        if let Err(e) = db.purge_old_features(config.agent.baseline_window_days) {
            tracing::warn!("Feature purge error: {e}");
        }
    }

    let _ = policy;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::Collector;
    use crate::ipc::AgentState;
    use crate::risk::UsageFeatures;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;
    use tokio::sync::RwLock;

    #[derive(Clone)]
    struct MockCollector {
        features: UsageFeatures,
        collect_calls: Arc<AtomicUsize>,
        policy_updates: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Collector for MockCollector {
        async fn collect(&self) -> anyhow::Result<UsageFeatures> {
            self.collect_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.features.clone())
        }

        fn name(&self) -> &'static str {
            "mock"
        }

        fn update_policy(&self, _policy: crate::config::PolicyConfig) -> anyhow::Result<()> {
            self.policy_updates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    async fn wait_for_first_event(state: &SharedState) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.read().await.latest_event.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("agent did not publish first event in time");
    }

    fn test_config(db_path: std::path::PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.agent.db_path = db_path;
        cfg.agent.scoring_interval_secs = 1;
        cfg.telemetry.emit_interval_secs = 3600;
        cfg
    }

    #[tokio::test]
    async fn test_run_agent_updates_state_and_persists_event() {
        let dir = tempdir().expect("tempdir");
        let db = Arc::new(AgentDb::open(&dir.path().join("agent.db")).expect("open db"));
        let state: SharedState = Arc::new(RwLock::new(AgentState::default()));

        let collect_calls = Arc::new(AtomicUsize::new(0));
        let policy_updates = Arc::new(AtomicUsize::new(0));
        let collector = MockCollector {
            features: UsageFeatures {
                off_hours_activity_score: 0.9,
                screen_recording_active: true,
                clipboard_access_count: 10,
                ..Default::default()
            },
            collect_calls: Arc::clone(&collect_calls),
            policy_updates,
        };

        let cfg = test_config(dir.path().join("agent.db"));
        let handle = tokio::spawn(run_agent(
            cfg,
            collector,
            Arc::clone(&db),
            Arc::clone(&state),
        ));

        wait_for_first_event(&state).await;

        let st = state.read().await;
        assert!(st.latest_event.is_some());
        assert!(st.latest_features.is_some());
        drop(st);

        let events = db.load_events().expect("load events");
        assert!(!events.is_empty(), "expected at least one persisted event");
        assert!(collect_calls.load(Ordering::Relaxed) >= 1);

        handle.abort();
    }

    #[tokio::test]
    async fn test_run_agent_applies_pending_policy() {
        let dir = tempdir().expect("tempdir");
        let db = Arc::new(AgentDb::open(&dir.path().join("agent.db")).expect("open db"));
        let state: SharedState = Arc::new(RwLock::new(AgentState::default()));

        let collect_calls = Arc::new(AtomicUsize::new(0));
        let policy_updates = Arc::new(AtomicUsize::new(0));
        let collector = MockCollector {
            features: UsageFeatures::default(),
            collect_calls,
            policy_updates: Arc::clone(&policy_updates),
        };

        {
            let mut st = state.write().await;
            let mut policy = crate::config::PolicyConfig::default();
            policy
                .risk_weights_override
                .insert("off_hours_activity_score".into(), 0.42);
            st.pending_policy = Some(policy);
        }

        let cfg = test_config(dir.path().join("agent.db"));
        let handle = tokio::spawn(run_agent(
            cfg,
            collector,
            Arc::clone(&db),
            Arc::clone(&state),
        ));

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if policy_updates.load(Ordering::Relaxed) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("policy update was not applied in time");

        let st = state.read().await;
        assert!(st.pending_policy.is_none());

        handle.abort();
    }
}
