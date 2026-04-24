use crate::config::TelemetryConfig;
use crate::risk::RiskEvent;
use anyhow::Context;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Remote telemetry emitter.  Batches `RiskEvent`s and POSTs them to the
/// configured SIEM/SOAR endpoint over HTTPS (with optional mTLS).
pub struct TelemetryEmitter {
    config: TelemetryConfig,
    pending: Arc<Mutex<VecDeque<RiskEvent>>>,
    dropped_events: Arc<AtomicU64>,
    client: reqwest::Client,
}

impl TelemetryEmitter {
    /// Create a new emitter.  If mTLS cert/key paths are configured, the
    /// `reqwest` client is built with those credentials.
    pub fn new(config: TelemetryConfig) -> anyhow::Result<Self> {
        let client = build_client(&config)?;
        Ok(Self {
            config,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            dropped_events: Arc::new(AtomicU64::new(0)),
            client,
        })
    }

    /// Enqueue a risk event for the next emission batch.
    pub async fn enqueue(&self, event: RiskEvent) {
        let mut queue = self.pending.lock().await;
        while queue.len() >= self.config.max_pending_events {
            queue.pop_front();
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(event);
    }

    /// Flush all pending events to the remote endpoint.
    ///
    /// Events are transmitted even if the remote endpoint is unreachable —
    /// the error is logged but does not crash the agent.  Successfully
    /// transmitted events are removed from the queue.
    pub async fn flush(&self) {
        let endpoint = match &self.config.remote_endpoint {
            Some(e) => e.clone(),
            None => return, // telemetry disabled
        };

        let payload = {
            let mut queue = self.pending.lock().await;
            if queue.is_empty() {
                return;
            }

            queue.drain(..).collect::<Vec<_>>()
        };

        if payload.is_empty() {
            return;
        }

        match self.client.post(&endpoint).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                let dropped = self.dropped_events.swap(0, Ordering::Relaxed);
                tracing::info!(
                    "Telemetry: emitted {} event(s) → {} (dropped while offline: {})",
                    payload.len(),
                    endpoint,
                    dropped
                );
            }
            Ok(resp) => {
                tracing::warn!(
                    "Telemetry: server returned {status} for {endpoint}",
                    status = resp.status()
                );
                let mut queue = self.pending.lock().await;
                for event in payload.into_iter().rev() {
                    queue.push_front(event);
                }
            }
            Err(e) => {
                tracing::warn!("Telemetry: failed to emit events: {e}");
                let mut queue = self.pending.lock().await;
                for event in payload.into_iter().rev() {
                    queue.push_front(event);
                }
            }
        }
    }

    /// Number of events currently queued.
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }
}

fn build_client(config: &TelemetryConfig) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(std::time::Duration::from_secs(30));

    // mTLS: load client certificate and key if configured.
    if let (Some(cert_path), Some(key_path)) = (&config.mtls_cert_path, &config.mtls_key_path) {
        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("reading mTLS cert {:?}", cert_path))?;
        let key_pem =
            std::fs::read(key_path).with_context(|| format!("reading mTLS key {:?}", key_path))?;
        let identity =
            reqwest::Identity::from_pem(&[cert_pem.as_slice(), key_pem.as_slice()].concat())
                .context("building mTLS identity")?;
        builder = builder.identity(identity);
    }

    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::RiskEvent;

    fn make_event(id: &str) -> RiskEvent {
        RiskEvent {
            schema_version: "1.0".into(),
            event_id: id.to_string(),
            device_id: "dev".into(),
            user_id: "user".into(),
            timestamp_utc: "2026-04-24T12:00:00Z".into(),
            score: 15,
            band: "Low".into(),
            delta_from_baseline: 0,
            top_contributors: vec![],
            anomalies: vec![],
            platform: "Linux".into(),
            os_version: "6.8".into(),
            agent_version: "0.1.0".into(),
        }
    }

    #[tokio::test]
    async fn test_enqueue_and_count() {
        let cfg = TelemetryConfig::default();
        let emitter = TelemetryEmitter::new(cfg).unwrap();
        emitter.enqueue(make_event("e1")).await;
        emitter.enqueue(make_event("e2")).await;
        assert_eq!(emitter.pending_count().await, 2);
    }

    #[tokio::test]
    async fn test_flush_no_endpoint_does_nothing() {
        let cfg = TelemetryConfig {
            remote_endpoint: None,
            ..Default::default()
        };
        let emitter = TelemetryEmitter::new(cfg).unwrap();
        emitter.enqueue(make_event("e1")).await;
        emitter.flush().await;
        // Events remain in queue because there is no endpoint.
        assert_eq!(emitter.pending_count().await, 1);
    }

    #[tokio::test]
    async fn test_queue_is_bounded() {
        let cfg = TelemetryConfig {
            remote_endpoint: None,
            max_pending_events: 2,
            ..Default::default()
        };
        let emitter = TelemetryEmitter::new(cfg).unwrap();
        emitter.enqueue(make_event("e1")).await;
        emitter.enqueue(make_event("e2")).await;
        emitter.enqueue(make_event("e3")).await;
        assert_eq!(emitter.pending_count().await, 2);
    }
}
