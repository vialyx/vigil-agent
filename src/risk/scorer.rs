use crate::config::PolicyConfig;
use crate::risk::baseline::BaselineStore;
use crate::risk::types::{FeatureContribution, RiskBand, RiskEvent, UsageFeatures};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Default feature weights as specified in the problem statement.
pub fn default_weights() -> HashMap<String, f32> {
    let mut m = HashMap::new();
    m.insert("off_hours_activity_score".into(), 0.20);
    m.insert("sensitive_app_duration_pct".into(), 0.18);
    m.insert("net_upload_anomaly_score".into(), 0.15);
    m.insert("shadow_it_app_detected".into(), 0.12);
    m.insert("screen_recording_active".into(), 0.10);
    m.insert("new_usb_device".into(), 0.08);
    m.insert("clipboard_access_count".into(), 0.07);
    m.insert("app_switch_rate_per_min".into(), 0.05);
    m.insert("high_cpu_anomaly_score".into(), 0.05);
    m
}

/// Merge admin weight overrides on top of the defaults.
pub fn merged_weights(policy: &PolicyConfig) -> HashMap<String, f32> {
    let mut weights = default_weights();
    for (k, v) in &policy.risk_weights_override {
        weights.insert(k.clone(), *v);
    }
    weights
}

/// Compute the composite risk score for a single scoring cycle.
///
/// Returns the score in [0, 100] and the individual per-feature contributions.
pub fn compute_score(
    features: &UsageFeatures,
    baseline: &BaselineStore,
    weights: &HashMap<String, f32>,
) -> (u32, Vec<FeatureContribution>, Vec<String>) {
    let mut weighted_sum: f64 = 0.0;
    let mut contributions: Vec<FeatureContribution> = Vec::new();
    let mut anomalies: Vec<String> = Vec::new();

    // Clipboard count is normalised to [0,1] using a cap of 100 accesses.
    let clipboard_norm = (features.clipboard_access_count as f32 / 100.0).min(1.0) as f64;

    let feature_values: Vec<(&str, f64)> = vec![
        (
            "off_hours_activity_score",
            features.off_hours_activity_score as f64,
        ),
        (
            "sensitive_app_duration_pct",
            features.sensitive_app_duration_pct as f64,
        ),
        (
            "net_upload_anomaly_score",
            features.net_upload_anomaly_score as f64,
        ),
        (
            "shadow_it_app_detected",
            features.shadow_it_app_detected as u8 as f64,
        ),
        (
            "screen_recording_active",
            features.screen_recording_active as u8 as f64,
        ),
        ("new_usb_device", features.new_usb_device as u8 as f64),
        ("clipboard_access_count", clipboard_norm),
        (
            "app_switch_rate_per_min",
            features.app_switch_rate_per_min as f64,
        ),
        (
            "high_cpu_anomaly_score",
            features.high_cpu_anomaly_score as f64,
        ),
    ];

    for (name, raw_value) in &feature_values {
        let weight = match weights.get(*name) {
            Some(w) => *w as f64,
            None => continue,
        };

        // Normalise against baseline; falls back to the raw value if no
        // baseline exists yet (first few cycles).
        let normalised = if baseline.baselines.contains_key(*name) {
            baseline.normalize(name, *raw_value)
        } else {
            raw_value.clamp(0.0, 1.0)
        };

        let contribution = weight * normalised;
        weighted_sum += contribution;

        contributions.push(FeatureContribution {
            feature: name.to_string(),
            contribution: contribution as f32,
            value: *raw_value as f32,
        });

        // Flag features that are anomalous (normalised > 0.5).
        if normalised > 0.5 {
            anomalies.push(name.to_string());
        }
    }

    // Boolean flags always trigger regardless of baseline.
    if features.screen_recording_active && !anomalies.contains(&"screen_recording_active".into()) {
        anomalies.push("screen_recording_active".into());
    }
    if features.new_usb_device && !anomalies.contains(&"new_usb_device".into()) {
        anomalies.push("new_usb_device".into());
    }
    if features.shadow_it_app_detected && !anomalies.contains(&"shadow_it_app_detected".into()) {
        anomalies.push("shadow_it_app_detected".into());
    }

    // Sort contributions descending for readability.
    contributions.sort_by(|a, b| b.contribution.partial_cmp(&a.contribution).unwrap());

    let score = (weighted_sum * 100.0).round().min(100.0) as u32;
    (score, contributions, anomalies)
}

/// Build a full `RiskEvent` from a scored cycle.
#[allow(clippy::too_many_arguments)]
pub fn build_risk_event(
    score: u32,
    band: RiskBand,
    delta_from_baseline: i32,
    contributions: Vec<FeatureContribution>,
    anomalies: Vec<String>,
    device_id: &str,
    user_id: &str,
) -> RiskEvent {
    RiskEvent {
        schema_version: "1.0".into(),
        event_id: Uuid::new_v4().to_string(),
        device_id: device_id.to_string(),
        user_id: user_id.to_string(),
        timestamp_utc: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        score,
        band: band.to_string(),
        delta_from_baseline,
        top_contributors: contributions.into_iter().take(5).collect(),
        anomalies,
        platform: std::env::consts::OS.to_string(),
        os_version: os_version(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or("Linux")
            .to_string()
    }

    #[cfg(target_os = "macos")]
    {
        "macOS".to_string()
    }

    #[cfg(target_os = "windows")]
    {
        "Windows".to_string()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "Unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_weights() -> HashMap<String, f32> {
        default_weights()
    }

    #[test]
    fn test_zero_features_gives_zero_score() {
        let features = UsageFeatures::default();
        let baseline = BaselineStore::default();
        let weights = make_weights();
        let (score, _, _) = compute_score(&features, &baseline, &weights);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_all_max_features_gives_high_score() {
        let features = UsageFeatures {
            off_hours_activity_score: 1.0,
            sensitive_app_duration_pct: 1.0,
            net_upload_anomaly_score: 1.0,
            shadow_it_app_detected: true,
            screen_recording_active: true,
            new_usb_device: true,
            clipboard_access_count: 100,
            app_switch_rate_per_min: 1.0,
            high_cpu_anomaly_score: 1.0,
            ..Default::default()
        };
        let baseline = BaselineStore::default();
        let weights = make_weights();
        let (score, _, _) = compute_score(&features, &baseline, &weights);
        assert!(score > 80, "expected high score, got {score}");
    }

    #[test]
    fn test_anomalies_include_boolean_flags() {
        let features = UsageFeatures {
            screen_recording_active: true,
            new_usb_device: true,
            ..Default::default()
        };
        let baseline = BaselineStore::default();
        let weights = make_weights();
        let (_, _, anomalies) = compute_score(&features, &baseline, &weights);
        assert!(anomalies.contains(&"screen_recording_active".to_string()));
        assert!(anomalies.contains(&"new_usb_device".to_string()));
    }

    #[test]
    fn test_weight_override_affects_score() {
        let features = UsageFeatures {
            off_hours_activity_score: 1.0,
            ..Default::default()
        };
        let baseline = BaselineStore::default();

        let mut low_weights = make_weights();
        low_weights.insert("off_hours_activity_score".into(), 0.01);

        let mut high_weights = make_weights();
        high_weights.insert("off_hours_activity_score".into(), 0.99);

        let (score_low, _, _) = compute_score(&features, &baseline, &low_weights);
        let (score_high, _, _) = compute_score(&features, &baseline, &high_weights);
        assert!(
            score_high > score_low,
            "higher weight should yield higher score"
        );
    }

    #[test]
    fn test_build_risk_event() {
        let contribs = vec![FeatureContribution {
            feature: "off_hours_activity_score".into(),
            contribution: 0.20,
            value: 1.0,
        }];
        let event = build_risk_event(
            67,
            RiskBand::High,
            24,
            contribs,
            vec!["screen_recording_active".into()],
            "device-001",
            "user@example.com",
        );
        assert_eq!(event.score, 67);
        assert_eq!(event.band, "High");
        assert_eq!(event.schema_version, "1.0");
        assert!(!event.event_id.is_empty());
    }

    #[test]
    fn test_merged_weights_override() {
        use crate::config::PolicyConfig;
        let mut policy = PolicyConfig::default();
        policy
            .risk_weights_override
            .insert("off_hours_activity_score".into(), 0.50);
        let weights = merged_weights(&policy);
        assert_eq!(weights["off_hours_activity_score"], 0.50);
        // Other weights are unchanged.
        assert_eq!(weights["screen_recording_active"], 0.10);
    }
}
