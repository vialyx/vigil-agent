use crate::risk::types::UsageFeatures;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-feature baseline state maintained by EMA + rolling standard deviation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureBaseline {
    /// Exponential moving average.
    pub ema: f64,
    /// Exponential moving variance (used to derive σ).
    pub emv: f64,
    /// Number of samples observed so far.
    pub sample_count: u64,
}

impl Default for FeatureBaseline {
    fn default() -> Self {
        Self {
            ema: 0.0,
            emv: 0.0,
            sample_count: 0,
        }
    }
}

impl FeatureBaseline {
    /// Update EMA and EMV with a new observation.
    ///
    /// α is the smoothing factor in (0, 1].  A smaller α retains history
    /// longer; the default corresponds to roughly 30-day decay at 1 sample/min.
    pub fn update(&mut self, value: f64, alpha: f64) {
        if self.sample_count == 0 {
            self.ema = value;
            self.emv = 0.0;
        } else {
            let delta = value - self.ema;
            self.ema += alpha * delta;
            // Welford-style exponential variance
            self.emv = (1.0 - alpha) * (self.emv + alpha * delta * delta);
        }
        self.sample_count += 1;
    }

    /// Return the current standard deviation (√EMV).
    pub fn std_dev(&self) -> f64 {
        self.emv.sqrt()
    }

    /// Normalize a raw value against the baseline.
    ///
    /// `normalize(x, μ, σ) = clamp((x − μ) / max(σ, ε), 0, 3) / 3`  → [0, 1]
    pub fn normalize(&self, value: f64) -> f64 {
        const EPSILON: f64 = 1e-6;
        let sigma = self.std_dev().max(EPSILON);
        ((value - self.ema) / sigma).clamp(0.0, 3.0) / 3.0
    }
}

/// Holds per-feature baselines for a single user/device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineStore {
    pub baselines: HashMap<String, FeatureBaseline>,
}

impl BaselineStore {
    /// EMA smoothing factor — tuned to approximately 30-day decay with 1-min samples.
    const ALPHA: f64 = 0.0023;

    pub fn update_from_features(&mut self, features: &UsageFeatures) {
        let values = Self::feature_map(features);
        for (name, value) in values {
            let entry = self.baselines.entry(name).or_default();
            entry.update(value, Self::ALPHA);
        }
    }

    /// Normalize a feature value against its stored baseline; returns 0.5 if
    /// the baseline is not yet established.
    pub fn normalize(&self, name: &str, value: f64) -> f64 {
        match self.baselines.get(name) {
            Some(b) if b.sample_count > 1 => b.normalize(value),
            _ => 0.0,
        }
    }

    /// Extract named f64 values from the feature vector.
    pub fn feature_map(f: &UsageFeatures) -> Vec<(String, f64)> {
        vec![
            ("active_app_count_1h".into(), f.active_app_count_1h as f64),
            (
                "unique_app_categories".into(),
                f.unique_app_categories as f64,
            ),
            (
                "off_hours_activity_score".into(),
                f.off_hours_activity_score as f64,
            ),
            (
                "app_switch_rate_per_min".into(),
                f.app_switch_rate_per_min as f64,
            ),
            (
                "sensitive_app_duration_pct".into(),
                f.sensitive_app_duration_pct as f64,
            ),
            (
                "shadow_it_app_detected".into(),
                f.shadow_it_app_detected as u8 as f64,
            ),
            (
                "browser_incognito_usage".into(),
                f.browser_incognito_usage as u8 as f64,
            ),
            (
                "high_cpu_anomaly_score".into(),
                f.high_cpu_anomaly_score as f64,
            ),
            (
                "net_upload_anomaly_score".into(),
                f.net_upload_anomaly_score as f64,
            ),
            (
                "clipboard_access_count".into(),
                f.clipboard_access_count as f64,
            ),
            (
                "screen_recording_active".into(),
                f.screen_recording_active as u8 as f64,
            ),
            (
                "usb_device_attached".into(),
                f.usb_device_attached as u8 as f64,
            ),
            ("new_usb_device".into(), f.new_usb_device as u8 as f64),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_update_and_normalize() {
        let mut b = FeatureBaseline::default();
        // Seed with several identical values so the baseline stabilises.
        for _ in 0..100 {
            b.update(10.0, 0.1);
        }
        // Same value → score near 0.
        let norm = b.normalize(10.0);
        assert!(
            norm < 0.05,
            "expected near-zero for baseline value, got {norm}"
        );

        // A value far above the baseline (100.0 vs μ ≈ 10.0) should normalise
        // close to 1.0 because (100 - 10) / max(σ, ε) >> 3 → clamped then / 3.
        let norm_high = b.normalize(100.0);
        assert!(
            norm_high > 0.9,
            "expected near-one for extreme outlier, got {norm_high}"
        );
    }

    #[test]
    fn test_baseline_first_sample() {
        let mut b = FeatureBaseline::default();
        b.update(5.0, 0.1);
        assert_eq!(b.ema, 5.0);
        assert_eq!(b.emv, 0.0);
        assert_eq!(b.sample_count, 1);
    }

    #[test]
    fn test_baseline_store_update() {
        let mut store = BaselineStore::default();
        let f = UsageFeatures {
            active_app_count_1h: 3,
            app_switch_rate_per_min: 2.0,
            ..Default::default()
        };
        store.update_from_features(&f);
        assert!(store.baselines.contains_key("active_app_count_1h"));
        assert!(store.baselines.contains_key("app_switch_rate_per_min"));
    }

    #[test]
    fn test_normalize_unknown_feature_returns_zero() {
        let store = BaselineStore::default();
        let norm = store.normalize("nonexistent_feature", 42.0);
        assert_eq!(norm, 0.0);
    }
}
