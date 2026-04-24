use serde::{Deserialize, Serialize};

/// Identity-provider MFA state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MfaStatus {
    #[default]
    Unknown,
    Enrolled,
    NotEnrolled,
    Bypassed,
}

/// Device compliance posture as reported by MDM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    #[default]
    Unknown,
    Compliant,
    NonCompliant,
    Exempt,
}

/// Risk band derived from the composite score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskBand {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskBand {
    /// Derive a band from a score in [0, 100] using the supplied thresholds.
    pub fn from_score(score: u32, medium: u32, high: u32, critical: u32) -> Self {
        if score >= critical {
            RiskBand::Critical
        } else if score >= high {
            RiskBand::High
        } else if score >= medium {
            RiskBand::Medium
        } else {
            RiskBand::Low
        }
    }
}

impl std::fmt::Display for RiskBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskBand::Low => write!(f, "Low"),
            RiskBand::Medium => write!(f, "Medium"),
            RiskBand::High => write!(f, "High"),
            RiskBand::Critical => write!(f, "Critical"),
        }
    }
}

/// The feature vector collected each scoring cycle (≈ 60 s).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageFeatures {
    // --- Temporal ---
    pub active_app_count_1h: u32,
    pub unique_app_categories: u32,
    /// Fraction of the scoring window that fell outside business hours [0–1].
    pub off_hours_activity_score: f32,

    // --- Behavioral ---
    pub app_switch_rate_per_min: f32,
    /// Fraction of time spent in sensitive-category apps [0–1].
    pub sensitive_app_duration_pct: f32,
    pub shadow_it_app_detected: bool,
    pub browser_incognito_usage: bool,

    // --- Resource ---
    pub high_cpu_anomaly_score: f32,
    pub net_upload_anomaly_score: f32,

    // --- Peripheral / Access ---
    pub clipboard_access_count: u32,
    pub screen_recording_active: bool,
    pub usb_device_attached: bool,
    /// USB device not seen in 30-day baseline.
    pub new_usb_device: bool,

    // --- Identity (optional IdP integration) ---
    pub mfa_status: MfaStatus,
    pub device_compliance: ComplianceStatus,
}

/// A single scored contribution for the top-contributors array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureContribution {
    pub feature: String,
    pub contribution: f32,
    pub value: f32,
}

/// The canonical risk event emitted by the scoring engine.
///
/// Conforms to the JSON schema described in the problem statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvent {
    pub schema_version: String,
    pub event_id: String,
    pub device_id: String,
    pub user_id: String,
    pub timestamp_utc: String,
    /// Composite risk score [0–100].
    pub score: u32,
    pub band: String,
    pub delta_from_baseline: i32,
    pub top_contributors: Vec<FeatureContribution>,
    pub anomalies: Vec<String>,
    pub platform: String,
    pub os_version: String,
    pub agent_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_band_from_score() {
        let (med, high, crit) = (30, 55, 75);
        assert_eq!(RiskBand::from_score(0, med, high, crit), RiskBand::Low);
        assert_eq!(RiskBand::from_score(29, med, high, crit), RiskBand::Low);
        assert_eq!(RiskBand::from_score(30, med, high, crit), RiskBand::Medium);
        assert_eq!(RiskBand::from_score(54, med, high, crit), RiskBand::Medium);
        assert_eq!(RiskBand::from_score(55, med, high, crit), RiskBand::High);
        assert_eq!(RiskBand::from_score(74, med, high, crit), RiskBand::High);
        assert_eq!(
            RiskBand::from_score(75, med, high, crit),
            RiskBand::Critical
        );
        assert_eq!(
            RiskBand::from_score(100, med, high, crit),
            RiskBand::Critical
        );
    }

    #[test]
    fn test_risk_band_display() {
        assert_eq!(RiskBand::Low.to_string(), "Low");
        assert_eq!(RiskBand::Medium.to_string(), "Medium");
        assert_eq!(RiskBand::High.to_string(), "High");
        assert_eq!(RiskBand::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_usage_features_default() {
        let f = UsageFeatures::default();
        assert_eq!(f.active_app_count_1h, 0);
        assert!(!f.screen_recording_active);
        assert_eq!(f.mfa_status, MfaStatus::Unknown);
    }

    #[test]
    fn test_risk_event_serialization() {
        let event = RiskEvent {
            schema_version: "1.0".into(),
            event_id: "test-id".into(),
            device_id: "device-abc".into(),
            user_id: "user@example.com".into(),
            timestamp_utc: "2026-04-24T15:30:00Z".into(),
            score: 67,
            band: "High".into(),
            delta_from_baseline: 24,
            top_contributors: vec![FeatureContribution {
                feature: "sensitive_app_duration_pct".into(),
                contribution: 0.18,
                value: 0.82,
            }],
            anomalies: vec!["screen_recording_active".into()],
            platform: "Linux".into(),
            os_version: "6.8.0".into(),
            agent_version: "0.1.0".into(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let decoded: RiskEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.score, 67);
        assert_eq!(decoded.band, "High");
    }
}
