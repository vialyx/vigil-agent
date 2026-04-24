use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Top-level agent configuration, loaded from `agent.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub agent: AgentConfig,
    pub policy: PolicyConfig,
    pub telemetry: TelemetryConfig,
    pub thresholds: ThresholdConfig,
}

impl Config {
    /// Load configuration from a TOML file.  Falls back to defaults if the
    /// file is missing.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let cfg = if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            toml::from_str(&raw)?
        } else {
            tracing::warn!("Config file {:?} not found, using defaults", path);
            Config::default()
        };

        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.thresholds.medium <= self.thresholds.high
                && self.thresholds.high <= self.thresholds.critical,
            "thresholds must satisfy medium <= high <= critical"
        );

        anyhow::ensure!(
            self.agent.scoring_interval_secs > 0,
            "agent.scoring_interval_secs must be greater than zero"
        );

        anyhow::ensure!(
            self.telemetry.emit_interval_secs > 0,
            "telemetry.emit_interval_secs must be greater than zero"
        );

        let cert_configured = self.telemetry.mtls_cert_path.is_some();
        let key_configured = self.telemetry.mtls_key_path.is_some();
        anyhow::ensure!(
            cert_configured == key_configured,
            "telemetry mTLS requires both mtls_cert_path and mtls_key_path"
        );

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// How often (seconds) the risk engine rescores.
    pub scoring_interval_secs: u64,
    /// Rolling baseline window in days.
    pub baseline_window_days: u32,
    /// Log verbosity: "error" | "warn" | "info" | "debug" | "trace".
    pub log_level: String,
    /// Path to the local SQLite database.
    pub db_path: PathBuf,
    /// IPC socket path (Unix) or pipe name (Windows).
    pub ipc_path: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            scoring_interval_secs: 60,
            baseline_window_days: 30,
            log_level: "info".to_string(),
            db_path: default_db_path(),
            ipc_path: default_ipc_path(),
        }
    }
}

fn default_db_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/vigil-agent/agent.db")
    }

    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library/Application Support/vigil-agent/agent.db")
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("VigilAgent")
            .join("agent.db")
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("./agent.db")
    }
}

fn default_ipc_path() -> String {
    #[cfg(target_os = "linux")]
    {
        "/var/run/vigil-agent/agent.sock".to_string()
    }

    #[cfg(target_os = "macos")]
    {
        "/tmp/vigil-agent.sock".to_string()
    }

    #[cfg(target_os = "windows")]
    {
        r"\\.\pipe\vigil-agent".to_string()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "./vigil-agent.sock".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Override weights per feature name.
    pub risk_weights_override: HashMap<String, f32>,
    /// Beginning of off-hours window (HH:MM).
    pub off_hours_start: String,
    /// End of off-hours window (HH:MM).
    pub off_hours_end: String,
    /// App categories considered sensitive.
    pub sensitive_app_categories: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            risk_weights_override: HashMap::new(),
            off_hours_start: "18:00".to_string(),
            off_hours_end: "08:00".to_string(),
            sensitive_app_categories: vec![
                "finance".to_string(),
                "security".to_string(),
                "devtools-remote".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Optional remote endpoint for SIEM/SOAR events.
    pub remote_endpoint: Option<String>,
    /// Path to mTLS client certificate (PEM).
    pub mtls_cert_path: Option<PathBuf>,
    /// Path to mTLS client private key (PEM).
    pub mtls_key_path: Option<PathBuf>,
    /// How often (seconds) to batch-emit events to the remote endpoint.
    pub emit_interval_secs: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            remote_endpoint: None,
            mtls_cert_path: None,
            mtls_key_path: None,
            emit_interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdConfig {
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            medium: 30,
            high: 55,
            critical: 75,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.agent.scoring_interval_secs, 60);
        assert_eq!(cfg.agent.baseline_window_days, 30);
        assert_eq!(cfg.thresholds.medium, 30);
        assert_eq!(cfg.thresholds.high, 55);
        assert_eq!(cfg.thresholds.critical, 75);
    }

    #[test]
    fn test_load_config_from_toml() {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"
[agent]
scoring_interval_secs = 120
baseline_window_days  = 14
log_level = "debug"

[thresholds]
medium   = 35
high     = 60
critical = 80
"#
        )
        .unwrap();

        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.agent.scoring_interval_secs, 120);
        assert_eq!(cfg.agent.baseline_window_days, 14);
        assert_eq!(cfg.thresholds.medium, 35);
        assert_eq!(cfg.thresholds.high, 60);
        assert_eq!(cfg.thresholds.critical, 80);
    }

    #[test]
    fn test_load_missing_file_uses_defaults() {
        let cfg = Config::load(std::path::Path::new("/nonexistent/path/agent.toml")).unwrap();
        assert_eq!(cfg.agent.scoring_interval_secs, 60);
    }

    #[test]
    fn test_invalid_thresholds_fail_validation() {
        let mut cfg = Config::default();
        cfg.thresholds.medium = 80;
        cfg.thresholds.high = 60;
        assert!(cfg.validate().is_err());
    }
}
