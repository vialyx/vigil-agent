use crate::collector::common::{
    browser_title_indicates_private, detect_screen_recording, detect_shadow_it,
    unique_category_count, CollectorSettings,
};
use crate::collector::Collector;
use crate::config::PolicyConfig;
use crate::risk::UsageFeatures;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Linux-specific collector that reads process and system information from
/// `/proc` and the X11 `_NET_ACTIVE_WINDOW` property (when available).
pub struct LinuxCollector {
    settings: Mutex<CollectorSettings>,
    /// Applications seen during the current 1-hour window.
    seen_apps: Mutex<HashSet<String>>,
    /// Timestamp of the last window reset.
    window_start: Mutex<Instant>,
    /// Previous foreground app name (for switch-rate tracking).
    last_app: Mutex<Option<String>>,
    /// App switch count within the current scoring window.
    switch_count: Mutex<u32>,
    /// Scoring window start timestamp.
    scoring_window_start: Mutex<Instant>,
    /// Clipboard access counter (approximated via /proc fd inspection).
    clipboard_count: Mutex<u32>,
    /// Previously observed USB device identities.
    known_usb_devices: Mutex<HashSet<String>>,
    /// Last network sample (timestamp, tx bytes) used for rate estimation.
    last_net_sample: Mutex<Option<(Instant, u64)>>,
}

impl LinuxCollector {
    pub fn new(policy: &PolicyConfig) -> Self {
        Self {
            settings: Mutex::new(CollectorSettings::from_policy(policy)),
            seen_apps: Mutex::new(HashSet::new()),
            window_start: Mutex::new(Instant::now()),
            last_app: Mutex::new(None),
            switch_count: Mutex::new(0),
            scoring_window_start: Mutex::new(Instant::now()),
            clipboard_count: Mutex::new(0),
            known_usb_devices: Mutex::new(HashSet::new()),
            last_net_sample: Mutex::new(None),
        }
    }

    /// Read all running process names from `/proc`.
    fn running_processes() -> Vec<String> {
        let mut procs = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Only numeric directories are PIDs.
                if name_str.chars().all(|c| c.is_ascii_digit()) {
                    if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                        procs.push(comm.trim().to_string());
                    }
                }
            }
        }
        procs
    }

    /// Attempt to determine the current foreground application name via
    /// `xdotool` (optional; gracefully degrades if not installed).
    fn foreground_app() -> Option<String> {
        let output = std::process::Command::new("xdotool")
            .args(["getactivewindow", "getwindowname"])
            .output()
            .ok()?;
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        } else {
            None
        }
    }

    fn usb_devices() -> HashSet<String> {
        let mut devices = HashSet::new();
        let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") else {
            return devices;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let vendor = std::fs::read_to_string(path.join("idVendor")).ok();
            let product = std::fs::read_to_string(path.join("idProduct")).ok();
            let serial = std::fs::read_to_string(path.join("serial")).ok();
            let name = std::fs::read_to_string(path.join("product")).ok();

            if vendor.is_none() && product.is_none() && serial.is_none() && name.is_none() {
                continue;
            }

            let identity = format!(
                "{}:{}:{}:{}",
                vendor.as_deref().unwrap_or_default().trim(),
                product.as_deref().unwrap_or_default().trim(),
                serial.as_deref().unwrap_or_default().trim(),
                name.as_deref().unwrap_or_default().trim()
            );
            devices.insert(identity);
        }

        devices
    }

    fn off_hours_score(&self) -> f32 {
        self.settings.lock().unwrap().off_hours_score()
    }

    /// Approximate CPU pressure using `/proc/loadavg` (1-min average / #CPUs).
    fn cpu_anomaly_score() -> f32 {
        let loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
        let load1: f32 = loadavg
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let ncpus = num_cpus();
        (load1 / ncpus as f32).min(1.0)
    }

    /// Approximate net upload anomaly using rolling `/proc/net/dev` samples.
    fn net_upload_anomaly_score(&self) -> f32 {
        let now = Instant::now();
        let tx_bytes = read_net_tx_bytes();
        let mut sample = self.last_net_sample.lock().unwrap();

        let score = if let Some((prev_ts, prev_bytes)) = *sample {
            let elapsed = now.saturating_duration_since(prev_ts).as_secs_f32();
            if elapsed > 0.0 {
                let delta_bytes = tx_bytes.saturating_sub(prev_bytes) as f32;
                let bytes_per_sec = delta_bytes / elapsed;
                // 100 MB/s is treated as the upper bound.
                (bytes_per_sec / 100_000_000.0).clamp(0.0, 1.0)
            } else {
                0.0
            }
        } else {
            0.0
        };

        *sample = Some((now, tx_bytes));
        score
    }
}

fn num_cpus() -> u32 {
    std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count()
        .max(1) as u32
}

fn read_net_tx_bytes() -> u64 {
    let content = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let mut total = 0u64;
    for line in content.lines().skip(2) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Column 9 is tx bytes (0-indexed), after the interface name (col 0).
        if fields.len() >= 10 {
            if let Ok(bytes) = fields[9].parse::<u64>() {
                total += bytes;
            }
        }
    }
    total
}

impl Default for LinuxCollector {
    fn default() -> Self {
        Self::new(&PolicyConfig::default())
    }
}

#[async_trait]
impl Collector for LinuxCollector {
    async fn collect(&self) -> anyhow::Result<UsageFeatures> {
        let procs = Self::running_processes();
        let fg_app = Self::foreground_app();

        // Maintain the 1-hour app window.
        let mut seen = self.seen_apps.lock().unwrap();
        let mut win_start = self.window_start.lock().unwrap();
        if win_start.elapsed() > Duration::from_secs(3600) {
            seen.clear();
            *win_start = Instant::now();
        }
        if let Some(ref app) = fg_app {
            seen.insert(app.clone());
        }
        let active_app_count_1h = seen.len() as u32;
        let unique_app_categories = unique_category_count(seen.iter().map(String::as_str));

        // Track app switches.
        let mut last = self.last_app.lock().unwrap();
        let mut switches = self.switch_count.lock().unwrap();
        let mut sw_start = self.scoring_window_start.lock().unwrap();

        if let Some(ref app) = fg_app {
            if last.as_deref() != Some(app.as_str()) {
                *switches += 1;
                *last = Some(app.clone());
            }
        }
        let elapsed_mins = sw_start.elapsed().as_secs_f32() / 60.0;
        let app_switch_rate_per_min = if elapsed_mins > 0.0 {
            *switches as f32 / elapsed_mins
        } else {
            0.0
        };
        // Reset counters each scoring cycle.
        *switches = 0;
        *sw_start = Instant::now();

        let settings = self.settings.lock().unwrap().clone();
        let screen_recording_active = detect_screen_recording(&procs);
        let usb_devices = Self::usb_devices();
        let usb_device_attached = !usb_devices.is_empty();
        let new_usb_device = {
            let mut known_devices = self.known_usb_devices.lock().unwrap();
            let is_new = !known_devices.is_empty() && usb_devices.iter().any(|device| !known_devices.contains(device));
            if known_devices.is_empty() {
                *known_devices = usb_devices.clone();
                false
            } else {
                known_devices.extend(usb_devices.iter().cloned());
                is_new
            }
        };
        let off_hours_activity_score = self.off_hours_score();
        let high_cpu_anomaly_score = Self::cpu_anomaly_score();
        let net_upload_anomaly_score = self.net_upload_anomaly_score();
        let sensitive_app_duration_pct = fg_app
            .as_deref()
            .map(|app| if settings.is_sensitive_app(app) { 1.0 } else { 0.0 })
            .unwrap_or(0.0);
        let browser_incognito_usage = fg_app
            .as_deref()
            .map(browser_title_indicates_private)
            .unwrap_or(false);

        let clipboard_count = {
            let mut c = self.clipboard_count.lock().unwrap();
            let val = *c;
            *c = 0; // reset each cycle
            val
        };

        Ok(UsageFeatures {
            active_app_count_1h,
            unique_app_categories,
            off_hours_activity_score,
            app_switch_rate_per_min,
            sensitive_app_duration_pct,
            shadow_it_app_detected: detect_shadow_it(&procs),
            browser_incognito_usage,
            high_cpu_anomaly_score,
            net_upload_anomaly_score,
            clipboard_access_count: clipboard_count,
            screen_recording_active,
            usb_device_attached,
            new_usb_device,
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        "linux"
    }

    fn update_policy(&self, policy: PolicyConfig) -> anyhow::Result<()> {
        *self.settings.lock().unwrap() = CollectorSettings::from_policy(&policy);
        Ok(())
    }
}
