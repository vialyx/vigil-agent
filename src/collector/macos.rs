use crate::collector::common::{
    browser_title_indicates_private, detect_screen_recording, detect_shadow_it,
    unique_category_count, CollectorSettings,
};
use crate::collector::Collector;
use crate::config::PolicyConfig;
use crate::risk::UsageFeatures;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct MacosCollector {
    settings: Mutex<CollectorSettings>,
    seen_apps: Mutex<HashSet<String>>,
    known_usb_devices: Mutex<HashSet<String>>,
    window_start: Mutex<Instant>,
    last_app: Mutex<Option<String>>,
    switch_count: Mutex<u32>,
    scoring_window_start: Mutex<Instant>,
    last_net_sample: Mutex<Option<(Instant, u64)>>,
}

impl MacosCollector {
    pub fn new(policy: &PolicyConfig) -> Self {
        Self {
            settings: Mutex::new(CollectorSettings::from_policy(policy)),
            seen_apps: Mutex::new(HashSet::new()),
            known_usb_devices: Mutex::new(HashSet::new()),
            window_start: Mutex::new(Instant::now()),
            last_app: Mutex::new(None),
            switch_count: Mutex::new(0),
            scoring_window_start: Mutex::new(Instant::now()),
            last_net_sample: Mutex::new(None),
        }
    }

    fn run_command(program: &str, args: &[&str]) -> Option<String> {
        let output = std::process::Command::new(program).args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8(output.stdout).ok()?;
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn foreground_app() -> Option<String> {
        Self::run_command(
            "osascript",
            &[
                "-e",
                "tell application \"System Events\" to get name of first process whose frontmost is true",
            ],
        )
    }

    fn foreground_window_title() -> Option<String> {
        Self::run_command(
            "osascript",
            &[
                "-e",
                "tell application \"System Events\" to tell (first process whose frontmost is true) to get name of front window",
            ],
        )
    }

    fn running_processes() -> Vec<String> {
        Self::run_command("ps", &["-axo", "comm="])
            .map(|stdout| {
                stdout
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn cpu_anomaly_score() -> f32 {
        let total_cpu: f32 = Self::run_command("ps", &["-A", "-o", "%cpu="])
            .map(|stdout| {
                stdout
                    .lines()
                    .filter_map(|line| line.trim().parse::<f32>().ok())
                    .sum::<f32>()
            })
            .unwrap_or(0.0);

        (total_cpu / 400.0).clamp(0.0, 1.0)
    }

    fn net_upload_anomaly_score(&self) -> f32 {
        let now = Instant::now();
        let tx_bytes = read_net_bytes_out();
        let mut sample = self.last_net_sample.lock().unwrap();

        let score = if let Some((prev_ts, prev_bytes)) = *sample {
            let elapsed = now.saturating_duration_since(prev_ts).as_secs_f32();
            if elapsed > 0.0 {
                let delta_bytes = tx_bytes.saturating_sub(prev_bytes) as f32;
                let bytes_per_sec = delta_bytes / elapsed;
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

    fn usb_devices() -> HashSet<String> {
        let mut devices = HashSet::new();
        let Some(stdout) = Self::run_command("system_profiler", &["SPUSBDataType", "-json"])
        else {
            return devices;
        };

        let Ok(json) = serde_json::from_str::<Value>(&stdout) else {
            return devices;
        };

        collect_usb_entries(&json, &mut devices);
        devices
    }

    fn off_hours_score(&self) -> f32 {
        self.settings.lock().unwrap().off_hours_score()
    }
}

fn collect_usb_entries(value: &Value, devices: &mut HashSet<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_usb_entries(item, devices);
            }
        }
        Value::Object(map) => {
            let device_name = map
                .get("_name")
                .and_then(Value::as_str)
                .or_else(|| map.get("device_name").and_then(Value::as_str));
            let vendor_id = map
                .get("vendor_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let product_id = map
                .get("product_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let serial = map
                .get("serial_num")
                .and_then(Value::as_str)
                .unwrap_or_default();

            if let Some(name) = device_name {
                devices.insert(format!("{vendor_id}:{product_id}:{serial}:{name}"));
            }

            for child in map.values() {
                collect_usb_entries(child, devices);
            }
        }
        _ => {}
    }
}

fn read_net_bytes_out() -> u64 {
    let Some(stdout) = MacosCollector::run_command("netstat", &["-ibn"]) else {
        return 0;
    };

    stdout
        .lines()
        .skip(1)
        .filter_map(|line| {
            let columns: Vec<&str> = line.split_whitespace().collect();
            if columns.len() < 10 || columns[0] == "Name" {
                return None;
            }

            columns
                .last()
                .and_then(|value| value.parse::<u64>().ok())
        })
        .sum()
}

impl Default for MacosCollector {
    fn default() -> Self {
        Self::new(&PolicyConfig::default())
    }
}

#[async_trait]
impl Collector for MacosCollector {
    async fn collect(&self) -> anyhow::Result<UsageFeatures> {
        let processes = Self::running_processes();
        let foreground_app = Self::foreground_app();
        let foreground_title = Self::foreground_window_title();

        let mut seen = self.seen_apps.lock().unwrap();
        let mut window_start = self.window_start.lock().unwrap();
        if window_start.elapsed() > Duration::from_secs(3600) {
            seen.clear();
            *window_start = Instant::now();
        }
        if let Some(app) = &foreground_app {
            seen.insert(app.clone());
        }

        let active_app_count_1h = seen.len() as u32;
        let unique_app_categories = unique_category_count(seen.iter().map(String::as_str));

        let mut last_app = self.last_app.lock().unwrap();
        let mut switch_count = self.switch_count.lock().unwrap();
        let mut scoring_window_start = self.scoring_window_start.lock().unwrap();
        if let Some(app) = &foreground_app {
            if last_app.as_deref() != Some(app.as_str()) {
                *switch_count += 1;
                *last_app = Some(app.clone());
            }
        }
        let elapsed_minutes = scoring_window_start.elapsed().as_secs_f32() / 60.0;
        let app_switch_rate_per_min = if elapsed_minutes > 0.0 {
            *switch_count as f32 / elapsed_minutes
        } else {
            0.0
        };
        *switch_count = 0;
        *scoring_window_start = Instant::now();

        let settings = self.settings.lock().unwrap().clone();
        let screen_recording_active = detect_screen_recording(&processes);
        let usb_devices = Self::usb_devices();
        let usb_device_attached = !usb_devices.is_empty();
        let new_usb_device = {
            let mut known = self.known_usb_devices.lock().unwrap();
            let is_new = !known.is_empty() && usb_devices.iter().any(|device| !known.contains(device));
            if known.is_empty() {
                *known = usb_devices.clone();
                false
            } else {
                known.extend(usb_devices.iter().cloned());
                is_new
            }
        };

        Ok(UsageFeatures {
            active_app_count_1h,
            unique_app_categories,
            off_hours_activity_score: self.off_hours_score(),
            app_switch_rate_per_min,
            sensitive_app_duration_pct: foreground_app
                .as_deref()
                .map(|app| if settings.is_sensitive_app(app) { 1.0 } else { 0.0 })
                .unwrap_or(0.0),
            shadow_it_app_detected: detect_shadow_it(&processes),
            browser_incognito_usage: foreground_title
                .as_deref()
                .map(browser_title_indicates_private)
                .unwrap_or(false),
            high_cpu_anomaly_score: Self::cpu_anomaly_score(),
            net_upload_anomaly_score: self.net_upload_anomaly_score(),
            clipboard_access_count: 0,
            screen_recording_active,
            usb_device_attached,
            new_usb_device,
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        "macos"
    }

    fn update_policy(&self, policy: PolicyConfig) -> anyhow::Result<()> {
        *self.settings.lock().unwrap() = CollectorSettings::from_policy(&policy);
        Ok(())
    }
}
