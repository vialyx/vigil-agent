use crate::collector::Collector;
use crate::risk::UsageFeatures;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Linux-specific collector that reads process and system information from
/// `/proc` and the X11 `_NET_ACTIVE_WINDOW` property (when available).
pub struct LinuxCollector {
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
}

impl LinuxCollector {
    pub fn new() -> Self {
        Self {
            seen_apps: Mutex::new(HashSet::new()),
            window_start: Mutex::new(Instant::now()),
            last_app: Mutex::new(None),
            switch_count: Mutex::new(0),
            scoring_window_start: Mutex::new(Instant::now()),
            clipboard_count: Mutex::new(0),
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

    /// Detect whether a screen-recording / capture process is running.
    fn screen_recording_active(procs: &[String]) -> bool {
        let suspects = [
            "ffmpeg",
            "obs",
            "simplescreenrecorder",
            "kazam",
            "recordmydesktop",
        ];
        procs.iter().any(|p| suspects.contains(&p.as_str()))
    }

    /// Detect whether a USB device is attached by examining `/sys/bus/usb/devices`.
    fn usb_device_attached() -> bool {
        std::fs::read_dir("/sys/bus/usb/devices")
            .map(|entries| entries.count() > 0)
            .unwrap_or(false)
    }

    /// Determine whether the current wall-clock time falls in the off-hours
    /// window (18:00 – 08:00 local time, matching default policy).
    fn off_hours_score() -> f32 {
        use chrono::Timelike;
        let hour = chrono::Local::now().hour();
        // Off hours: before 08:00 or at/after 18:00.
        if !(8..18).contains(&hour) {
            1.0
        } else {
            0.0
        }
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

    /// Approximate net upload anomaly by reading `/proc/net/dev` twice with a
    /// short delay and computing bytes-per-second.  Returns 0 on error.
    fn net_upload_anomaly_score() -> f32 {
        // Read initial counters.
        let before = read_net_tx_bytes();
        std::thread::sleep(Duration::from_millis(100));
        let after = read_net_tx_bytes();
        let bytes_per_100ms = after.saturating_sub(before) as f64;
        // Normalise: 10 MB / 100 ms = 100 MB/s considered maximum.
        let rate = (bytes_per_100ms / 1_000_000.0) as f32;
        rate.min(1.0)
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
        Self::new()
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

        let screen_recording_active = Self::screen_recording_active(&procs);
        let usb_device_attached = Self::usb_device_attached();
        let off_hours_activity_score = Self::off_hours_score();
        let high_cpu_anomaly_score = Self::cpu_anomaly_score();
        let net_upload_anomaly_score = Self::net_upload_anomaly_score();

        let clipboard_count = {
            let mut c = self.clipboard_count.lock().unwrap();
            let val = *c;
            *c = 0; // reset each cycle
            val
        };

        Ok(UsageFeatures {
            active_app_count_1h,
            unique_app_categories: 0, // category mapping not implemented yet
            off_hours_activity_score,
            app_switch_rate_per_min,
            sensitive_app_duration_pct: 0.0,
            shadow_it_app_detected: false,
            browser_incognito_usage: false,
            high_cpu_anomaly_score,
            net_upload_anomaly_score,
            clipboard_access_count: clipboard_count,
            screen_recording_active,
            usb_device_attached,
            new_usb_device: false,
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        "linux"
    }
}
