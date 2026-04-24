use crate::collector::common::{
    browser_title_indicates_private, detect_screen_recording, detect_shadow_it,
    unique_category_count, CollectorSettings,
};
use crate::collector::Collector;
use crate::config::PolicyConfig;
use crate::risk::UsageFeatures;
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HWND, MAX_PATH};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
};

pub struct WindowsCollector {
    settings: Mutex<CollectorSettings>,
    seen_apps: Mutex<HashSet<String>>,
    known_usb_devices: Mutex<HashSet<String>>,
    window_start: Mutex<Instant>,
    last_app: Mutex<Option<String>>,
    switch_count: Mutex<u32>,
    scoring_window_start: Mutex<Instant>,
    last_net_sample: Mutex<Option<(Instant, u64)>>,
}

impl WindowsCollector {
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

    fn foreground_window() -> Option<(String, String)> {
        unsafe {
            let hwnd: HWND = GetForegroundWindow();
            if hwnd.0.is_null() {
                return None;
            }

            let title_len = GetWindowTextLengthW(hwnd);
            let mut title_buffer = vec![0u16; title_len as usize + 1];
            let written = GetWindowTextW(hwnd, &mut title_buffer);
            let title = String::from_utf16_lossy(&title_buffer[..written as usize]);

            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == 0 {
                return Some((title, String::new()));
            }

            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut path_buffer = vec![0u16; MAX_PATH as usize];
            let mut path_len = path_buffer.len() as u32;
            let process_name = if QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(path_buffer.as_mut_ptr()),
                &mut path_len,
            )
            .is_ok()
            {
                let full_path = String::from_utf16_lossy(&path_buffer[..path_len as usize]);
                Path::new(&full_path)
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default()
                    .to_string()
            } else {
                String::new()
            };
            let _ = CloseHandle(handle);

            Some((title, process_name))
        }
    }

    fn running_processes() -> Vec<String> {
        Self::run_command("tasklist", &["/fo", "csv", "/nh"])
            .map(|stdout| {
                stdout
                    .lines()
                    .filter_map(parse_tasklist_name)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn cpu_anomaly_score() -> f32 {
        let output = Self::run_command(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-Counter '\\Processor(_Total)\\% Processor Time').CounterSamples.CookedValue",
            ],
        );

        output
            .and_then(|value| value.lines().last().and_then(|line| line.trim().parse::<f32>().ok()))
            .map(|value| (value / 100.0).clamp(0.0, 1.0))
            .unwrap_or(0.0)
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
        Self::run_command(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-PnpDevice -Class USB -PresentOnly | Select-Object -ExpandProperty InstanceId",
            ],
        )
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

    fn off_hours_score(&self) -> f32 {
        self.settings.lock().unwrap().off_hours_score()
    }
}

fn parse_tasklist_name(line: &str) -> Option<String> {
    let trimmed = line.trim().trim_matches('"');
    let first_field = trimmed.split("\",\"").next()?.trim();
    if first_field.is_empty() {
        return None;
    }

    Some(first_field.trim_end_matches(".exe").to_string())
}

fn read_net_bytes_out() -> u64 {
    WindowsCollector::run_command(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-NetAdapterStatistics | Measure-Object -Property OutboundBytes -Sum).Sum",
        ],
    )
    .and_then(|stdout| stdout.lines().last().and_then(|line| line.trim().parse::<u64>().ok()))
    .unwrap_or(0)
}

impl Default for WindowsCollector {
    fn default() -> Self {
        Self::new(&PolicyConfig::default())
    }
}

#[async_trait]
impl Collector for WindowsCollector {
    async fn collect(&self) -> anyhow::Result<UsageFeatures> {
        let processes = Self::running_processes();
        let (foreground_title, foreground_app) =
            Self::foreground_window().unwrap_or_else(|| (String::new(), String::new()));
        let foreground_app = if foreground_app.is_empty() {
            None
        } else {
            Some(foreground_app)
        };

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
            browser_incognito_usage: browser_title_indicates_private(&foreground_title),
            high_cpu_anomaly_score: Self::cpu_anomaly_score(),
            net_upload_anomaly_score: self.net_upload_anomaly_score(),
            clipboard_access_count: 0,
            screen_recording_active: detect_screen_recording(&processes),
            usb_device_attached,
            new_usb_device,
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        "windows"
    }

    fn update_policy(&self, policy: PolicyConfig) -> anyhow::Result<()> {
        *self.settings.lock().unwrap() = CollectorSettings::from_policy(&policy);
        Ok(())
    }
}
