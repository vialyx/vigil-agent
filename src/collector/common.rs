use crate::config::PolicyConfig;
use chrono::Timelike;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct CollectorSettings {
    off_hours_start_minute: u16,
    off_hours_end_minute: u16,
    sensitive_categories: HashSet<String>,
}

impl CollectorSettings {
    pub fn from_policy(policy: &PolicyConfig) -> Self {
        Self {
            off_hours_start_minute: parse_hhmm(&policy.off_hours_start, 18 * 60),
            off_hours_end_minute: parse_hhmm(&policy.off_hours_end, 8 * 60),
            sensitive_categories: policy
                .sensitive_app_categories
                .iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
        }
    }

    pub fn off_hours_score(&self) -> f32 {
        let now = chrono::Local::now();
        let minute_of_day = (now.hour() * 60 + now.minute()) as u16;
        let in_window = if self.off_hours_start_minute == self.off_hours_end_minute {
            true
        } else if self.off_hours_start_minute < self.off_hours_end_minute {
            (self.off_hours_start_minute..self.off_hours_end_minute).contains(&minute_of_day)
        } else {
            minute_of_day >= self.off_hours_start_minute
                || minute_of_day < self.off_hours_end_minute
        };

        if in_window { 1.0 } else { 0.0 }
    }

    pub fn is_sensitive_app(&self, app_name: &str) -> bool {
        categorize_app(app_name)
            .map(|category| self.sensitive_categories.contains(category))
            .unwrap_or(false)
    }
}

fn parse_hhmm(value: &str, fallback: u16) -> u16 {
    let mut parts = value.split(':');
    let hour = parts.next().and_then(|part| part.parse::<u16>().ok());
    let minute = parts.next().and_then(|part| part.parse::<u16>().ok());
    match (hour, minute) {
        (Some(hour), Some(minute)) if hour < 24 && minute < 60 => hour * 60 + minute,
        _ => fallback,
    }
}

pub fn normalize_name(name: &str) -> String {
    name.trim()
        .trim_matches('\0')
        .trim()
        .to_ascii_lowercase()
        .replace(".app", "")
        .replace(".exe", "")
}

pub fn categorize_app(name: &str) -> Option<&'static str> {
    let normalized = normalize_name(name);
    let value = normalized.as_str();

    if contains_any(value, &["chrome", "firefox", "safari", "edge", "browser"]) {
        Some("browser")
    } else if contains_any(
        value,
        &["zoom", "slack", "teams", "discord", "skype", "meet"],
    ) {
        Some("communication")
    } else if contains_any(
        value,
        &[
            "bank",
            "wallet",
            "trading",
            "coinbase",
            "metamask",
            "finance",
            "quickbooks",
        ],
    ) {
        Some("finance")
    } else if contains_any(
        value,
        &[
            "1password",
            "keychain",
            "keeper",
            "vault",
            "security",
            "authy",
            "okta",
        ],
    ) {
        Some("security")
    } else if contains_any(
        value,
        &[
            "teamviewer",
            "anydesk",
            "rustdesk",
            "ngrok",
            "tailscale",
            "openvpn",
            "wireguard",
            "remote",
        ],
    ) {
        Some("devtools-remote")
    } else if contains_any(value, &["dropbox", "mega", "resilio", "onedrive", "drive"]) {
        Some("storage-sync")
    } else if contains_any(value, &["code", "xcode", "terminal", "iterm", "powershell"]) {
        Some("developer-tools")
    } else {
        None
    }
}

pub fn unique_category_count<'a>(apps: impl IntoIterator<Item = &'a str>) -> u32 {
    let mut categories = HashSet::new();
    for app in apps {
        if let Some(category) = categorize_app(app) {
            categories.insert(category);
        }
    }
    categories.len() as u32
}

pub fn detect_shadow_it(processes: &[String]) -> bool {
    processes.iter().any(|process| {
        let normalized = normalize_name(process);
        contains_any(
            normalized.as_str(),
            &[
                "teamviewer",
                "anydesk",
                "rustdesk",
                "ngrok",
                "tailscale",
                "tor",
                "wireguard",
                "openvpn",
                "dropbox",
                "mega",
                "resilio",
            ],
        )
    })
}

pub fn detect_screen_recording(processes: &[String]) -> bool {
    processes.iter().any(|process| {
        let normalized = normalize_name(process);
        contains_any(
            normalized.as_str(),
            &[
                "obs",
                "ffmpeg",
                "simplescreenrecorder",
                "kazam",
                "recordmydesktop",
                "quicktime",
                "screenflick",
                "camtasia",
                "screencapture",
            ],
        )
    })
}

pub fn browser_title_indicates_private(title: &str) -> bool {
    let normalized = normalize_name(title);
    contains_any(
        normalized.as_str(),
        &["incognito", "inprivate", "private browsing", "private window"],
    )
}

fn contains_any(value: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| value.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_mapping() {
        assert_eq!(categorize_app("Google Chrome"), Some("browser"));
        assert_eq!(categorize_app("AnyDesk"), Some("devtools-remote"));
        assert_eq!(categorize_app("1Password"), Some("security"));
    }

    #[test]
    fn test_private_title_detection() {
        assert!(browser_title_indicates_private("Chrome - Incognito"));
        assert!(browser_title_indicates_private("Edge - InPrivate"));
        assert!(!browser_title_indicates_private("Regular browsing"));
    }

    #[test]
    fn test_off_hours_parsing() {
        let policy = PolicyConfig {
            off_hours_start: "22:30".into(),
            off_hours_end: "07:15".into(),
            ..Default::default()
        };
        let settings = CollectorSettings::from_policy(&policy);
        assert!(settings.off_hours_start_minute > settings.off_hours_end_minute);
    }
}