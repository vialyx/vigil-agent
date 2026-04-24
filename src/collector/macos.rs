use crate::collector::Collector;
use crate::risk::UsageFeatures;
use async_trait::async_trait;

/// macOS collector — uses `NSWorkspace` notifications and related APIs.
///
/// Full implementation requires the `core-foundation` and `objc2` crates plus
/// macOS-specific entitlements (Accessibility API). This skeleton shows the
/// integration points; a production build would call into Objective-C/Swift
/// via FFI.
pub struct MacosCollector;

impl MacosCollector {
    pub fn new() -> Self {
        Self
    }

    /// Placeholder: returns the front-most application name via `osascript`.
    fn foreground_app() -> Option<String> {
        let output = std::process::Command::new("osascript")
            .args([
                "-e",
                "tell application \"System Events\" to get name of first process whose frontmost is true",
            ])
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

    fn off_hours_score() -> f32 {
        use chrono::Timelike;
        let hour = chrono::Local::now().hour();
        if !(8..18).contains(&hour) {
            1.0
        } else {
            0.0
        }
    }
}

impl Default for MacosCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for MacosCollector {
    async fn collect(&self) -> anyhow::Result<UsageFeatures> {
        let _fg_app = Self::foreground_app();
        Ok(UsageFeatures {
            off_hours_activity_score: Self::off_hours_score(),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        "macos"
    }
}
