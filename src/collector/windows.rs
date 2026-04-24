use crate::collector::Collector;
use crate::risk::UsageFeatures;
use async_trait::async_trait;

/// Windows collector — integrates with `GetForegroundWindow`,
/// `GetWindowText`, WMI process traces, and related Win32 APIs.
///
/// Full implementation uses the `windows` crate with unsafe FFI.  This
/// skeleton demonstrates the structure; the unsafe blocks are left as
/// documented integration points.
pub struct WindowsCollector;

impl WindowsCollector {
    pub fn new() -> Self {
        Self
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

#[async_trait]
impl Collector for WindowsCollector {
    async fn collect(&self) -> anyhow::Result<UsageFeatures> {
        // TODO: call GetForegroundWindow / GetWindowText, enumerate processes
        // via NtQuerySystemInformation, read clipboard listener state, etc.
        Ok(UsageFeatures {
            off_hours_activity_score: Self::off_hours_score(),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        "windows"
    }
}
