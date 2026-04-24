use crate::risk::UsageFeatures;
use async_trait::async_trait;

/// A platform-specific OS event collector.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Collect one feature vector snapshot.
    async fn collect(&self) -> anyhow::Result<UsageFeatures>;

    /// Human-readable name of this collector implementation.
    fn name(&self) -> &'static str;
}

// Re-export the platform-specific implementation.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxCollector as PlatformCollector;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosCollector as PlatformCollector;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsCollector as PlatformCollector;

/// A no-op collector used in unit tests and on unsupported platforms.
pub struct NullCollector;

#[async_trait]
impl Collector for NullCollector {
    async fn collect(&self) -> anyhow::Result<UsageFeatures> {
        Ok(UsageFeatures::default())
    }

    fn name(&self) -> &'static str {
        "null"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_null_collector() {
        let c = NullCollector;
        let features = c.collect().await.unwrap();
        assert_eq!(features.active_app_count_1h, 0);
    }
}
