use crate::risk::{RiskEvent, UsageFeatures};
use anyhow::Context;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;

/// Table: event_id (str) → JSON-serialised RiskEvent.
const EVENTS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("risk_events");

/// Table: feature key (str) → JSON-serialised UsageFeatures.
const FEATURES_TABLE: TableDefinition<&str, &str> = TableDefinition::new("usage_features");

/// Table: baseline key (str) → JSON-serialised BaselineStore.
const BASELINE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("baselines");

/// Local time-series database backed by `redb`.
pub struct AgentDb {
    db: Database,
}

impl AgentDb {
    /// Open (or create) the database at `path`.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating DB directory {:?}", parent))?;
        }
        let db = Database::create(path)
            .with_context(|| format!("opening database {:?}", path))?;
        // Ensure tables exist.
        {
            let write_tx = db.begin_write()?;
            write_tx.open_table(EVENTS_TABLE)?;
            write_tx.open_table(FEATURES_TABLE)?;
            write_tx.open_table(BASELINE_TABLE)?;
            write_tx.commit()?;
        }
        Ok(Self { db })
    }

    /// Persist a `RiskEvent`.
    pub fn insert_event(&self, event: &RiskEvent) -> anyhow::Result<()> {
        let json = serde_json::to_string(event)?;
        let write_tx = self.db.begin_write()?;
        {
            let mut table = write_tx.open_table(EVENTS_TABLE)?;
            table.insert(event.event_id.as_str(), json.as_str())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Persist a `UsageFeatures` snapshot keyed by ISO-8601 timestamp.
    pub fn insert_features(&self, timestamp: &str, features: &UsageFeatures) -> anyhow::Result<()> {
        let json = serde_json::to_string(features)?;
        let write_tx = self.db.begin_write()?;
        {
            let mut table = write_tx.open_table(FEATURES_TABLE)?;
            table.insert(timestamp, json.as_str())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Load all stored `RiskEvent`s (ordered by insertion key).
    pub fn load_events(&self) -> anyhow::Result<Vec<RiskEvent>> {
        let read_tx = self.db.begin_read()?;
        let table = read_tx.open_table(EVENTS_TABLE)?;
        let mut events = Vec::new();
        for result in table.iter()? {
            let (_, value) = result?;
            let event: RiskEvent = serde_json::from_str(value.value())?;
            events.push(event);
        }
        Ok(events)
    }

    /// Persist the serialised baseline store.
    pub fn save_baseline(&self, key: &str, json: &str) -> anyhow::Result<()> {
        let write_tx = self.db.begin_write()?;
        {
            let mut table = write_tx.open_table(BASELINE_TABLE)?;
            table.insert(key, json)?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Load the serialised baseline store for the given key.
    pub fn load_baseline(&self, key: &str) -> anyhow::Result<Option<String>> {
        let read_tx = self.db.begin_read()?;
        let table = read_tx.open_table(BASELINE_TABLE)?;
        Ok(table
            .get(key)?
            .map(|v| v.value().to_string()))
    }

    /// Purge events older than `retention_days` days.
    ///
    /// Events are keyed by their UUID, so we rely on the timestamp field for
    /// age comparison.  Events without a parseable timestamp are retained.
    pub fn purge_old_events(&self, retention_days: u32) -> anyhow::Result<usize> {
        use chrono::{Duration, Utc};
        let cutoff = Utc::now() - Duration::days(retention_days as i64);
        let events = self.load_events()?;
        let mut removed = 0usize;

        let write_tx = self.db.begin_write()?;
        {
            let mut table = write_tx.open_table(EVENTS_TABLE)?;
            for event in &events {
                if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&event.timestamp_utc) {
                    if ts < cutoff {
                        table.remove(event.event_id.as_str())?;
                        removed += 1;
                    }
                }
            }
        }
        write_tx.commit()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_event(id: &str, score: u32) -> RiskEvent {
        RiskEvent {
            schema_version: "1.0".into(),
            event_id: id.to_string(),
            device_id: "dev".into(),
            user_id: "user".into(),
            timestamp_utc: "2026-04-24T12:00:00Z".into(),
            score,
            band: "Low".into(),
            delta_from_baseline: 0,
            top_contributors: vec![],
            anomalies: vec![],
            platform: "Linux".into(),
            os_version: "6.8".into(),
            agent_version: "0.1.0".into(),
        }
    }

    #[test]
    fn test_insert_and_load_events() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = AgentDb::open(&db_path).unwrap();

        let e1 = make_event("id-1", 10);
        let e2 = make_event("id-2", 42);
        db.insert_event(&e1).unwrap();
        db.insert_event(&e2).unwrap();

        let loaded = db.load_events().unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_insert_features() {
        let dir = tempdir().unwrap();
        let db = AgentDb::open(&dir.path().join("f.db")).unwrap();
        let f = UsageFeatures {
            active_app_count_1h: 5,
            ..Default::default()
        };
        db.insert_features("2026-04-24T12:00:00Z", &f).unwrap();
    }

    #[test]
    fn test_save_and_load_baseline() {
        let dir = tempdir().unwrap();
        let db = AgentDb::open(&dir.path().join("b.db")).unwrap();
        db.save_baseline("user1", r#"{"baselines":{}}"#).unwrap();
        let result = db.load_baseline("user1").unwrap();
        assert_eq!(result.as_deref(), Some(r#"{"baselines":{}}"#));
    }

    #[test]
    fn test_load_baseline_missing_returns_none() {
        let dir = tempdir().unwrap();
        let db = AgentDb::open(&dir.path().join("m.db")).unwrap();
        let result = db.load_baseline("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_purge_old_events() {
        let dir = tempdir().unwrap();
        let db = AgentDb::open(&dir.path().join("p.db")).unwrap();

        // Insert an old event with a timestamp well in the past.
        let mut old = make_event("old-id", 5);
        old.timestamp_utc = "2020-01-01T00:00:00Z".into();
        db.insert_event(&old).unwrap();

        // Insert a recent event.
        let mut recent = make_event("new-id", 20);
        recent.timestamp_utc = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        db.insert_event(&recent).unwrap();

        let removed = db.purge_old_events(30).unwrap();
        assert_eq!(removed, 1);

        let remaining = db.load_events().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].event_id, "new-id");
    }
}
