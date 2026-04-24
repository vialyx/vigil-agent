# vigil-agent

Cross-platform desktop agent for continuous application-usage risk scoring.

The agent periodically collects local usage signals, computes a composite risk score, emits structured risk events, persists local history, and exposes live state over IPC.

## What it does

- Collects per-cycle behavior and system signals (`UsageFeatures`)
- Maintains a rolling EMA/variance baseline per feature
- Computes a weighted risk score in range `0..100`
- Assigns risk bands: `Low`, `Medium`, `High`, `Critical`
- Builds and stores a canonical `RiskEvent`
- Optionally batches and ships events to a remote HTTPS endpoint (optional mTLS)
- Exposes latest state via JSON-RPC over Unix socket / Windows named pipe

## Current implementation status

- Linux collector: process, window, USB, category, and anomaly heuristics implemented
- macOS collector: foreground app/window, process inventory, USB inventory, and anomaly heuristics implemented
- Windows collector: foreground window/process, task inventory, USB inventory, and anomaly heuristics implemented

The agent now supports runtime policy updates over IPC, immediate rescoring, platform-aware default paths, retention cleanup for feature snapshots, and safer telemetry batching.

## Architecture at a glance

Main loop (`run_agent`):

1. Collect features
2. Update baseline
3. Score + classify + detect anomalies
4. Build risk event
5. Persist features/event and baseline
6. Update shared IPC state
7. Queue telemetry payload
8. Enforce retention policy

Core modules:

- `src/collector/*`: platform feature collection
- `src/risk/*`: baseline, scoring, event model
- `src/storage/*`: local persistence (`redb`)
- `src/ipc/*`: JSON-RPC state interface
- `src/telemetry/*`: batched remote emitter

## Quick start

### Prerequisites

- Rust stable toolchain
- Platform-specific access/permissions for richer signals (optional)

### Build

```bash
cargo build --release
```

### Run

By default the binary loads `agent.toml` in the current directory.

```bash
cargo run --release
```

Or point to a custom config file:

```bash
VIGIL_CONFIG=/path/to/agent.toml cargo run --release
```

## Configuration

Configuration is TOML (see `agent.toml`). Missing file falls back to defaults.

Top-level sections:

- `[agent]`
	- `scoring_interval_secs` (default: `60`)
	- `baseline_window_days` (default: `30`)
	- `log_level` (`error|warn|info|debug|trace`, default: `info`)
	- `db_path` (platform-aware default when omitted)
	- `ipc_path` (platform-aware default when omitted)
- `[policy]`
	- `risk_weights_override` (per-feature overrides)
	- `off_hours_start` / `off_hours_end`
	- `sensitive_app_categories`
- `[telemetry]`
	- `remote_endpoint` (optional; disabled when absent)
	- `mtls_cert_path` / `mtls_key_path` (optional, both required for mTLS)
	- `emit_interval_secs` (default: `300`)
- `[thresholds]`
	- `medium`, `high`, `critical` (default: `30/55/75`)

## IPC (JSON-RPC 2.0)

The agent exposes newline-delimited JSON-RPC requests/responses over:

- Unix: socket path from `agent.ipc_path`
- Windows: named pipe path from `agent.ipc_path`

Supported methods:

- `get_risk_state` → latest `RiskEvent`
- `get_usage_summary` → latest `UsageFeatures`
- `get_baseline` → current baseline store
- `rescore` → sets a rescore request flag
- `update_policy` → validates and stages a new runtime `policy`, then triggers an immediate rescore

Example request:

```json
{"jsonrpc":"2.0","method":"get_risk_state","id":1}
```

## Telemetry

When `telemetry.remote_endpoint` is configured, queued events are POSTed in batches at `emit_interval_secs`.

- HTTPS via `reqwest` + `rustls`
- Optional mTLS client identity from PEM cert+key
- Failed sends are logged and retried on subsequent flushes

## Local data and retention

- Storage engine: `redb`
- Tables:
	- risk events
	- usage feature snapshots
	- serialized per-device/user baseline
- Old events are purged using `baseline_window_days`

## Development

### Test + lint

```bash
cargo test --all-features
cargo clippy --all-features -- -D warnings
```

### Performance benchmarking

Run local benchmarks:

```bash
cargo bench --bench perf
```

The benchmark suite covers risk scoring and risk-event construction.

## CI benchmark regression gate

Pull requests run a Benchmark Gate workflow that:

1. Benchmarks the PR base branch
2. Benchmarks the PR branch
3. Compares Criterion estimates
4. Fails if regressions exceed threshold

Default threshold: `+15%` slowdown (`REGRESSION_THRESHOLD_PCT` in workflow env).

## License

MIT — see `LICENSE`.

