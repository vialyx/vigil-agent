# vigil-agent
Vigil Agent for Continuous Application Usage Risk Scoring

## Performance benchmarking

Run local benchmarks:

- `cargo bench --bench perf`

The benchmark suite covers risk scoring and risk-event construction.

## CI benchmark regression gate

Pull requests run the Benchmark Gate workflow, which:

1. Benchmarks the PR base branch.
2. Benchmarks the PR branch.
3. Compares Criterion estimates.
4. Fails if any benchmark regresses above the configured threshold.

Default threshold: `+15%` slowdown (`REGRESSION_THRESHOLD_PCT` in workflow env).

