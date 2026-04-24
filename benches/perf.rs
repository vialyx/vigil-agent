use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use vigil_agent::risk::{
    build_risk_event, compute_score, default_weights, BaselineStore, RiskBand, UsageFeatures,
};

fn make_feature_sets() -> Vec<UsageFeatures> {
    vec![
        UsageFeatures::default(),
        UsageFeatures {
            off_hours_activity_score: 0.3,
            sensitive_app_duration_pct: 0.4,
            app_switch_rate_per_min: 0.6,
            high_cpu_anomaly_score: 0.2,
            net_upload_anomaly_score: 0.5,
            clipboard_access_count: 12,
            ..Default::default()
        },
        UsageFeatures {
            off_hours_activity_score: 1.0,
            sensitive_app_duration_pct: 1.0,
            net_upload_anomaly_score: 1.0,
            shadow_it_app_detected: true,
            screen_recording_active: true,
            new_usb_device: true,
            clipboard_access_count: 100,
            app_switch_rate_per_min: 1.0,
            high_cpu_anomaly_score: 1.0,
            ..Default::default()
        },
    ]
}

fn scoring_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk_scoring");
    let weights = default_weights();

    for (idx, features) in make_feature_sets().into_iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("compute_score_cold", idx),
            &features,
            |b, f| {
                b.iter(|| {
                    let baseline = BaselineStore::default();
                    let _ = compute_score(black_box(f), black_box(&baseline), black_box(&weights));
                });
            },
        );

        let mut trained = BaselineStore::default();
        for _ in 0..500 {
            trained.update_from_features(&features);
        }

        group.bench_with_input(
            BenchmarkId::new("compute_score_warm", idx),
            &features,
            |b, f| {
                b.iter(|| {
                    let _ = compute_score(black_box(f), black_box(&trained), black_box(&weights));
                });
            },
        );
    }

    group.finish();
}

fn event_build_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_build");
    let features = UsageFeatures {
        off_hours_activity_score: 0.85,
        sensitive_app_duration_pct: 0.78,
        net_upload_anomaly_score: 0.66,
        screen_recording_active: true,
        clipboard_access_count: 42,
        ..Default::default()
    };
    let mut baseline = BaselineStore::default();
    for _ in 0..500 {
        baseline.update_from_features(&features);
    }
    let weights = default_weights();

    group.bench_function("build_risk_event_from_scored_cycle", |b| {
        b.iter(|| {
            let (score, contributions, anomalies) = compute_score(
                black_box(&features),
                black_box(&baseline),
                black_box(&weights),
            );
            let _ = build_risk_event(
                black_box(score),
                black_box(RiskBand::High),
                black_box(5),
                black_box(contributions),
                black_box(anomalies),
                black_box("device-001"),
                black_box("user@example.com"),
            );
        });
    });

    group.finish();
}

criterion_group!(benches, scoring_benchmarks, event_build_benchmark);
criterion_main!(benches);
