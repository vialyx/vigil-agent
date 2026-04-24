#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def _estimate_value(payload: dict) -> float:
    for metric in ("median", "mean"):
        entry = payload.get(metric)
        if isinstance(entry, dict) and "point_estimate" in entry:
            return float(entry["point_estimate"])
    raise ValueError("No median/mean point_estimate in estimates file")


def load_estimates(root: Path) -> dict[str, float]:
    results: dict[str, float] = {}

    # Criterion typically writes .../<bench>/new/estimates.json
    for p in root.rglob("new/estimates.json"):
        key = str(p.relative_to(root)).replace("/new/estimates.json", "")
        with p.open("r", encoding="utf-8") as f:
            results[key] = _estimate_value(json.load(f))

    # Fallback for layouts that place estimates.json directly.
    if not results:
        for p in root.rglob("estimates.json"):
            key = str(p.relative_to(root)).replace("/estimates.json", "")
            with p.open("r", encoding="utf-8") as f:
                results[key] = _estimate_value(json.load(f))

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Criterion outputs and fail on regressions above threshold."
    )
    parser.add_argument("--base", required=True, help="Base benchmark directory")
    parser.add_argument("--current", required=True, help="Current benchmark directory")
    parser.add_argument(
        "--threshold-pct",
        type=float,
        default=15.0,
        help="Maximum allowed slowdown percentage (default: 15)",
    )
    args = parser.parse_args()

    base = load_estimates(Path(args.base))
    current = load_estimates(Path(args.current))

    if not base:
        print("error: no baseline estimates found", file=sys.stderr)
        return 2
    if not current:
        print("error: no current estimates found", file=sys.stderr)
        return 2

    common = sorted(set(base.keys()) & set(current.keys()))
    if not common:
        print("error: no common benchmark IDs between baseline and current", file=sys.stderr)
        return 2

    print("| Benchmark | Base (ns) | Current (ns) | Delta |")
    print("|---|---:|---:|---:|")

    failures: list[tuple[str, float]] = []

    for key in common:
        b = base[key]
        c = current[key]
        if b <= 0:
            continue
        delta = (c / b - 1.0) * 100.0
        print(f"| {key} | {b:.2f} | {c:.2f} | {delta:+.2f}% |")
        if delta > args.threshold_pct:
            failures.append((key, delta))

    if failures:
        print(
            f"\nPerformance regression detected (threshold: +{args.threshold_pct:.2f}%):",
            file=sys.stderr,
        )
        for key, delta in failures:
            print(f"  - {key}: +{delta:.2f}%", file=sys.stderr)
        return 1

    print(f"\nBenchmark gate passed (threshold: +{args.threshold_pct:.2f}%).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
