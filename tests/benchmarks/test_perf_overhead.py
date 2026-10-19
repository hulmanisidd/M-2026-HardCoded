"""Real pipeline benchmark: fixture JSON -> snapshot (P1+P2) -> path discovery (P3) -> scoring (P4).

Calls the same functions backend/api/service.py uses, so the numbers describe what the API does.
No time.sleep, no mocks. If a fixture is missing the test fails instead of silently using fake data.
"""
import json
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.api.service import ENTRY_TYPES, _scores, val  # same entry/target heuristics as the API
from backend.ingestion.loader import load_account_file
from backend.ingestion.snapshot import build_snapshot
from backend.paths import discover_paths
from contracts import PathOptions

ORG = Path(__file__).resolve().parents[2] / "fixtures" / "organization"  # independent of cwd
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)

SCENARIOS = {  # sizes are real fixture sizes; see the printed entity/edge counts
    "small": "scenario_01_passrole_escalation",
    "medium": "scenario_05_enterprise_multihop",
    "large": "scenario_06_privesc_toolkit",
}
WARMUP, ITERATIONS = 5, 50


def _p(sorted_ms, q):
    return sorted_ms[min(len(sorted_ms) - 1, int(q * len(sorted_ms)))]


def _time(fn):
    t0 = time.perf_counter()
    out = fn()
    return (time.perf_counter() - t0) * 1000.0, out


def _stages(path: Path):
    """Run every stage once. Returns ({stage: ms}, snapshot, search result)."""
    ms = {}
    ms["load+validate"], account = _time(lambda: load_account_file(path))
    ms["snapshot"], built = _time(lambda: build_snapshot(account, created_at=T0))
    snap = built.snapshot
    entries = [n.entity_id for n in snap.entities if val(n.entity_type) in ENTRY_TYPES]
    admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
    targets = [e.source_id for e in snap.edges
               if e.target_id in admin and val(e.relation_type) == "has_policy"]
    ms["paths"], res = _time(
        lambda: discover_paths(snap, entries, targets, PathOptions(include_blocked=True)))
    ms["scoring"], _ = _time(lambda: _scores(snap, res.paths, targets))
    ms["total"] = sum(ms.values())
    return ms, snap, res


@pytest.mark.parametrize("scale", list(SCENARIOS))
def test_pipeline_performance(scale):
    path = ORG / f"{SCENARIOS[scale]}.json"
    assert path.exists(), f"fixture missing: {path}"

    # Baseline: just parse the JSON, no validation, no graph. This is a floor, not a competitor.
    base = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        with open(path, encoding="utf-8") as f:
            json.load(f)
        base.append((time.perf_counter() - t0) * 1000.0)

    # First call in this process (imports are already warm, so this is NOT a true cold start).
    first_ms, snap, res = _stages(path)

    for _ in range(WARMUP):
        _stages(path)
    runs = [_stages(path)[0] for _ in range(ITERATIONS)]

    # Memory: separate run, because tracemalloc slows everything down.
    tracemalloc.start()
    _stages(path)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    stats = res.stats
    print(f"\n--- {scale.upper()}  ({path.name}, {path.stat().st_size / 1024:.1f} KB) ---")
    print(f"graph: {len(snap.entities)} entities, {len(snap.edges)} edges | "
          f"paths found: {stats.paths_found}, truncated: {stats.truncated}")
    print(f"first call (in-process): {first_ms['total']:.2f} ms")
    for stage in ("load+validate", "snapshot", "paths", "scoring", "total"):
        xs = sorted(r[stage] for r in runs)
        print(f"{stage:>14}: p50 {_p(xs, 0.50):7.2f} ms | p95 {_p(xs, 0.95):7.2f} ms")
    base.sort()
    print(f"raw json.load only: p50 {_p(base, 0.50):.3f} ms  (pipeline is "
          f"{_p(sorted(r['total'] for r in runs), 0.50) / _p(base, 0.50):.0f}x this)")
    print(f"peak memory (one full run): {peak / 1024 / 1024:.2f} MB")

    # Guards that can actually fail: correctness first, then a loose time/memory budget.
    assert snap.entities and snap.edges, "empty graph"
    assert stats.paths_found > 0, "no attack paths found; pipeline is not exercising P3"
    assert not stats.truncated, f"search truncated: {stats.truncation_reason}"
    totals = sorted(r["total"] for r in runs)
    assert _p(totals, 0.95) < 150.0   # measured p95 max ≈ 41 ms
    assert peak / 1024 / 1024 < 10.0  # measured peak max ≈ 1.3 MB