"""Live before/after snapshot timing table.

"before" = brute-force mode (every principal tested against every role, no per-action filtering),
"after"  = the indexed code. Both are run right now on the same machine and the edge IDs are compared,
so the table is measured live rather than typed in.

Run from the repo root:  python demo_speedup.py
"""
import statistics
import sys
import time

sys.path.insert(0, ".")
from test_perf_scaling import make_account, parse_account, build_snapshot, T0  # noqa: E402
from backend.ingestion.edges import _Builder, _Identity, build_edges  # noqa: E402

SIZES = [5, 40, 80]      # units; add 200 for a bigger (slower) row
RUNS = 3                 # median of this many timed runs

_orig_candidates = _Builder._assume_candidates
_orig_for_action = _Identity.for_action


def set_brute_force(on: bool) -> None:
    if on:
        _Builder._assume_candidates = lambda self, principal, identity: self.account.roles
        _Identity.for_action = lambda self, action: self
    else:
        _Builder._assume_candidates = _orig_candidates
        _Identity.for_action = _orig_for_action


def measure(account, brute_force: bool):
    set_brute_force(brute_force)
    try:
        build_snapshot(account, created_at=T0)  # warm-up
        times, snap = [], None
        for _ in range(RUNS):
            t = time.perf_counter()
            snap = build_snapshot(account, created_at=T0).snapshot
            times.append((time.perf_counter() - t) * 1e3)
        edge_ids = [e.edge_id for e in build_edges(account).edges]
        return statistics.median(times), len(snap.entities), edge_ids
    finally:
        set_brute_force(False)


def main() -> None:
    print(f"\nSnapshot build time, median of {RUNS} runs (same machine, same account)\n")
    header = f"{'units (entities)':>18} | {'before':>12} | {'after':>10} | {'speedup':>8} | edges identical"
    print(header)
    print("-" * len(header))
    for units in SIZES:
        account = parse_account(make_account(units))
        before_ms, entities, before_ids = measure(account, brute_force=True)
        after_ms, _, after_ids = measure(account, brute_force=False)
        same = before_ids == after_ids
        print(f"{f'{units} ({entities})':>18} | {before_ms:9.1f} ms | {after_ms:7.1f} ms | "
              f"{before_ms / after_ms:7.1f}x | {'yes' if same else 'NO - MISMATCH'}", flush=True)
        if not same:
            sys.exit("Edge sets differ: the optimization changed the output.")
    print()


if __name__ == "__main__":
    main()