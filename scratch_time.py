import sys, time, faulthandler
sys.path.insert(0, "tests/benchmarks")
from test_perf_scaling import (make_account, parse_account, build_snapshot, T0,
                               discover_paths, PathOptions, ENTRY_TYPES, val, _scores)

# If anything runs longer than 20s, dump the exact stack to the terminal and keep going.
faulthandler.dump_traceback_later(20, repeat=True)

for units in (5, 10, 20, 40, 80):
    data = make_account(units)
    print(f"\n--- {units} units ---", flush=True)

    t = time.perf_counter(); account = parse_account(data)
    print(f"validate  {(time.perf_counter()-t)*1e3:9.1f} ms", flush=True)

    t = time.perf_counter(); snap = build_snapshot(account, created_at=T0).snapshot
    print(f"snapshot  {(time.perf_counter()-t)*1e3:9.1f} ms  "
          f"({len(snap.entities)} entities, {len(snap.edges)} edges)", flush=True)

    entries = [n.entity_id for n in snap.entities if val(n.entity_type) in ENTRY_TYPES]
    admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
    targets = [e.source_id for e in snap.edges
               if e.target_id in admin and val(e.relation_type) == "has_policy"]

    t = time.perf_counter()
    res = discover_paths(snap, entries, targets, PathOptions(include_blocked=True))
    print(f"paths     {(time.perf_counter()-t)*1e3:9.1f} ms  "
          f"(found {res.stats.paths_found}, truncated={res.stats.truncated})", flush=True)

    t = time.perf_counter(); _scores(snap, res.paths, targets)
    print(f"scoring   {(time.perf_counter()-t)*1e3:9.1f} ms", flush=True)
    from collections import Counter
    print(Counter(val(e.relation_type) for e in snap.edges), flush=True)