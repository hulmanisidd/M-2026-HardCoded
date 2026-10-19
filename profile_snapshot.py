import cProfile, pstats, sys
sys.path.insert(0, ".")
from test_perf_scaling import make_account, parse_account, build_snapshot, T0

account = parse_account(make_account(100))
cProfile.run("build_snapshot(account, created_at=T0)", "snap.prof")
pstats.Stats("snap.prof").sort_stats("cumulative").print_stats(15)