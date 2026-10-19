import sys, json
sys.path.insert(0, ".")
from test_perf_scaling import make_account, parse_account
from backend.ingestion.edges import build_edges

r = build_edges(parse_account(make_account(30)))
out = {"edges": [e.edge_id for e in r.edges], "warnings": list(r.warnings)}
if len(sys.argv) > 1 and sys.argv[1] == "check":
    assert out == json.load(open("baseline.json")), "EDGES CHANGED"
    print("identical to baseline")
else:
    json.dump(out, open("baseline.json", "w")); print("baseline saved")