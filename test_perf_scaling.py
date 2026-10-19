"""Scaling benchmark: how does the real pipeline behave as the IAM account grows?

Generates synthetic AWS-shaped accounts in memory (no fixture files), then times the same stages as
test_perf_overhead.py. Each "unit" is 1 user + 1 group + 3 roles (~8 entities incl. edges' endpoints).
The first ADMIN_UNITS units have a real escalation chain:
user -> group -> dev role -> ops role -> deploy role (AdministratorAccess).
The admin count is held constant as the account grows, like a real account (a few admins, not 10% of teams).
"""
import math
import time
import tracemalloc
from datetime import datetime, timezone

import pytest

from backend.api.service import ENTRY_TYPES, _scores, val
from backend.ingestion.loader import parse_account
from backend.ingestion.snapshot import build_snapshot
from backend.paths import discover_paths
from contracts import PathOptions

ACCOUNT = "111122223333"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
ADMIN_UNITS = 3                            # constant number of admin chains, independent of account size
UNIT_COUNTS = [10, 50, 200, 500]           # roughly 80 / 400 / 1600 / 4000 entities
ITERATIONS = {10: 5, 50: 3, 200: 2, 500: 1}


def _assume(role_arn: str) -> dict:
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": role_arn}]}


def _role(name: str, assumes: str | None, admin: bool) -> dict:
    return {
        "Path": "/", "RoleName": name, "RoleId": f"AROA{name.upper()}",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
             "Action": "sts:AssumeRole"}]},
        "RolePolicyList": ([{"PolicyName": "Next", "PolicyDocument": _assume(assumes)}] if assumes else []),
        "AttachedManagedPolicies": ([{"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN}]
                                    if admin else []),
    }


def make_account(units: int) -> dict:
    users, groups, roles = [], [], []
    for i in range(units):
        dev, ops, dep = (f"t{i}-dev", f"t{i}-ops", f"t{i}-deploy")
        arn = lambda n: f"arn:aws:iam::{ACCOUNT}:role/{n}"  # noqa: E731
        users.append({"Path": "/", "UserName": f"user{i}", "UserId": f"AIDAUSER{i}",
                      "Arn": f"arn:aws:iam::{ACCOUNT}:user/user{i}", "GroupList": [f"team{i}"],
                      "AttachedManagedPolicies": [], "UserPolicyList": [], "Tags": []})
        groups.append({"Path": "/", "GroupName": f"team{i}", "GroupId": f"AGPATEAM{i}",
                       "Arn": f"arn:aws:iam::{ACCOUNT}:group/team{i}",
                       "GroupPolicyList": [{"PolicyName": "Dev", "PolicyDocument": _assume(arn(dev))}],
                       "AttachedManagedPolicies": []})
        roles += [_role(dev, arn(ops), False), _role(ops, arn(dep), False),
                  _role(dep, None, admin=(i < ADMIN_UNITS))]
    admin = {"PolicyName": "AdministratorAccess", "PolicyId": "ANPAADMINISTRATORACCESS", "Arn": ADMIN_ARN,
             "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": {
                 "Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}
    return {"UserDetailList": users, "GroupDetailList": groups, "RoleDetailList": roles,
            "Policies": [admin]}


def _run(data: dict):
    ms = {}
    t = time.perf_counter(); account = parse_account(data); ms["validate"] = (time.perf_counter() - t) * 1e3
    t = time.perf_counter(); built = build_snapshot(account, created_at=T0)
    ms["snapshot"] = (time.perf_counter() - t) * 1e3
    snap = built.snapshot
    entries = [n.entity_id for n in snap.entities if val(n.entity_type) in ENTRY_TYPES]
    admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
    targets = [e.source_id for e in snap.edges
               if e.target_id in admin and val(e.relation_type) == "has_policy"]
    t = time.perf_counter()
    res = discover_paths(snap, entries, targets, PathOptions(include_blocked=True))
    ms["paths"] = (time.perf_counter() - t) * 1e3
    t = time.perf_counter(); _scores(snap, res.paths, targets); ms["scoring"] = (time.perf_counter() - t) * 1e3
    ms["total"] = sum(ms.values())
    return ms, snap, res


def _median(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2]


def test_generator_matches_expectation():
    """Cheap check that the generated account yields exactly one path per admin unit."""
    _, snap, res = _run(make_account(20))
    assert res.stats.paths_found == ADMIN_UNITS, \
        f"expected {ADMIN_UNITS} escalation paths, got {res.stats.paths_found}"


def test_scaling():
    rows = []
    for units in UNIT_COUNTS:
        print(f"\n[{units} units] running...", flush=True)
        data = make_account(units)
        _run(data)  # warm-up
        runs = [_run(data) for _ in range(ITERATIONS[units])]
        ms = {k: _median([r[0][k] for r in runs]) for k in runs[0][0]}
        _, snap, res = runs[-1]
        tracemalloc.start(); _run(data); _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        rows.append((units, len(snap.entities), len(snap.edges), res.stats.paths_found,
                     res.stats.truncated, ms, peak / 1024 / 1024))
        print(f"[{units} units] done: {ms['total']:.0f} ms total", flush=True)
        assert res.stats.paths_found == min(units, ADMIN_UNITS), "path count off: generator or P3 changed"
        assert not res.stats.truncated

    print("\n entities  edges  paths | validate snapshot   paths  scoring |  total ms | peak MB")
    for units, ents, edges, paths, _, ms, mb in rows:
        print(f"{ents:9d} {edges:6d} {paths:6d} | {ms['validate']:8.1f} {ms['snapshot']:8.1f} "
              f"{ms['paths']:7.1f} {ms['scoring']:8.1f} | {ms['total']:9.1f} | {mb:7.2f}")

    # Empirical growth exponent between the two largest sizes: time ~ entities^k (k=1 linear, k=2 quadratic).
    (_, e1, _, _, _, m1, _), (_, e2, _, _, _, m2, _) = rows[-2], rows[-1]
    for stage in ("snapshot", "paths", "total"):
        k = math.log(m2[stage] / m1[stage]) / math.log(e2 / e1)
        print(f"growth exponent {stage:>8}: {k:.2f}  (entities {e1} -> {e2})")

    assert rows[-1][5]["total"] < 60_000, "largest size took over a minute"  # TODO: tighten once measured