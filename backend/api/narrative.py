"""Plain-language explanation of a /simulate-remediation result.

Deterministic: only re-words fields the simulation already produced. It never computes
or changes a risk figure, a path or a verdict source. Safe to unit test.

explain_simulation(result) -> dict with:
  verdict        one of GOOD | NEEDS_REVIEW | PARTIAL | INEFFECTIVE | UNVERIFIED
  verdict_label  short human label
  headline       one sentence a non-expert can read
  blocked        list[str]  dangerous routes that are closed
  still_open     list[str]  dangerous routes that remain
  side_effects   list[str]  legitimate access that would break
  kept           list[str]  legitimate access kept through a backup route
  cautions       list[str]  limits of the analysis, in plain words
  approval       str
  next_steps     list[str]
"""
from __future__ import annotations

import re

VERDICT_LABELS = {
    "GOOD": "Looks safe to approve",
    "NEEDS_REVIEW": "Closes the risk but breaks legitimate access",
    "PARTIAL": "Helps, but dangerous routes remain",
    "INEFFECTIVE": "Does not close any dangerous route",
    "UNVERIFIED": "Cannot be trusted yet: search was incomplete",
}

_PRIMARY = re.compile(r"primary route \((?P<route>.+?)\) is cut")
_ALT = re.compile(r"(?P<n>\d+) alternative route\(s\) examined, none passed")


def split_route(route: str) -> list[str]:
    return [p.strip() for p in route.split("->") if p.strip()]


def describe_route(route: str) -> str:
    """'a -> b -> c' becomes 'a can reach c through b'."""
    hops = split_route(route)
    if len(hops) < 2:
        return route
    if len(hops) == 2:
        return f"{hops[0]} can reach {hops[1]} directly"
    return f"{hops[0]} can reach {hops[-1]} through {' then '.join(hops[1:-1])}"


def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def describe_lost(item: dict) -> str:
    if not isinstance(item, dict):
        return str(item)
    who, what = item.get("principal", "?"), item.get("resource", "?")
    reason = str(item.get("reason", "") or "")
    out = f"{who} would lose normal access to {what}."
    m = _PRIMARY.search(reason)
    if m:
        out += f" Their usual route ({m.group('route')}) is cut by this fix."
    a = _ALT.search(reason)
    if a:
        out += f" We tried {a.group('n')} other routes and none were safe."
    elif "could not be verified" in reason:
        out += " A backup route exists but could not be verified as safe."
    if "depth-limited" in reason:
        out += " The search for other routes was limited in depth, so one may exist."
    if not (m or a) and reason and "could not be verified" not in reason:
        out += f" Detail: {reason}"
    return out


def describe_kept(item: dict) -> str:
    if not isinstance(item, dict):
        return str(item)
    who, what = item.get("principal", "?"), item.get("resource", "?")
    out = f"{who} keeps access to {what}"
    if item.get("route"):
        out += f" through a backup route ({item['route']})"
    return out + "."


def _verdict(result: dict) -> str:
    paths = result.get("paths", {})
    removed, residual = paths.get("removed", []), paths.get("residual", [])
    lost = result.get("access", {}).get("lost", [])
    if result.get("search_truncated"):
        return "UNVERIFIED"
    if not removed:
        return "INEFFECTIVE"
    if lost:
        return "NEEDS_REVIEW"
    if residual:
        return "PARTIAL"
    return "GOOD"


def _headline(verdict: str, result: dict) -> str:
    paths = result.get("paths", {})
    before = paths.get("before", 0)
    n_rem, n_res = len(paths.get("removed", [])), len(paths.get("residual", []))
    n_fix = len(result.get("fixes_simulated", []))
    lost = result.get("access", {}).get("lost", [])
    fixes = _plural(n_fix, "fix", "fixes")
    base = f"Applying {fixes} would close {n_rem} of {before} dangerous routes"
    if verdict == "GOOD":
        return base + " and nothing legitimate breaks."
    if verdict == "NEEDS_REVIEW":
        who = sorted({f"{x.get('principal', '?')} to {x.get('resource', '?')}" for x in lost if isinstance(x, dict)})
        extra = f" ({', '.join(who[:2])}{' and more' if len(who) > 2 else ''})" if who else ""
        return base + f", but {_plural(len(lost), 'legitimate access', 'legitimate accesses')} would break{extra}."
    if verdict == "PARTIAL":
        return base + f"; {n_res} still remain open."
    if verdict == "INEFFECTIVE":
        return f"Applying {fixes} would not close any of the {before} dangerous routes."
    return base + ", but the path search was cut short, so this result is a lower bound."


def _next_steps(verdict: str, result: dict) -> list[str]:
    steps = {
        "GOOD": ["Send for human approval; nothing is applied until someone approves."],
        "NEEDS_REVIEW": [
            "Ask the owner of the affected access whether it is still needed.",
            "If it is, pick a narrower fix or add a safe backup route before approving.",
        ],
        "PARTIAL": ["Add fixes for the remaining routes, then simulate again."],
        "INEFFECTIVE": ["Choose different fixes; this one changes nothing about the risk."],
        "UNVERIFIED": ["Re-run with a larger search limit before trusting the result."],
    }.get(verdict, ["Re-run the simulation and review the technical details."])
    if result.get("approval", {}).get("requires_human_approval", True):
        steps = steps + ["Find the owner and approver: this data is missing, so approval cannot be routed yet."]
    return steps


def _explain(result: dict) -> dict:
    paths = result.get("paths", {})
    access = result.get("access", {})
    verdict = _verdict(result)
    blocked = [describe_route(str(p.get("route", ""))) for p in paths.get("removed", []) if isinstance(p, dict)]
    still_open = [describe_route(str(p.get("route", ""))) for p in paths.get("residual", []) if isinstance(p, dict)]
    cautions = []
    if result.get("search_truncated"):
        cautions.append("The path search was cut short. The remaining dangerous routes are a "
                        "minimum, and an empty list does not prove the fix is enough.")
    if not access.get("requirements_loaded"):
        cautions.append("No list of required access exists for this scenario, so side effects "
                        "on legitimate users were not checked. That means unknown, not safe.")
    for w in result.get("warnings", []):
        if "Backup routes assume" in w:
            cautions.append("Backup routes rely on policy data that is still marked as inferred.")
        elif "truncated" in w.lower() and result.get("search_truncated"):
            continue
        elif w and not w.startswith("No access requirements"):
            cautions.append(w)
    approval = result.get("approval", {})
    return {
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS.get(verdict, VERDICT_LABELS["UNVERIFIED"]),
        "headline": _headline(verdict, result),
        "blocked": blocked,
        "still_open": still_open,
        "side_effects": [describe_lost(x) for x in access.get("lost", [])],
        "kept": [describe_kept(x) for x in access.get("preserved_via_backup", [])],
        "cautions": list(dict.fromkeys(cautions)),
        "approval": ("A person must approve this before anything changes. "
                     "Nothing has been or will be applied to AWS by this simulation."
                     if approval.get("requires_human_approval", True) else "No approval required."),
        "next_steps": _next_steps(verdict, result),
    }


def _fallback(result: dict) -> dict:
    """Used only if the normal explanation fails on unexpected data: honest, generic, never a guess."""
    return {
        "verdict": "UNVERIFIED", "verdict_label": VERDICT_LABELS["UNVERIFIED"],
        "headline": "The plain-language summary could not be built for this result. "
                    "Use the technical details and do not treat this as approval.",
        "blocked": [], "still_open": [], "side_effects": [], "kept": [],
        "cautions": ["The result had an unexpected shape, so no verdict was drawn."],
        "approval": "A person must approve this before anything changes. "
                    "Nothing has been or will be applied to AWS by this simulation.",
        "next_steps": ["Check the technical details and report this scenario to the maintainers."],
    }


def explain_simulation(result: dict) -> dict:
    """Never raises: new or odd inputs degrade to a clearly labelled generic explanation."""
    try:
        return _explain(result)
    except Exception:  # noqa: BLE001 - explanation must not break the simulation endpoint
        return _fallback(result)


def to_text(expl: dict) -> str:
    """Flat text version of the explanation."""
    out = [f"{expl['verdict_label']}. {expl['headline']}"]
    for title, key in (("Closed routes", "blocked"), ("Still open", "still_open"),
                       ("Side effects", "side_effects"), ("Access kept", "kept"),
                       ("Cautions", "cautions"), ("Next steps", "next_steps")):
        if expl[key]:
            out.append(title + ":")
            out += [f"- {x}" for x in expl[key]]
    out.append(expl["approval"])
    return "\n".join(out)
