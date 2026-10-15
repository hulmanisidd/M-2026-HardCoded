import json
import sys
from collections import Counter
from pathlib import Path

LISTS = ("UserPolicyList", "GroupPolicyList", "RolePolicyList")
OWNER = {"UserPolicyList": "UserName", "GroupPolicyList": "GroupName", "RolePolicyList": "RoleName"}
DETAIL = ("UserDetailList", "GroupDetailList", "RoleDetailList")


def inline(doc):
    for section in DETAIL:
        for owner in doc.get(section, []):
            for key in LISTS:
                for pol in owner.get(key, []):
                    yield owner[OWNER[key]] if key in owner or True else "", pol


for name in sys.argv[1:]:
    p = Path(name)
    doc = json.loads(p.read_text(encoding="utf-8"))
    counts = Counter(pol["PolicyName"] for _, pol in inline(doc))
    seen = set()
    for owner, pol in inline(doc):
        n = pol["PolicyName"]
        if counts[n] > 1:
            if n in seen:
                pol["PolicyName"] = f"{n}-{owner}"
                print(f"{p.name}: {n} -> {pol['PolicyName']}")
            seen.add(n)
    p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")