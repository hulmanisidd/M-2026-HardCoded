"""Optional LLM polish for the plain-language explanation. OFF unless configured.

The deterministic text from narrative.py is always the source of truth. The model may only
re-phrase it. The output is rejected (and the deterministic text is returned) if it is empty,
adds a name or number that was not in the input, or the call fails for any reason.

Enable with env vars: EXPLAIN_LLM=1 and ANTHROPIC_API_KEY=...  (EXPLAIN_LLM_MODEL optional).
Never used for decisions, scoring or verdicts.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

DEFAULT_MODEL = "claude-sonnet-4-6"
SYSTEM = (
    "You rewrite a cloud-security simulation summary for a non-technical manager. "
    "Use short plain sentences. Do NOT add, remove or change any fact, name, number or "
    "recommendation. Keep every account/role name exactly as written. "
    "Keep the sections: verdict, what is closed, what is still open, side effects, next steps. "
    "Do not claim anything is safe unless the input says so."
)
_TOKEN = re.compile(r"[A-Za-z][\w-]*[\w]|\d+(?:\.\d+)?")


def enabled() -> bool:
    return os.environ.get("EXPLAIN_LLM") == "1" and bool(os.environ.get("ANTHROPIC_API_KEY"))


def _numbers_and_names(text: str) -> set[str]:
    # hyphenated identifiers (ana-analyst) and numbers are the facts that must not appear from nowhere
    return {t.lower() for t in _TOKEN.findall(text) if "-" in t or t[0].isdigit()}


def is_faithful(source: str, rewritten: str) -> bool:
    if not rewritten.strip():
        return False
    return _numbers_and_names(rewritten) <= _numbers_and_names(source)


def rewrite(source_text: str, timeout: float = 15.0) -> tuple[str, str]:
    """Returns (text, origin) where origin is 'llm' or 'template'."""
    if not enabled():
        return source_text, "template"
    body = json.dumps({
        "model": os.environ.get("EXPLAIN_LLM_MODEL", DEFAULT_MODEL), "max_tokens": 1000,
        "system": SYSTEM, "messages": [{"role": "user", "content": source_text}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body, method="POST",
        headers={"content-type": "application/json", "anthropic-version": "2023-06-01",
                 "x-api-key": os.environ["ANTHROPIC_API_KEY"]})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    except Exception:
        return source_text, "template"
    return (text, "llm") if is_faithful(source_text, text) else (source_text, "template")
