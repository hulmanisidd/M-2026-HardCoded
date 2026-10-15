"""HardCoded web demo: FastAPI app.

Design rules (see TEAM_SPLIT.md section 6):
- visitors can only pick from a hardcoded whitelist; no user text ever becomes a file path
- every scenario is computed once at startup; requests are plain dict lookups
- only webapp/static/ is served as files, never the repo root
"""
import logging
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from webapp.analysis import build_graph_data

log = logging.getLogger("webapp")

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures" / "organization"
STATIC = Path(__file__).resolve().parent / "static"

# name -> (label, path). The ONLY way a request reaches a file.
SCENARIOS = {
    name: (label, FIXTURES / f"{name}.json")
    for name, label in [
        ("scenario_01_passrole_escalation", "01 PassRole escalation"),
        ("scenario_02_role_chain", "02 Role chain"),
        ("scenario_03_deny_and_conditions", "03 Deny and conditions"),
        ("scenario_04_policy_self_edit", "04 Policy self-edit"),
        ("scenario_05_enterprise_multihop", "05 Enterprise multi-hop"),
        ("scenario_06_privesc_toolkit", "06 Privesc toolkit"),
        ("scenario_07_exposed_vs_defended", "07 Exposed vs defended"),
        ("scenario_08_access_rerouting", "08 Access rerouting"),
    ]
}
SAMPLES = {"scenarios": [{"name": n, "label": lbl} for n, (lbl, _) in SCENARIOS.items()]}

# Precompute everything once: (name, fail) -> graph dict.
CACHE = {(n, f): build_graph_data(p, fail=f) for n, (_, p) in SCENARIOS.items() for f in (False, True)}

# ---- tiny in-memory rate limiter (per client IP, only for /api) ----
RATE_LIMIT, RATE_WINDOW = 60, 60.0
_hits: dict = {}
_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    # Behind a host's proxy the last X-Forwarded-For entry is the one the proxy itself appended.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _allowed(ip: str) -> bool:
    now = time.monotonic()
    with _lock:
        if len(_hits) > 10_000:  # bound memory
            _hits.clear()
        q = [t for t in _hits.get(ip, []) if now - t < RATE_WINDOW]
        if len(q) >= RATE_LIMIT:
            _hits[ip] = q
            return False
        q.append(now)
        _hits[ip] = q
        return True


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # no public API docs


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.url.path.startswith("/api/") and not _allowed(_client_ip(request)):
        resp = JSONResponse({"detail": "too many requests"}, status_code=429, headers={"Retry-After": "60"})
    else:
        try:
            resp = await call_next(request)
        except Exception:
            log.exception("unhandled error")  # stack trace goes to server logs only
            resp = JSONResponse({"detail": "internal error"}, status_code=500)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = CSP
    return resp


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail if isinstance(exc.detail, str) else "error"}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def bad_request(request: Request, exc: RequestValidationError):
    return JSONResponse({"detail": "invalid request"}, status_code=422)


@app.get("/api/samples")
def samples():
    return SAMPLES


@app.get("/api/analyze/{name}")
def analyze(name: str, fail: bool = False):
    data = CACHE.get((name, fail))
    if data is None:
        return JSONResponse({"detail": "unknown scenario"}, status_code=404)
    return data


@app.get("/", include_in_schema=False)
def index():
    page = STATIC / "index.html"
    if not page.is_file():
        return JSONResponse({"detail": "ui not built yet"}, status_code=503)
    return FileResponse(page, media_type="text/html")


# Only webapp/static/ is exposed (assets). index.html is served by "/" above.
if STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
