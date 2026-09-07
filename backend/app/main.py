from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.core import db
from app.core.config import APP_NAME, APP_VERSION, CORS_ORIGINS
from app.detection.model_store import model_store
from app.proxy.reverse_proxy import handle_proxied_request
from app.routers import blocklist, inspect, logs, misc, model, rules


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    model_store.ensure_loaded()  # trains automatically on first run if no saved model
    yield


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "ShieldWAF -- ML + signature hybrid Web Application Firewall. "
        "Combines a supervised HTTP-request classifier, an unsupervised "
        "anomaly detector, an OWASP-CRS-style regex rule engine, a real "
        "reverse proxy for live inline protection, a Combined-Log-Format "
        "parser for retroactive log analysis, IP rate limiting/auto-block, "
        "and firewall-advisory generation."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(inspect.router)
app.include_router(logs.router)
app.include_router(model.router)
app.include_router(rules.router)
app.include_router(blocklist.router)
app.include_router(misc.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": APP_NAME, "version": APP_VERSION}


# --- Reverse proxy catch-all -------------------------------------------------
# Mounted LAST and matches everything not already claimed by /api/* routes
# above, so this app doubles as both the management API and the live
# inline WAF proxy in front of app.core.config.UPSTREAM_TARGET.

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_catch_all(request: Request, path: str):
    if path.startswith("api/") or path == "api":
        # Should be unreachable (routers above already claim /api/*), but
        # guard explicitly rather than accidentally proxying an API typo.
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "not found"}, status_code=404)
    return await handle_proxied_request(request, path)
