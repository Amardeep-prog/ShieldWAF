"""
The live-protection component: a real reverse proxy that sits in front
of an upstream web application, inspects every incoming request through
`detection.engine.inspect_request` BEFORE forwarding it, and either:

  - forwards the request to the upstream app and relays its response
    (ALLOW), or
  - returns a 403 block page immediately without ever contacting the
    upstream app (BLOCK).

This mirrors what a real WAF (ModSecurity, AWS WAF, Cloudflare) does
architecturally -- inline inspection in the request path, not
after-the-fact log analysis. It is mounted as a catch-all FastAPI route
in `main.py`.

Every request, allowed or blocked, is persisted via `core.db` and run
through the rate limiter, so the Dashboard/Alerts pages reflect live
traffic exactly the same way they reflect an uploaded log or manual
test batch.
"""

from __future__ import annotations

from typing import Any, Dict

import httpx
from fastapi import Request, Response

from app.core import config, db
from app.detection.engine import inspect_request
from app.services.rate_limiter import rate_limiter

BLOCK_PAGE_HTML = """<!doctype html>
<html><head><title>Blocked</title></head>
<body style="font-family:sans-serif;background:#0b1e33;color:#fff;
text-align:center;padding:80px 20px;">
<h1 style="color:#f87171;">403 &mdash; Request Blocked</h1>
<p>This request was blocked by ShieldWAF for matching a known attack
signature or exceeding the request-rate limit.</p>
<p style="color:#94a3b8;font-size:13px;">Reference: {ref}</p>
</body></html>"""


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


async def handle_proxied_request(request: Request, path: str) -> Response:
    client_ip = _client_ip(request)

    # Rate-limit check happens on every single request, independent of content.
    rate_limited, rate_reason = rate_limiter.record_request(client_ip)

    body_bytes = await request.body()
    try:
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_text = ""

    req_dict: Dict[str, Any] = {
        "method": request.method,
        "path": "/" + path,
        "query_string": str(request.url.query or ""),
        "body": body_text,
        "headers": dict(request.headers),
    }

    if rate_limited:
        result = {
            "client_ip": client_ip, "method": request.method, "path": "/" + path,
            "query_string": req_dict["query_string"], "predicted_class": "RATE_LIMITED",
            "confidence": 1.0, "anomaly_score": None, "is_anomalous": False,
            "severity": "medium", "rule_matches": [], "top_features": [],
            "action": "BLOCK", "already_rate_blocked": True,
            "rate_block_reason": rate_reason, "auto_blocked_this_request": False,
            "auto_block_reason": None,
        }
    else:
        result = inspect_request(req_dict, client_ip=client_ip)

    live_batch_id = "live_proxy_traffic"
    # Ensure a single running "live traffic" batch exists to append to.
    existing = [b for b in db.list_batches(limit=200) if b["batch_id"] == live_batch_id]
    if not existing:
        db.insert_batch(live_batch_id, "live_proxy", 0, {})
    db.insert_request(live_batch_id, result)

    if result["action"] == "BLOCK":
        ref = result.get("rate_block_reason") or (
            result["rule_matches"][0]["id"] if result["rule_matches"] else result["predicted_class"]
        )
        return Response(
            content=BLOCK_PAGE_HTML.format(ref=ref),
            status_code=403,
            media_type="text/html",
        )

    # ALLOW -- forward to the real upstream application.
    upstream_url = config.UPSTREAM_TARGET.rstrip("/") + "/" + path
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream_resp = await client.request(
                method=request.method,
                url=upstream_url,
                params=dict(request.query_params),
                content=body_bytes,
                headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            )
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers={k: v for k, v in upstream_resp.headers.items() if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")},
        )
    except httpx.RequestError as exc:
        return Response(
            content=f"ShieldWAF: upstream application unreachable at {config.UPSTREAM_TARGET} ({exc})",
            status_code=502,
            media_type="text/plain",
        )
