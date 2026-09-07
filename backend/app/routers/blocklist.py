from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.services.rate_limiter import rate_limiter

router = APIRouter(prefix="/api/blocklist", tags=["blocklist"])


@router.get("")
def get_blocklist():
    return {"blocked_ips": rate_limiter.snapshot()}


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manually blocked by analyst"
    duration_seconds: int | None = None


@router.post("/block")
def block_ip(payload: BlockRequest):
    rate_limiter.manual_block(payload.ip, payload.reason, payload.duration_seconds)
    return {"status": "blocked", "ip": payload.ip}


@router.post("/unblock/{ip}")
def unblock_ip(ip: str):
    rate_limiter.unblock(ip)
    return {"status": "unblocked", "ip": ip}
