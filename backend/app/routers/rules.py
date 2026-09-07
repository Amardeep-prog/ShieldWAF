from __future__ import annotations

from fastapi import APIRouter

from app.detection.rule_engine import rule_engine

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
def list_rules():
    return {"rules": rule_engine.rules}


@router.post("/reload")
def reload_rules():
    rule_engine.reload()
    return {"status": "reloaded", "count": len(rule_engine.rules)}
