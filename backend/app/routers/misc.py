from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from app.core import db
from app.services.ai_advisor import explain_request
from app.services.firewall import build_block_advisory
from app.services.report_generator import generate_incident_report

router = APIRouter(prefix="/api", tags=["misc"])


@router.get("/alerts")
def get_alerts(limit: int = 100):
    return {"alerts": db.recent_blocked(limit=limit)}


@router.get("/dashboard/stats")
def dashboard_stats():
    return db.dashboard_stats()


@router.get("/firewall/advisory/{ip}")
def firewall_advisory(ip: str, reason: str = "flagged by ShieldWAF"):
    return build_block_advisory(ip, reason).__dict__


class FeedbackRequest(BaseModel):
    request_id: int
    verdict: str
    note: str = ""


@router.post("/feedback")
def submit_feedback(payload: FeedbackRequest):
    if payload.verdict not in {"true_positive", "false_positive"}:
        raise HTTPException(400, "verdict must be 'true_positive' or 'false_positive'")
    fid = db.insert_feedback(payload.request_id, payload.verdict, payload.note)
    return {"status": "recorded", "feedback_id": fid}


class ExplainRequest(BaseModel):
    request_id: int


@router.post("/ai/explain")
def ai_explain(payload: ExplainRequest):
    req = db.get_request(payload.request_id)
    if not req:
        raise HTTPException(404, "request not found")
    rule_matches = json.loads(req.get("rule_matches") or "[]")
    request_content = {
        "method": req.get("method"), "path": req.get("path"),
        "query_string": req.get("query_string"), "client_ip": req.get("client_ip"),
    }
    result = explain_request(request_content, req["predicted_class"], rule_matches)
    return result


@router.get("/reports/{batch_id}")
def download_report(batch_id: str):
    requests = db.get_batch_requests(batch_id)
    if not requests:
        raise HTTPException(404, "batch not found")

    class_counts: dict = {}
    blocked = []
    for r in requests:
        class_counts[r["predicted_class"]] = class_counts.get(r["predicted_class"], 0) + 1
        if r["action"] == "BLOCK":
            blocked.append({
                "client_ip": r.get("client_ip"),
                "path": r.get("path"),
                "predicted_class": r["predicted_class"],
                "severity": r.get("severity"),
                "rule_matches": json.loads(r.get("rule_matches") or "[]"),
            })

    from app.detection.model_store import model_store
    model_store.ensure_loaded()
    model_summary = {
        "roc_auc_macro_ovr": model_store.metrics.get("roc_auc_macro_ovr"),
        "anomaly_auc": model_store.metrics.get("anomaly_detector", {}).get("benign_vs_attack_auc"),
        "n_train": model_store.metrics.get("n_train"),
    }

    pdf_bytes = generate_incident_report(batch_id, class_counts, blocked, model_summary)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="shieldwaf_report_{batch_id}.pdf"'},
    )
