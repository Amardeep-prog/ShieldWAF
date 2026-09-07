from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core import db
from app.detection.dataset import sample_requests
from app.detection.engine import inspect_request
from app.detection.schema import CLASSES, FEATURE_COLUMNS

router = APIRouter(prefix="/api/inspect", tags=["inspect"])


class RequestPayload(BaseModel):
    method: str = "GET"
    path: str = "/"
    query_string: str = ""
    body: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    client_ip: str = "203.0.113.1"


class InspectBatchRequest(BaseModel):
    requests: List[RequestPayload] = Field(..., min_length=1)


@router.get("/schema")
def get_schema():
    return {"features": FEATURE_COLUMNS, "classes": CLASSES}


@router.post("")
def inspect(payload: InspectBatchRequest):
    results = []
    for r in payload.requests:
        req = r.model_dump()
        client_ip = req.pop("client_ip")
        result = inspect_request(req, client_ip=client_ip)
        results.append(result)

    class_counts: Dict[str, int] = {}
    for r in results:
        class_counts[r["predicted_class"]] = class_counts.get(r["predicted_class"], 0) + 1

    batch_id = db.new_batch_id()
    db.insert_batch(batch_id, "manual", len(results), class_counts)
    ids = [db.insert_request(batch_id, r) for r in results]
    for r, rid in zip(results, ids):
        r["request_id"] = rid

    return {"batch_id": batch_id, "class_counts": class_counts, "results": results}


@router.get("/sample/{label}")
def get_sample(label: str, n: int = 5):
    label = label.upper()
    if label not in CLASSES:
        raise HTTPException(400, f"Unknown class '{label}'. Valid: {CLASSES}")
    requests = sample_requests(label, n=min(max(n, 1), 30))
    for i, r in enumerate(requests):
        r["client_ip"] = f"198.51.100.{(i % 200) + 1}"
    return {"label": label, "requests": requests}


@router.get("/history")
def history(limit: int = 50):
    return {"batches": db.list_batches(limit=limit)}


@router.get("/{batch_id}")
def get_batch(batch_id: str):
    requests = db.get_batch_requests(batch_id)
    if not requests:
        raise HTTPException(404, "batch not found")
    return {"batch_id": batch_id, "requests": requests}
