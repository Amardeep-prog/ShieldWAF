from __future__ import annotations

from fastapi import APIRouter

from app.detection.model_store import model_store

router = APIRouter(prefix="/api/model", tags=["model"])


@router.get("/metrics")
def get_metrics():
    model_store.ensure_loaded()
    return model_store.metrics


@router.post("/retrain")
def retrain(n_per_class: int = 700):
    metrics = model_store.retrain(n_per_class=n_per_class)
    return {"status": "retrained", "metrics": metrics}
