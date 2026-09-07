"""
Combines the three protection layers into one verdict per request:

  1. RandomForest multi-class content classifier + confidence + top
     contributing features.
  2. IsolationForest anomaly score on BENIGN-trained data (flags
     content that doesn't match any known attack signature but still
     looks statistically unusual -- candidate obfuscated/zero-day payload).
  3. Regex signature rule engine (independent, deterministic).
  4. Rate limiter / repeat-offender auto-block (IP-level, cross-request).

Final action is ALLOW or BLOCK: BLOCK if the IP is already auto-blocked,
OR any critical/high-severity rule matched, OR the ML classifier is
confident (>0.6) about a non-BENIGN class.
"""

from __future__ import annotations

from typing import Any, Dict, List

import numpy as np

from app.detection.features import extract_features
from app.detection.model_store import model_store
from app.detection.preprocessing import features_to_row
from app.detection.rule_engine import rule_engine
from app.detection.schema import FEATURE_COLUMNS, SEVERITY_BY_CLASS
from app.services.rate_limiter import rate_limiter

_SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
BLOCK_SEVERITY_THRESHOLD = "high"
ML_BLOCK_CONFIDENCE = 0.6


def _top_features(feature_row: List[float], clf) -> List[Dict[str, Any]]:
    importances = clf.feature_importances_
    scored = [
        {"feature": name, "value": round(float(v), 3), "importance": round(float(imp), 4)}
        for name, v, imp in zip(FEATURE_COLUMNS, feature_row, importances)
    ]
    scored.sort(key=lambda x: x["importance"] * (1.0 if x["value"] else 0.3), reverse=True)
    return scored[:5]


def inspect_request(request: Dict[str, Any], client_ip: str = "0.0.0.0") -> Dict[str, Any]:
    """Full inspection pipeline. Does NOT itself check/update the rate
    limiter's request-volume counter (call `rate_limiter.record_request`
    separately at the proxy layer per incoming connection) -- this
    function is the content-inspection half."""
    model_store.ensure_loaded()
    clf = model_store.clf
    iforest = model_store.iforest

    already_blocked, block_reason, remaining = rate_limiter.is_blocked(client_ip)

    features = extract_features(request)
    row = features_to_row(features)
    X = np.array([row])

    proba = clf.predict_proba(X)[0]
    classes = clf.classes_
    pred_idx = int(np.argmax(proba))
    predicted_class = classes[pred_idx]
    confidence = float(proba[pred_idx])

    anomaly_raw = float(iforest.decision_function(X)[0])
    is_anomalous = bool(iforest.predict(X)[0] == -1)

    rule_matches = rule_engine.evaluate(request)

    severity = SEVERITY_BY_CLASS.get(predicted_class, "none")
    for m in rule_matches:
        if _SEVERITY_RANK.get(m["severity"], 0) > _SEVERITY_RANK.get(severity, 0):
            severity = m["severity"]
    if is_anomalous and predicted_class == "BENIGN" and severity == "none":
        severity = "low"

    ml_says_block = predicted_class != "BENIGN" and confidence >= ML_BLOCK_CONFIDENCE
    rule_says_block = _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK[BLOCK_SEVERITY_THRESHOLD]
    is_malicious = predicted_class != "BENIGN" or bool(rule_matches)

    action = "BLOCK" if (already_blocked or ml_says_block or rule_says_block) else "ALLOW"

    auto_blocked = False
    auto_block_reason = None
    if action == "BLOCK" and not already_blocked and is_malicious:
        auto_blocked, auto_block_reason = rate_limiter.record_malicious(client_ip)

    result = {
        "client_ip": client_ip,
        "method": request.get("method"),
        "path": request.get("path"),
        "query_string": request.get("query_string"),
        "predicted_class": predicted_class,
        "confidence": round(confidence, 4),
        "class_probabilities": {c: round(float(p), 4) for c, p in zip(classes, proba)},
        "anomaly_score": round(anomaly_raw, 4),
        "is_anomalous": is_anomalous,
        "severity": severity,
        "rule_matches": rule_matches,
        "top_features": _top_features(row, clf),
        "action": action,
        "already_rate_blocked": already_blocked,
        "rate_block_reason": block_reason,
        "auto_blocked_this_request": auto_blocked,
        "auto_block_reason": auto_block_reason,
    }
    return result
