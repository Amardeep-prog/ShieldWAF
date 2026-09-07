from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core import db
from app.detection.engine import inspect_request
from app.logs.log_parser import parse_log_text

router = APIRouter(prefix="/api/logs", tags=["logs"])

MAX_LOG_BYTES = 10 * 1024 * 1024  # 10 MB cap for a lab/demo deployment
MAX_LINES = 20000


@router.post("/upload")
async def upload_log(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > MAX_LOG_BYTES:
        raise HTTPException(413, "Log file too large for this demo deployment (10 MB cap)")

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(400, f"Could not decode file as text: {exc}")

    parsed = parse_log_text(text)
    requests = parsed["requests"][:MAX_LINES]
    if not requests:
        raise HTTPException(
            400,
            "No valid Combined Log Format lines found. Expected Apache/Nginx "
            "access.log format, e.g.: "
            '127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
        )

    results = []
    for req in requests:
        client_ip = req.get("client_ip", "0.0.0.0")
        result = inspect_request(req, client_ip=client_ip)
        results.append(result)

    class_counts: Dict[str, int] = {}
    for r in results:
        class_counts[r["predicted_class"]] = class_counts.get(r["predicted_class"], 0) + 1

    batch_id = db.new_batch_id()
    db.insert_batch(batch_id, "log_upload", len(results), class_counts)
    ids = [db.insert_request(batch_id, r) for r in results]
    for r, rid in zip(results, ids):
        r["request_id"] = rid

    return {
        "batch_id": batch_id,
        "lines_parsed": len(requests),
        "lines_failed": parsed["failed_lines"],
        "failed_samples": parsed["failed_samples"],
        "class_counts": class_counts,
        "results": results,
    }
