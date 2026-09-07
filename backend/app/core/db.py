"""
Plain sqlite3 persistence -- no ORM -- for inspected requests, batches
(a single log-upload or classify-batch run), and analyst feedback.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from app.core.config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    source TEXT NOT NULL,          -- 'live_proxy' | 'log_upload' | 'manual' | 'sample'
    n_requests INTEGER NOT NULL,
    class_counts TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    client_ip TEXT,
    method TEXT,
    path TEXT,
    query_string TEXT,
    predicted_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    anomaly_score REAL,
    is_anomalous INTEGER NOT NULL DEFAULT 0,
    severity TEXT,
    action TEXT NOT NULL,          -- 'ALLOW' | 'BLOCK'
    rule_matches TEXT,
    top_features TEXT,
    created_at REAL NOT NULL,
    FOREIGN KEY(batch_id) REFERENCES batches(batch_id)
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    analyst_verdict TEXT NOT NULL,
    note TEXT,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_requests_batch ON requests(batch_id);
CREATE INDEX IF NOT EXISTS idx_requests_class ON requests(predicted_class);
CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(client_ip);
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def new_batch_id() -> str:
    return f"batch_{uuid.uuid4().hex[:12]}"


def insert_batch(batch_id: str, source: str, n_requests: int, class_counts: Dict[str, int]) -> None:
    with db_session() as conn:
        conn.execute(
            "INSERT INTO batches (batch_id, created_at, source, n_requests, class_counts) VALUES (?,?,?,?,?)",
            (batch_id, time.time(), source, n_requests, json.dumps(class_counts)),
        )


def insert_request(batch_id: str, result: Dict[str, Any]) -> int:
    with db_session() as conn:
        cur = conn.execute(
            """INSERT INTO requests
               (batch_id, client_ip, method, path, query_string, predicted_class,
                confidence, anomaly_score, is_anomalous, severity, action,
                rule_matches, top_features, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                batch_id,
                result.get("client_ip"),
                result.get("method"),
                result.get("path"),
                result.get("query_string"),
                result["predicted_class"],
                result["confidence"],
                result.get("anomaly_score"),
                int(result.get("is_anomalous", False)),
                result.get("severity"),
                result.get("action", "ALLOW"),
                json.dumps(result.get("rule_matches", [])),
                json.dumps(result.get("top_features", [])),
                time.time(),
            ),
        )
        return cur.lastrowid


def list_batches(limit: int = 50) -> List[Dict[str, Any]]:
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM batches ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_batch_requests(batch_id: str) -> List[Dict[str, Any]]:
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM requests WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_request(request_id: int) -> Optional[Dict[str, Any]]:
    with db_session() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        return dict(row) if row else None


def recent_blocked(limit: int = 100) -> List[Dict[str, Any]]:
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM requests WHERE action='BLOCK' ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def insert_feedback(request_id: int, verdict: str, note: str = "") -> int:
    with db_session() as conn:
        cur = conn.execute(
            "INSERT INTO feedback (request_id, analyst_verdict, note, created_at) VALUES (?,?,?,?)",
            (request_id, verdict, note, time.time()),
        )
        return cur.lastrowid


def dashboard_stats() -> Dict[str, Any]:
    with db_session() as conn:
        total_requests = conn.execute("SELECT COUNT(*) c FROM requests").fetchone()["c"]
        total_batches = conn.execute("SELECT COUNT(*) c FROM batches").fetchone()["c"]
        blocked = conn.execute("SELECT COUNT(*) c FROM requests WHERE action='BLOCK'").fetchone()["c"]
        by_class = conn.execute(
            "SELECT predicted_class, COUNT(*) c FROM requests GROUP BY predicted_class"
        ).fetchall()
        by_severity = conn.execute(
            "SELECT severity, COUNT(*) c FROM requests WHERE severity IS NOT NULL GROUP BY severity"
        ).fetchall()
        top_attacker_ips = conn.execute(
            """SELECT client_ip, COUNT(*) c FROM requests
               WHERE action='BLOCK' AND client_ip IS NOT NULL
               GROUP BY client_ip ORDER BY c DESC LIMIT 10"""
        ).fetchall()
        return {
            "total_requests": total_requests,
            "total_batches": total_batches,
            "blocked_requests": blocked,
            "by_class": {r["predicted_class"]: r["c"] for r in by_class},
            "by_severity": {r["severity"]: r["c"] for r in by_severity},
            "top_attacker_ips": [{"ip": r["client_ip"], "count": r["c"]} for r in top_attacker_ips],
        }
