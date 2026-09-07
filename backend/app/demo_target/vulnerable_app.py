"""
A small, DELIBERATELY vulnerable demo web application, for local
demonstration of ShieldWAF only. Run it as the "protected" upstream
app and point the proxy at it:

    python -m app.demo_target.vulnerable_app     # runs on :9000
    SHIELDWAF_UPSTREAM=http://localhost:9000 uvicorn app.main:app --reload

Then send requests to the ShieldWAF proxy (default :8000) instead of
directly to :9000 -- benign searches get forwarded and return results;
SQLi/XSS payloads get blocked with a 403 before ever reaching this
vulnerable app.

WARNING: this app is intentionally insecure (string-concatenated SQL,
unescaped HTML output). Never expose it outside a local demo
environment, and never point it at anything but ShieldWAF's own
tests/demos.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

DB_PATH = Path(__file__).resolve().parent / "demo_shop.db"

app = FastAPI(title="ShieldWAF Demo Target (intentionally vulnerable)")


def _init_demo_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO products (name, price) VALUES (?, ?)",
            [("Running Shoes", 59.99), ("Wireless Mouse", 19.99), ("Desk Lamp", 24.50)],
        )
        conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'super_secret_demo_value')")
        conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    _init_demo_db()


@app.get("/", response_class=HTMLResponse)
def home():
    return "<h1>Demo Shop</h1><p>Try <code>/search?q=shoes</code> or <code>/comment?text=hello</code></p>"


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    """INTENTIONALLY VULNERABLE: builds SQL via string concatenation
    instead of a parameterised query, so a real SQLi payload here would
    actually work if it reaches this app -- which is exactly what
    ShieldWAF's proxy is meant to prevent upstream of this endpoint."""
    conn = sqlite3.connect(DB_PATH)
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        rows = []
        error = str(exc)
    else:
        error = None
    conn.close()
    html = "<h2>Search results</h2><ul>"
    for r in rows:
        html += f"<li>{r[1]} - ${r[2]}</li>"
    html += "</ul>"
    if error:
        html += f"<p style='color:red'>SQL error: {error}</p>"
    return html


@app.get("/comment", response_class=HTMLResponse)
def comment(text: str = ""):
    """INTENTIONALLY VULNERABLE: reflects `text` into the page without
    escaping, so a real XSS payload would execute in a browser if it
    reaches this app."""
    return f"<h2>Your comment</h2><div>{text}</div>"


if __name__ == "__main__":
    import uvicorn
    _init_demo_db()
    uvicorn.run(app, host="0.0.0.0", port=9000)
