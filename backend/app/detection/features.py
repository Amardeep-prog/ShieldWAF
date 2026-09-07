"""
Real, deterministic feature extraction from an HTTP request's textual
content. Given a parsed request (method, path, query string, body,
headers), computes the lexical/statistical features in schema.py.

This is the WAF equivalent of the NIDS project's flow-feature
extractor: it turns raw request text into the numeric vector the ML
classifier and rule engine both consume, so there is exactly one code
path from "text a client sent" to "features a model sees" (avoiding
train/serve skew the same way `pcap_parser.py` did for network flows).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote

SQL_KEYWORDS = [
    "union", "select", "insert", "update", "delete", "drop", "alter",
    "exec", "execute", "or 1=1", "and 1=1", "sleep(", "benchmark(",
    "information_schema", "xp_cmdshell", "waitfor delay", "having 1=1",
    "order by", "group_concat", "load_file", "into outfile",
]

XSS_KEYWORDS = [
    "<script", "onerror=", "onload=", "onmouseover=", "javascript:",
    "document.cookie", "alert(", "prompt(", "confirm(", "<iframe",
    "<svg", "onfocus=", "eval(", "fromcharcode",
]

PATH_TRAVERSAL_TOKENS = [
    "../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "/etc/passwd",
    "boot.ini", "win.ini", "/proc/self/environ", "....//",
]

CMD_INJECTION_TOKENS = [
    "; ls", "; cat", "| nc", "&& wget", "&& curl", "$(", "`", "; rm ",
    "; whoami", "%0a", "/bin/sh", "/bin/bash", "; ping",
]

COMMENT_TOKENS = ["--", "/*", "*/", "<!--", "#"]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "nessus", "acunetix", "w3af", "havij",
    "burpsuite", "dirbuster", "wpscan", "masscan", "zgrab",
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _count_occurrences(haystack: str, needles: List[str]) -> int:
    haystack_lower = haystack.lower()
    return sum(haystack_lower.count(n) for n in needles)


def extract_features(request: Dict[str, Any]) -> Dict[str, float]:
    """
    request: {
        "method": "GET", "path": "/search", "query_string": "q=...",
        "body": "...", "headers": {"User-Agent": "...", ...}
    }
    """
    path = request.get("path", "") or ""
    query = request.get("query_string", "") or ""
    body = request.get("body", "") or ""
    headers = request.get("headers", {}) or {}
    user_agent = (headers.get("User-Agent") or headers.get("user-agent") or "").lower()

    # Decode URL-encoding once so keyword/token matching sees the real payload,
    # while still counting the RAW encoded sequences as their own signal
    # (heavy %XX encoding is itself suspicious -- obfuscation).
    encoded_char_count = len(re.findall(r"%[0-9A-Fa-f]{2}", path + query + body))
    decoded_blob = unquote(path) + " " + unquote(query) + " " + unquote(body)

    try:
        params = parse_qs(query, keep_blank_values=True)
        param_values = [v for vals in params.values() for v in vals]
    except Exception:
        param_values = []
    if body:
        try:
            body_params = parse_qs(body, keep_blank_values=True)
            param_values += [v for vals in body_params.values() for v in vals]
        except Exception:
            pass

    total_len = len(path) + len(query) + len(body)
    non_alnum = sum(1 for c in decoded_blob if not c.isalnum() and not c.isspace())
    digits = sum(1 for c in decoded_blob if c.isdigit())

    features = {
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "body_length": float(len(body)),
        "num_params": float(len(param_values)),
        "special_char_ratio": non_alnum / max(len(decoded_blob), 1),
        "quote_count": float(decoded_blob.count("'") + decoded_blob.count('"')),
        "sql_keyword_count": float(_count_occurrences(decoded_blob, SQL_KEYWORDS)),
        "xss_keyword_count": float(_count_occurrences(decoded_blob, XSS_KEYWORDS)),
        "path_traversal_count": float(_count_occurrences(decoded_blob, PATH_TRAVERSAL_TOKENS)),
        "cmd_injection_count": float(_count_occurrences(decoded_blob, CMD_INJECTION_TOKENS)),
        "payload_entropy": _shannon_entropy(decoded_blob),
        "encoded_char_count": float(encoded_char_count),
        "script_tag_count": float(decoded_blob.lower().count("<script")),
        "comment_token_count": float(_count_occurrences(decoded_blob, COMMENT_TOKENS)),
        "suspicious_ua_flag": 1.0 if any(tok in user_agent for tok in SUSPICIOUS_USER_AGENTS) else 0.0,
        "avg_param_length": (sum(len(v) for v in param_values) / len(param_values)) if param_values else 0.0,
        "max_param_length": float(max((len(v) for v in param_values), default=0)),
        "digit_ratio": digits / max(len(decoded_blob), 1),
    }
    return features
