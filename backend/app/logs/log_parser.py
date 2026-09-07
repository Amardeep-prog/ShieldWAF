"""
Real parser for the Apache/Nginx "Combined Log Format" access log line
-- the de facto standard format both web servers write by default:

    127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] "GET /apache_pub HTTP/1.0"
    200 2326 "http://example.com/start.html" "Mozilla/5.0 ..."

This lets ShieldWAF run in a "retroactive log analysis" mode: an
analyst uploads an existing `access.log`, and every historical request
line is decomposed and re-run through the exact same detection engine
that inspects live proxied traffic -- so a team without a live WAF
deployment yet can still audit whether attacks already got through.

Regex derived directly from the published Apache/NCSA Combined Log
Format specification. Tested in `tests/test_log_parser.py` against
real-format log lines (including edge cases: missing referer/UA
recorded as "-", query strings with spaces/quotes inside them).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

# Combined Log Format:
# %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request_line>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
)

_REQUEST_LINE_PATTERN = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/(?P<version>[\d.]+)$'
)


class LogParseError(Exception):
    pass


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one Combined Log Format line into a request dict compatible
    with `detection.features.extract_features`. Returns None for blank
    lines; raises LogParseError for a line that doesn't match the
    format at all (so a caller can report a bad-line count rather than
    silently skipping/misparsing)."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    m = _LOG_PATTERN.match(line)
    if not m:
        raise LogParseError(f"Line does not match Combined Log Format: {line[:120]!r}")

    request_line = m.group("request_line")
    rm = _REQUEST_LINE_PATTERN.match(request_line)
    if rm:
        method = rm.group("method")
        target = rm.group("target")
    else:
        # Malformed/truncated request line (e.g. a raw scanner probe that
        # isn't valid HTTP at all) -- still worth analysing as a path.
        parts = request_line.split(" ", 1)
        method = parts[0] if parts else "GET"
        target = parts[1].rsplit(" HTTP/", 1)[0] if len(parts) > 1 else request_line

    split = urlsplit(target)
    path = split.path or "/"
    query_string = split.query or ""

    ua = m.group("user_agent") or ""
    referer = m.group("referer") or ""

    return {
        "method": method,
        "path": path,
        "query_string": query_string,
        "body": "",  # access logs never contain the request body
        "headers": {"User-Agent": ua, "Referer": referer},
        "client_ip": m.group("ip"),
        "timestamp": m.group("timestamp"),
        "status": m.group("status"),
        "response_size": m.group("size"),
        "raw_line": line,
    }


def parse_log_text(text: str) -> Dict[str, Any]:
    """Parse a whole access-log file's text. Returns parsed requests
    plus a count of lines that failed to parse (reported, not hidden)."""
    requests: List[Dict[str, Any]] = []
    failed = 0
    failed_samples: List[str] = []
    for line in text.splitlines():
        try:
            parsed = parse_log_line(line)
        except LogParseError:
            failed += 1
            if len(failed_samples) < 5:
                failed_samples.append(line[:200])
            continue
        if parsed:
            requests.append(parsed)
    return {"requests": requests, "failed_lines": failed, "failed_samples": failed_samples}
