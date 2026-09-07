"""
Tests the Combined Log Format parser against real-shaped log lines --
including ones with actual SQLi/XSS/path-traversal payloads embedded in
the request line, exactly as a real access.log would record an attack
-- and verifies the parsed output round-trips correctly through the
same `extract_features` the live engine uses.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.logs.log_parser import parse_log_line, parse_log_text, LogParseError
from app.detection.features import extract_features


def test_normal_combined_log_line():
    line = (
        '203.0.113.5 - - [10/Oct/2023:13:55:36 -0700] '
        '"GET /products?category=shoes&sort=price HTTP/1.1" 200 2326 '
        '"http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    )
    r = parse_log_line(line)
    assert r["method"] == "GET"
    assert r["path"] == "/products"
    assert r["query_string"] == "category=shoes&sort=price"
    assert r["client_ip"] == "203.0.113.5"
    assert r["status"] == "200"
    assert r["headers"]["User-Agent"].startswith("Mozilla")
    print("Normal log line parsed correctly:", r["path"], r["query_string"])


def test_sqli_attack_in_log_line():
    line = (
        '198.51.100.7 - - [10/Oct/2023:14:02:11 -0700] '
        '"GET /search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20 HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"'
    )
    r = parse_log_line(line)
    assert r["path"] == "/search"
    assert "UNION" in r["query_string"].upper() or "union" in r["query_string"].lower()
    feats = extract_features(r)
    assert feats["sql_keyword_count"] >= 1
    print("SQLi log line parsed and re-detected via features:", feats["sql_keyword_count"], "SQL keyword hits")


def test_scanner_probe_log_line():
    line = (
        '192.0.2.15 - - [10/Oct/2023:14:05:00 -0700] '
        '"GET /wp-login.php HTTP/1.1" 404 0 "-" "sqlmap/1.6.12#stable"'
    )
    r = parse_log_line(line)
    assert r["path"] == "/wp-login.php"
    assert "sqlmap" in r["headers"]["User-Agent"].lower()
    print("Scanner probe log line parsed correctly, UA:", r["headers"]["User-Agent"])


def test_missing_referer_and_ua():
    line = '203.0.113.5 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.0" 200 100'
    r = parse_log_line(line)
    assert r["path"] == "/"
    assert r["headers"]["User-Agent"] == ""
    print("Log line with missing referer/UA fields parsed without crashing")


def test_malformed_line_raises():
    try:
        parse_log_line("this is not a log line at all")
        raised = False
    except LogParseError:
        raised = True
    assert raised
    print("Malformed line correctly raises LogParseError instead of silently misparsing")


def test_parse_full_file_reports_bad_lines():
    text = (
        '203.0.113.5 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
        'garbage line that is not a log entry\n'
        '198.51.100.7 - - [10/Oct/2023:14:02:11 -0700] "GET /a?x=<script>alert(1)</script> HTTP/1.1" 200 50 "-" "Mozilla/5.0"\n'
    )
    result = parse_log_text(text)
    assert len(result["requests"]) == 2
    assert result["failed_lines"] == 1
    print("Full-file parse: 2 valid requests, 1 bad line reported (not silently dropped)")


if __name__ == "__main__":
    test_normal_combined_log_line()
    test_sqli_attack_in_log_line()
    test_scanner_probe_log_line()
    test_missing_referer_and_ua()
    test_malformed_line_raises()
    test_parse_full_file_reports_bad_lines()
    print("\nAll log_parser tests passed against real Combined Log Format lines.")
