"""
Feature schema for ShieldWAF's request classifier.

Unlike a network-flow NIDS (which looks at packet/byte statistics),
a WAF inspects the *content* of an HTTP request -- path, query string,
body, headers -- for the textual signatures of web application attacks.
This schema is a set of lexical/statistical features computed directly
from that content, in the same spirit as features used in published
ML-based WAF research (e.g. detecting SQLi/XSS via keyword counts,
special-character ratios, and payload entropy rather than raw string
matching alone).

CLASS TAXONOMY (OWASP Top 10 -aligned, six classes distinguishable from
request content alone, without needing the target application's source):

  BENIGN              - normal request
  SQLI                - SQL injection (UNION/boolean/time-based patterns)
  XSS                 - cross-site scripting (script/event-handler injection)
  PATH_TRAVERSAL       - directory traversal / local file inclusion attempts
  COMMAND_INJECTION    - OS command injection (shell metacharacters + commands)
  SCANNER_RECON        - automated scanner/recon traffic (sqlmap, nikto, nmap
                          user-agents; rapid probing of common sensitive paths)
"""

from __future__ import annotations

from typing import List

FEATURE_COLUMNS: List[str] = [
    "path_length",
    "query_length",
    "body_length",
    "num_params",
    "special_char_ratio",       # non-alphanumeric chars / total length
    "quote_count",              # ' and " occurrences
    "sql_keyword_count",
    "xss_keyword_count",
    "path_traversal_count",
    "cmd_injection_count",
    "payload_entropy",          # Shannon entropy of path+query+body
    "encoded_char_count",       # count of %XX URL-encoded sequences
    "script_tag_count",
    "comment_token_count",      # SQL/HTML comment tokens: --, /*, <!--
    "suspicious_ua_flag",       # known scanner/tool user-agent
    "avg_param_length",
    "max_param_length",
    "digit_ratio",
]

CLASSES: List[str] = [
    "BENIGN",
    "SQLI",
    "XSS",
    "PATH_TRAVERSAL",
    "COMMAND_INJECTION",
    "SCANNER_RECON",
]

SEVERITY_BY_CLASS = {
    "BENIGN": "none",
    "SCANNER_RECON": "low",
    "PATH_TRAVERSAL": "high",
    "XSS": "high",
    "COMMAND_INJECTION": "critical",
    "SQLI": "critical",
}


def n_features() -> int:
    return len(FEATURE_COLUMNS)


def n_classes() -> int:
    return len(CLASSES)
