"""
Deterministic OWASP-CRS-style regex rule engine, run independently of
the ML classifier as a fast, explainable cross-check (same
misuse-detection role `rule_engine.py` played in the NIDS project, just
matching decoded request text instead of flow statistics).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import unquote

import yaml

RULES_PATH = Path(__file__).resolve().parent / "rules.yaml"


class RuleEngine:
    def __init__(self, rules_path: Path = RULES_PATH):
        self.rules_path = rules_path
        self.rules: List[Dict[str, Any]] = []
        self._compiled: List[Dict[str, Any]] = []
        self.reload()

    def reload(self) -> None:
        with open(self.rules_path) as f:
            self.rules = yaml.safe_load(f) or []
        self._compiled = [
            {**r, "_regex": re.compile(r["pattern"], re.IGNORECASE | re.DOTALL)}
            for r in self.rules
        ]

    @staticmethod
    def _field_text(rule_field: str, path: str, query: str, body: str, ua: str) -> str:
        if rule_field == "path":
            return unquote(path)
        if rule_field == "query_string":
            return unquote(query)
        if rule_field == "body":
            return unquote(body)
        if rule_field == "user_agent":
            return ua
        # "any"
        return " ".join([unquote(path), unquote(query), unquote(body)])

    def evaluate(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        path = request.get("path", "") or ""
        query = request.get("query_string", "") or ""
        body = request.get("body", "") or ""
        headers = request.get("headers", {}) or {}
        ua = headers.get("User-Agent") or headers.get("user-agent") or ""

        matches = []
        for rule in self._compiled:
            text = self._field_text(rule["field"], path, query, body, ua)
            if rule["_regex"].search(text):
                matches.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "description": rule["description"].strip(),
                })
        return matches


rule_engine = RuleEngine()
