"""
In-process sliding-window rate limiter and repeat-offender auto-block.

Two independent protections a real WAF needs beyond per-request content
inspection:
  1. Rate limiting -- too many requests from one IP in a short window,
     regardless of content (crude DoS/brute-force protection).
  2. Auto-block -- an IP that has triggered N *malicious* verdicts
     within a window gets temporarily blocked outright, so a slow drip
     of varied payloads from the same attacker still gets shut down
     after a few tries instead of being evaluated fresh every time.

Deliberately in-memory (a `dict` of deques) rather than requiring Redis,
so this runs standalone for a lab/demo deployment -- swapping in Redis
for multi-worker deployments is noted as future work.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple


class RateLimiter:
    def __init__(self, window_seconds: float = 60.0, max_requests: int = 120,
                 max_malicious: int = 3, block_seconds: float = 300.0):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.max_malicious = max_malicious
        self.block_seconds = block_seconds

        self._lock = threading.Lock()
        self._requests: Dict[str, Deque[float]] = defaultdict(deque)
        self._malicious_hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._blocked_until: Dict[str, float] = {}
        self._block_reason: Dict[str, str] = {}

    def _prune(self, dq: Deque[float], now: float, window: float) -> None:
        while dq and now - dq[0] > window:
            dq.popleft()

    def is_blocked(self, ip: str) -> Tuple[bool, Optional[str], Optional[float]]:
        with self._lock:
            until = self._blocked_until.get(ip)
            if until and time.time() < until:
                return True, self._block_reason.get(ip), until - time.time()
            if until and time.time() >= until:
                del self._blocked_until[ip]
                self._block_reason.pop(ip, None)
            return False, None, None

    def record_request(self, ip: str) -> Tuple[bool, str]:
        """Call once per incoming request. Returns (rate_limited, reason)."""
        now = time.time()
        with self._lock:
            dq = self._requests[ip]
            self._prune(dq, now, self.window_seconds)
            dq.append(now)
            if len(dq) > self.max_requests:
                self._blocked_until[ip] = now + self.block_seconds
                self._block_reason[ip] = (
                    f"rate limit exceeded: {len(dq)} requests in "
                    f"{self.window_seconds:.0f}s (max {self.max_requests})"
                )
                return True, self._block_reason[ip]
            return False, ""

    def record_malicious(self, ip: str) -> Tuple[bool, str]:
        """Call when a request from this IP was flagged malicious.
        Returns (auto_blocked, reason)."""
        now = time.time()
        with self._lock:
            dq = self._malicious_hits[ip]
            self._prune(dq, now, self.window_seconds * 5)  # wider window for repeat-offender tracking
            dq.append(now)
            if len(dq) >= self.max_malicious:
                self._blocked_until[ip] = now + self.block_seconds
                self._block_reason[ip] = (
                    f"repeat offender: {len(dq)} malicious requests within "
                    f"{self.window_seconds * 5:.0f}s (threshold {self.max_malicious})"
                )
                return True, self._block_reason[ip]
            return False, ""

    def manual_block(self, ip: str, reason: str = "manually blocked by analyst",
                      duration: Optional[float] = None) -> None:
        with self._lock:
            self._blocked_until[ip] = time.time() + (duration or self.block_seconds * 10)
            self._block_reason[ip] = reason

    def unblock(self, ip: str) -> None:
        with self._lock:
            self._blocked_until.pop(ip, None)
            self._block_reason.pop(ip, None)

    def snapshot(self) -> Dict[str, dict]:
        now = time.time()
        with self._lock:
            return {
                ip: {
                    "blocked": until > now,
                    "remaining_seconds": max(0, until - now),
                    "reason": self._block_reason.get(ip),
                }
                for ip, until in self._blocked_until.items()
            }


rate_limiter = RateLimiter()
