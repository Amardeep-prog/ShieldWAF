from __future__ import annotations

import threading
from typing import Optional

from app.detection.train import load_or_train, train_and_evaluate


class ModelStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.clf = None
        self.iforest = None
        self.metrics: Optional[dict] = None

    def ensure_loaded(self) -> None:
        with self._lock:
            if self.clf is None:
                self.clf, self.iforest, self.metrics = load_or_train()

    def retrain(self, n_per_class: int = 700) -> dict:
        with self._lock:
            self.metrics = train_and_evaluate(n_per_class=n_per_class)
            self.clf, self.iforest, _ = load_or_train()
            return self.metrics


model_store = ModelStore()
