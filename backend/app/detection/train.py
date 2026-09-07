"""
Trains ShieldWAF's request classifier: a RandomForestClassifier over
the 6-class attack taxonomy, PLUS an IsolationForest fit on BENIGN-only
requests for anomaly scoring (catches novel/obfuscated payloads that
don't match any known keyword/pattern signature -- the same
misuse+anomaly hybrid idea as a network NIDS, applied to request
content instead of traffic statistics).

Run directly:
    python -m app.detection.train
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize

from app.detection.dataset import generate_dataset
from app.detection.preprocessing import dataframe_to_matrix
from app.detection.schema import CLASSES, FEATURE_COLUMNS

MODEL_DIR = Path(__file__).resolve().parent.parent / "model_store"
MODEL_PATH = MODEL_DIR / "shieldwaf_rf.joblib"
ANOMALY_PATH = MODEL_DIR / "shieldwaf_iforest.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"


def train_and_evaluate(n_per_class: int = 700, seed: int = 42) -> dict:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    df = generate_dataset(n_per_class=n_per_class, seed=seed)
    X = dataframe_to_matrix(df)
    y = df["label"].to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=seed, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=300, max_depth=12, min_samples_leaf=2,
        random_state=seed, n_jobs=-1, class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)

    report = classification_report(y_test, y_pred, labels=CLASSES, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=CLASSES)

    y_test_bin = label_binarize(y_test, classes=clf.classes_.tolist())
    try:
        roc_auc = float(roc_auc_score(y_test_bin, y_proba, average="macro", multi_class="ovr"))
    except ValueError:
        roc_auc = None

    importances = dict(zip(FEATURE_COLUMNS, clf.feature_importances_.tolist()))

    benign_mask = y_train == "BENIGN"
    iforest = IsolationForest(n_estimators=200, contamination=0.05, random_state=seed)
    iforest.fit(X_train[benign_mask])

    anomaly_scores_test = iforest.decision_function(X_test)
    is_benign_test = (y_test == "BENIGN").astype(int)
    try:
        anomaly_auc = float(roc_auc_score(is_benign_test, anomaly_scores_test))
    except ValueError:
        anomaly_auc = None

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(iforest, ANOMALY_PATH)

    metrics = {
        "trained_at": time.time(),
        "train_seconds": round(time.time() - t0, 3),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "classes": CLASSES,
        "classification_report": report,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": CLASSES,
        "roc_auc_macro_ovr": roc_auc,
        "feature_importances": importances,
        "anomaly_detector": {
            "trained_on": "BENIGN-only requests",
            "n_benign_train": int(benign_mask.sum()),
            "benign_vs_attack_auc": anomaly_auc,
            "contamination": 0.05,
        },
        "notes": (
            "Trained on requests built from real, documented OWASP-style "
            "attack payload strings with randomised benign request "
            "structure around them (see dataset.py). High accuracy "
            "reflects the classifier's ability to separate these known "
            "payload patterns, not an audited real-world false-positive "
            "rate against live production traffic."
        ),
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    return metrics


def load_or_train():
    if MODEL_PATH.exists() and ANOMALY_PATH.exists() and METRICS_PATH.exists():
        clf = joblib.load(MODEL_PATH)
        iforest = joblib.load(ANOMALY_PATH)
        with open(METRICS_PATH) as f:
            metrics = json.load(f)
        return clf, iforest, metrics
    metrics = train_and_evaluate()
    clf = joblib.load(MODEL_PATH)
    iforest = joblib.load(ANOMALY_PATH)
    return clf, iforest, metrics


if __name__ == "__main__":
    m = train_and_evaluate()
    print(f"Trained in {m['train_seconds']}s on {m['n_train']} requests, tested on {m['n_test']}.")
    print(f"Macro ROC-AUC (RF, one-vs-rest): {m['roc_auc_macro_ovr']:.4f}")
    print(f"Anomaly detector benign-vs-attack AUC: {m['anomaly_detector']['benign_vs_attack_auc']:.4f}")
    for c in CLASSES:
        print(f"  {c:20s} f1={m['classification_report'][c]['f1-score']:.3f}")
