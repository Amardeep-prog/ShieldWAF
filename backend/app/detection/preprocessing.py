"""Shared preprocessing so training and inference use the identical
feature vector construction (same anti-skew rationale as the NIDS
project's preprocessing.py)."""

from __future__ import annotations

from typing import Any, Dict, List

import numpy as np
import pandas as pd

from app.detection.schema import FEATURE_COLUMNS


def features_to_row(features: Dict[str, float]) -> List[float]:
    return [float(features.get(col, 0.0) or 0.0) for col in FEATURE_COLUMNS]


def dataframe_to_matrix(df: pd.DataFrame) -> np.ndarray:
    df = df[FEATURE_COLUMNS].copy().fillna(0.0)
    return df.to_numpy(dtype=float)
