"""Frequency baseline anomaly scorer trained on ATIF trajectories (SM-9)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentauth.receipts.action_features import FEATURE_NAMES, feature_vector_from_tools
from agentauth.core.hash_util import hash_canonical_json

ANOMALY_MODEL_ENV = "AGENT_RECEIPTS_ANOMALY_MODEL"


@dataclass
class AnomalyBaselineModel:
    feature_names: list[str]
    mean: list[float]
    std: list[float]
    model_id: str = "atif-frequency-v1"
    training_samples: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "feature_names": list(self.feature_names),
            "mean": list(self.mean),
            "std": list(self.std),
            "training_samples": self.training_samples,
            "model_commitment": self.model_commitment(),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AnomalyBaselineModel:
        return cls(
            feature_names=[str(item) for item in raw.get("feature_names", FEATURE_NAMES)],
            mean=[float(item) for item in raw.get("mean", [])],
            std=[float(item) for item in raw.get("std", [])],
            model_id=str(raw.get("model_id", "atif-frequency-v1")),
            training_samples=int(raw.get("training_samples", 0)),
        )

    def model_commitment(self) -> str:
        return hash_canonical_json(
            {
                "model_id": self.model_id,
                "feature_names": self.feature_names,
                "mean": self.mean,
                "std": self.std,
                "training_samples": self.training_samples,
            }
        )

    def score(self, features: list[float]) -> float:
        if not self.mean or len(features) != len(self.mean):
            return 0.0
        z_total = 0.0
        for value, mean, std in zip(features, self.mean, self.std):
            denominator = std if std > 1e-9 else 1.0
            z_total += abs((value - mean) / denominator)
        normalized = z_total / max(1.0, float(len(features)))
        return min(1.0, normalized / 3.0)


def train_baseline_from_trajectories(
    trajectories: list[dict[str, Any]],
    *,
    model_id: str = "atif-frequency-v1",
) -> AnomalyBaselineModel:
    from agentauth.receipts.action_features import trajectory_tool_names

    vectors: list[list[float]] = []
    for trajectory in trajectories:
        tools = trajectory_tool_names(trajectory)
        if tools:
            vectors.append(feature_vector_from_tools(tools))

    if not vectors:
        return AnomalyBaselineModel(
            feature_names=list(FEATURE_NAMES),
            mean=[0.0] * len(FEATURE_NAMES),
            std=[1.0] * len(FEATURE_NAMES),
            model_id=model_id,
            training_samples=0,
        )

    feature_count = len(FEATURE_NAMES)
    mean = [0.0] * feature_count
    for vector in vectors:
        for index, value in enumerate(vector):
            mean[index] += value
    mean = [value / len(vectors) for value in mean]

    std = [0.0] * feature_count
    for vector in vectors:
        for index, value in enumerate(vector):
            std[index] += (value - mean[index]) ** 2
    std = [
        (value / max(1, len(vectors) - 1)) ** 0.5 if len(vectors) > 1 else 1.0
        for value in std
    ]

    return AnomalyBaselineModel(
        feature_names=list(FEATURE_NAMES),
        mean=mean,
        std=std,
        model_id=model_id,
        training_samples=len(vectors),
    )


def load_anomaly_model(path: str | Path | None = None) -> AnomalyBaselineModel | None:
    resolved = Path(path) if path is not None else None
    if resolved is None:
        env_path = os.environ.get(ANOMALY_MODEL_ENV, "").strip()
        if not env_path:
            return None
        resolved = Path(env_path)
    if not resolved.is_file():
        return None
    raw = json.loads(resolved.read_text(encoding="utf-8"))
    return AnomalyBaselineModel.from_dict(raw)


def write_anomaly_model(model: AnomalyBaselineModel, path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(model.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest
