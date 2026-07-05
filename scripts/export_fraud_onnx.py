#!/usr/bin/env python3
"""Export a tiny fraud-score ONNX head for EZKL (1 feature -> 1 sigmoid output)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "circuits" / "fraud_head"
MODEL_PATH = OUT_DIR / "model.onnx"
INPUT_PATH = OUT_DIR / "input.sample.json"


def export_with_torch() -> None:
    import torch
    import torch.nn as nn

    class FraudHead(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.linear = nn.Linear(1, 1)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return torch.sigmoid(self.linear(x))

    model = FraudHead()
    # Approximate min(1, amount / 10000) near origin: y ≈ amount/10000
    with torch.no_grad():
        model.linear.weight.fill_(1.0 / 10_000.0)
        model.linear.bias.fill_(0.0)

    dummy = torch.tensor([[250.0]], dtype=torch.float32)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model,
        dummy,
        MODEL_PATH,
        input_names=["amount"],
        output_names=["fraud_score"],
        dynamic_axes=None,
        opset_version=17,
    )
    out = model(dummy).item()
    write_sample_input(250.0, out)


def export_with_onnx_helper() -> None:
    import numpy as np
    import onnx
    from onnx import TensorProto, helper

    weight = np.array([[1.0 / 10_000.0]], dtype=np.float32)
    bias = np.array([0.0], dtype=np.float32)

    x = helper.make_tensor_value_info("amount", TensorProto.FLOAT, [1, 1])
    y = helper.make_tensor_value_info("fraud_score", TensorProto.FLOAT, [1, 1])
    w = helper.make_tensor("W", TensorProto.FLOAT, [1, 1], weight.flatten().tolist())
    b = helper.make_tensor("B", TensorProto.FLOAT, [1], bias.flatten().tolist())

    gemm = helper.make_node("Gemm", ["amount", "W", "B"], ["logit"], alpha=1.0, beta=1.0, transB=0)
    sigmoid = helper.make_node("Sigmoid", ["logit"], ["fraud_score"])
    graph = helper.make_graph([gemm, sigmoid], "fraud_head", [x], [y], [w, b])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    onnx.checker.check_model(model)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    onnx.save(model, MODEL_PATH)
    score = float(1.0 / (1.0 + np.exp(-(250.0 / 10_000.0))))
    write_sample_input(250.0, score)


def write_sample_input(amount: float, fraud_score: float) -> None:
  payload = {
      "input_data": [[amount]],
      "output_data": [[fraud_score]],
  }
  INPUT_PATH.write_text(json.dumps(payload, indent=2))
  print(f"wrote {MODEL_PATH}")
  print(f"wrote {INPUT_PATH}")


def main() -> None:
    try:
        export_with_torch()
    except ImportError:
        export_with_onnx_helper()


if __name__ == "__main__":
    main()
