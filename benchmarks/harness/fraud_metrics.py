from __future__ import annotations


def decision_label_mismatch(decision: str | None, ground_truth_fraud: int) -> bool:
    """True when model decision disagrees with the corpus fraud label.

    NOTE: the fraud model is a *workload fixture*, not the product. This is used
    only as a decision-branch coverage proxy (does the fixture exercise both allow
    and deny paths) — not as a model-accuracy metric. AgentAuth attests whatever
    decision a customer's model makes; it is not a fraud model.
    """
    if decision is None:
        return True
    if ground_truth_fraud == 1:
        return decision == "approve"
    return decision != "approve"
