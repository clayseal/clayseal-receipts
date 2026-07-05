import json
import random
from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.action_features import feature_vector_from_tools, trajectory_tool_names
from agentauth.receipts.anomaly_baseline import train_baseline_from_trajectories, write_anomaly_model
from agentauth.receipts.action_monitor import MonitoredAction
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.proof import DecisionOutcome
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel

ROOT = Path(__file__).resolve().parents[2]
ATIF_ROOT = ROOT / "benchmarks" / "corpus" / "mcp_agent_trajectory_benchmark"


def _load_trajectories(limit: int | None = None) -> list[dict]:
    paths = sorted(ATIF_ROOT.glob("*/trajectory.json"))
    if limit is not None:
        paths = paths[:limit]
    return [json.loads(path.read_text(encoding="utf-8")) for path in paths]


def test_atif_baseline_scores_shuffled_trajectory_higher():
    trajectories = _load_trajectories()
    if len(trajectories) < 2:
        return

    model = train_baseline_from_trajectories(trajectories)
    control = trajectories[0]
    control_tools = trajectory_tool_names(control)
    control_score = model.score(feature_vector_from_tools(control_tools))

    shuffled_tools = list(control_tools)
    random.Random(0).shuffle(shuffled_tools)
    shuffled_score = model.score(feature_vector_from_tools(shuffled_tools))

    assert shuffled_score >= control_score


def test_train_script_writes_model(tmp_path):
    trajectories = _load_trajectories(limit=5)
    if not trajectories:
        return
    model = train_baseline_from_trajectories(trajectories)
    output = write_anomaly_model(model, tmp_path / "model.json")
    loaded = json.loads(output.read_text())
    assert loaded["training_samples"] == len(trajectories)
    assert loaded["model_commitment"] == model.model_commitment()


def test_bounded_auto_run_blocks_on_monitoring_before_model():
    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "run-block",
            "tier": "tool_trace",
            "capability": "operator_attested",
            "output_schema": {"fields": ["status"], "required": []},
            "monitoring": {
                "enabled": True,
                "review_threshold": 0.4,
                "block_threshold": 0.5,
                "sensitive_keywords": ["curl"],
            },
        }
    )
    cert = dev_certificate(policy.commitment(), scope=["agent.run"])
    calls: list[str] = []

    def model(_inp):
        calls.append("ran")
        return {"status": "ok"}

    agent = AgentWrapper(
        model=model,
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
    )

    agent.session_monitor._history["default"] = [
        MonitoredAction(
            "mcp.tools/call/read_file",
            "mcp_tool_call",
            "repo:read_file",
            SideEffectLevel.READ_ONLY,
            "read_file",
        ),
        MonitoredAction(
            "mcp.tools/call/read_file",
            "mcp_tool_call",
            "repo:read_file",
            SideEffectLevel.READ_ONLY,
            "read_file",
        ),
    ]

    result = agent.run(
        {"url": "http://example.invalid"},
        action=ActionDescriptor(
            action_name="mcp.tools/call/curl_url",
            action_category="mcp_tool_call",
            resource_type="mcp_tool",
            resource_ref="repo:curl_url",
            side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        ),
    )

    assert calls == []
    assert result.decision.outcome == DecisionOutcome.DENY
    assert result.output["status"] == "blocked"
