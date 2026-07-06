from __future__ import annotations

import sys
import types

import pytest

from agentauth.receipts import Policy
from agentauth.receipts.frameworks import (
    ReceiptedCallable,
    output_with_receipt_metadata,
    receipted_function,
)
from agentauth.receipts.frameworks.autogen import (
    receipted_function_tool as autogen_receipted_function_tool,
)
from agentauth.receipts.frameworks.crewai import receipted_tool as crewai_receipted_tool
from agentauth.receipts.frameworks.haystack import receipted_tool as haystack_receipted_tool
from agentauth.receipts.frameworks.langchain import receipted_runnable, receipted_tool
from agentauth.receipts.frameworks.llamaindex import receipted_function_tool
from agentauth.receipts.frameworks.openai_agents import (
    receipted_function_tool as openai_receipted_function_tool,
)
from agentauth.receipts.frameworks.pydantic_ai import (
    receipted_plain_tool,
)
from agentauth.receipts.frameworks.pydantic_ai import (
    receipted_tool as pydantic_ai_receipted_tool,
)
from agentauth.receipts.frameworks.semantic_kernel import receipted_kernel_function


def _policy() -> Policy:
    return Policy.from_dict(
        {
            "version": 1,
            "name": "framework-test",
            "tier": "structural",
            "capability": "operator_attested",
            "output_schema": {"required": ["decision", "fraud_score"]},
            "numeric_ranges": [{"field": "fraud_score", "min": 0, "max": 1}],
        }
    )


def test_receipted_callable_records_receipt(tmp_path):
    adapter = ReceiptedCallable.from_target(
        lambda inp: {"decision": "approve", "fraud_score": inp["score"]},
        _policy(),
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    output = adapter({"score": 0.2})

    assert output == {"decision": "approve", "fraud_score": 0.2}
    adapter.wrapper.audit.verify_chain()


def test_receipted_callable_can_return_metadata(tmp_path):
    adapter = ReceiptedCallable.from_target(
        lambda _inp: {"decision": "approve", "fraud_score": 0.3},
        _policy(),
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
        output_adapter=output_with_receipt_metadata,
    )

    output = adapter({"transaction_id": "t1"})

    assert output["_agentauth_receipt"]["policy_satisfied"] is True
    assert output["_agentauth_receipt"]["decision_outcome"] == "allow"
    assert output["_agentauth_receipt"]["proof"]["policy_satisfied"] is True


def test_receipted_function_preserves_signature_and_records_receipt(tmp_path):
    def score_transaction(score: float, decision: str = "approve") -> dict[str, object]:
        """Score a transaction."""
        return {"decision": decision, "fraud_score": score}

    wrapped = receipted_function(
        score_transaction,
        _policy(),
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert "score: 'float'" in str(wrapped.__signature__)
    assert "decision: 'str' = 'approve'" in str(wrapped.__signature__)
    assert wrapped(0.6) == {"decision": "approve", "fraud_score": 0.6}
    wrapped.agentauth_adapter.wrapper.audit.verify_chain()


def test_langchain_runnable_uses_optional_core(monkeypatch, tmp_path):
    runnables = types.ModuleType("langchain_core.runnables")

    class RunnableLambda:
        def __init__(self, func):
            self.func = func

        def invoke(self, value):
            return self.func(value)

    runnables.RunnableLambda = RunnableLambda
    monkeypatch.setitem(sys.modules, "langchain_core", types.ModuleType("langchain_core"))
    monkeypatch.setitem(sys.modules, "langchain_core.runnables", runnables)

    runnable = receipted_runnable(
        lambda inp: {"decision": "approve", "fraud_score": inp["score"]},
        _policy(),
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert runnable.invoke({"score": 0.4}) == {"decision": "approve", "fraud_score": 0.4}


def test_langchain_tool_uses_optional_core(monkeypatch, tmp_path):
    tools = types.ModuleType("langchain_core.tools")

    class StructuredTool:
        @classmethod
        def from_function(cls, **kwargs):
            tool = cls()
            tool.kwargs = kwargs
            tool.invoke = lambda value: kwargs["func"](**value)
            return tool

    tools.StructuredTool = StructuredTool
    monkeypatch.setitem(sys.modules, "langchain_core", types.ModuleType("langchain_core"))
    monkeypatch.setitem(sys.modules, "langchain_core.tools", tools)

    def score_transaction(score: float) -> dict[str, object]:
        """Score a transaction."""
        return {"decision": "approve", "fraud_score": score}

    tool = receipted_tool(
        score_transaction,
        _policy(),
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert tool.kwargs["name"] == "score_transaction"
    assert tool.invoke({"score": 0.5}) == {"decision": "approve", "fraud_score": 0.5}


def test_langchain_missing_dependency_has_actionable_error(monkeypatch):
    monkeypatch.delitem(sys.modules, "langchain_core.runnables", raising=False)
    monkeypatch.delitem(sys.modules, "langchain_core", raising=False)

    with pytest.raises(ImportError, match="agentauth-receipts\\[langchain\\]"):
        receipted_runnable(lambda inp: inp, _policy(), mode="shadow", audit_db=":memory:")


def test_pydantic_ai_plain_tool_records_receipt(tmp_path):
    def score_transaction(score: float) -> dict[str, object]:
        return {"decision": "approve", "fraud_score": score}

    tool = receipted_plain_tool(
        score_transaction,
        _policy(),
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert tool(0.7) == {"decision": "approve", "fraud_score": 0.7}
    tool.agentauth_adapter.wrapper.audit.verify_chain()


def test_pydantic_ai_tool_uses_optional_sdk(monkeypatch, tmp_path):
    module = types.ModuleType("pydantic_ai")

    class Tool:
        def __init__(self, func, **kwargs):
            self.func = func
            self.kwargs = kwargs

        def __call__(self, *args, **kwargs):
            return self.func(*args, **kwargs)

    module.Tool = Tool
    monkeypatch.setitem(sys.modules, "pydantic_ai", module)

    def score_transaction(score: float) -> dict[str, object]:
        return {"decision": "approve", "fraud_score": score}

    tool = pydantic_ai_receipted_tool(
        score_transaction,
        _policy(),
        name="score_transaction",
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert tool.kwargs["takes_ctx"] is False
    assert tool.kwargs["name"] == "score_transaction"
    assert tool(0.8) == {"decision": "approve", "fraud_score": 0.8}


def test_pydantic_ai_context_tools_are_rejected():
    with pytest.raises(ValueError, match="takes_ctx=False"):
        pydantic_ai_receipted_tool(
            lambda _ctx, score: {"decision": "approve", "fraud_score": score},
            _policy(),
            takes_ctx=True,
            mode="shadow",
            audit_db=":memory:",
        )


def test_llamaindex_function_tool_uses_optional_sdk(monkeypatch, tmp_path):
    tools = types.ModuleType("llama_index.core.tools")

    class FunctionTool:
        @classmethod
        def from_defaults(cls, fn, **kwargs):
            tool = cls()
            tool.kwargs = kwargs
            tool.call = lambda *args, **call_kwargs: fn(*args, **call_kwargs)
            return tool

    tools.FunctionTool = FunctionTool
    monkeypatch.setitem(sys.modules, "llama_index", types.ModuleType("llama_index"))
    monkeypatch.setitem(sys.modules, "llama_index.core", types.ModuleType("llama_index.core"))
    monkeypatch.setitem(sys.modules, "llama_index.core.tools", tools)

    def score_transaction(score: float) -> dict[str, object]:
        return {"decision": "approve", "fraud_score": score}

    tool = receipted_function_tool(
        score_transaction,
        _policy(),
        name="score_transaction",
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert tool.kwargs["name"] == "score_transaction"
    assert tool.call(0.9) == {"decision": "approve", "fraud_score": 0.9}


def test_crewai_tool_uses_optional_sdk(monkeypatch, tmp_path):
    tools = types.ModuleType("crewai.tools")

    def tool(name):
        def decorate(func):
            func.crewai_tool_name = name
            return func

        return decorate

    tools.tool = tool
    monkeypatch.setitem(sys.modules, "crewai", types.ModuleType("crewai"))
    monkeypatch.setitem(sys.modules, "crewai.tools", tools)

    def score_transaction(score: float) -> dict[str, object]:
        return {"decision": "approve", "fraud_score": score}

    wrapped = crewai_receipted_tool(
        score_transaction,
        _policy(),
        name="score_transaction",
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert wrapped.crewai_tool_name == "score_transaction"
    assert wrapped(0.95) == {"decision": "approve", "fraud_score": 0.95}


def test_openai_agents_function_tool_uses_optional_sdk(monkeypatch, tmp_path):
    agents = types.ModuleType("agents")

    def function_tool(func=None, **kwargs):
        def decorate(inner):
            inner.openai_tool_kwargs = kwargs
            return inner

        if func is None:
            return decorate
        return decorate(func)

    agents.function_tool = function_tool
    monkeypatch.setitem(sys.modules, "agents", agents)

    def score_transaction(score: float) -> dict[str, object]:
        return {"decision": "approve", "fraud_score": score}

    wrapped = openai_receipted_function_tool(
        score_transaction,
        _policy(),
        function_tool_kwargs={"name_override": "score_transaction"},
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert wrapped.openai_tool_kwargs["name_override"] == "score_transaction"
    assert wrapped(0.97) == {"decision": "approve", "fraud_score": 0.97}


def test_semantic_kernel_function_uses_optional_sdk(monkeypatch, tmp_path):
    functions = types.ModuleType("semantic_kernel.functions")

    def kernel_function(**kwargs):
        def decorate(func):
            func.semantic_kernel_kwargs = kwargs
            return func

        return decorate

    functions.kernel_function = kernel_function
    monkeypatch.setitem(sys.modules, "semantic_kernel", types.ModuleType("semantic_kernel"))
    monkeypatch.setitem(sys.modules, "semantic_kernel.functions", functions)

    def score_transaction(score: float) -> dict[str, object]:
        return {"decision": "approve", "fraud_score": score}

    wrapped = receipted_kernel_function(
        score_transaction,
        _policy(),
        name="score_transaction",
        description="Score a transaction.",
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert wrapped.semantic_kernel_kwargs["name"] == "score_transaction"
    assert wrapped.semantic_kernel_kwargs["description"] == "Score a transaction."
    assert wrapped(0.41) == {"decision": "approve", "fraud_score": 0.41}


def test_autogen_function_tool_uses_optional_sdk(monkeypatch, tmp_path):
    tools = types.ModuleType("autogen_core.tools")

    class FunctionTool:
        def __init__(self, func, **kwargs):
            self.func = func
            self.kwargs = kwargs

        def run_json(self, value):
            return self.func(**value)

    tools.FunctionTool = FunctionTool
    monkeypatch.setitem(sys.modules, "autogen_core", types.ModuleType("autogen_core"))
    monkeypatch.setitem(sys.modules, "autogen_core.tools", tools)

    def score_transaction(score: float) -> dict[str, object]:
        return {"decision": "approve", "fraud_score": score}

    tool = autogen_receipted_function_tool(
        score_transaction,
        _policy(),
        name="score_transaction",
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert tool.kwargs["name"] == "score_transaction"
    assert tool.run_json({"score": 0.42}) == {"decision": "approve", "fraud_score": 0.42}


def test_haystack_tool_uses_optional_sdk(monkeypatch, tmp_path):
    tools = types.ModuleType("haystack.tools")

    class Tool:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def invoke(self, value):
            return self.kwargs["function"](**value)

    tools.Tool = Tool
    monkeypatch.setitem(sys.modules, "haystack", types.ModuleType("haystack"))
    monkeypatch.setitem(sys.modules, "haystack.tools", tools)

    def score_transaction(score: float) -> dict[str, object]:
        return {"decision": "approve", "fraud_score": score}

    tool = haystack_receipted_tool(
        score_transaction,
        _policy(),
        name="score_transaction",
        parameters={"type": "object"},
        mode="shadow",
        audit_db=str(tmp_path / "chain.sqlite"),
    )

    assert tool.kwargs["name"] == "score_transaction"
    assert tool.kwargs["parameters"] == {"type": "object"}
    assert tool.invoke({"score": 0.43}) == {"decision": "approve", "fraud_score": 0.43}
