import pytest
from agentauth.core.resource_refs import (
    ResourceRefStyle,
    format_resource_ref,
    is_resource_ref,
    parse_resource_ref,
)
from agentauth.core.runtime import ActionDescriptor


def test_parse_scoped_resource_ref():
    parsed = parse_resource_ref("service:payments-api")

    assert parsed.kind == "service"
    assert parsed.value == "payments-api"
    assert parsed.style == ResourceRefStyle.SCOPED
    assert parsed.to_string() == "service:payments-api"


def test_parse_uri_resource_ref():
    parsed = parse_resource_ref("mcp://billing/refund")

    assert parsed.kind == "mcp"
    assert parsed.value == "billing/refund"
    assert parsed.style == ResourceRefStyle.URI
    assert parsed.to_string() == "mcp://billing/refund"


def test_format_resource_ref_and_action_descriptor_parser():
    action = ActionDescriptor(
        action_name="tool.call",
        resource_ref=format_resource_ref("env", "prod"),
    )

    parsed = action.parsed_resource_ref()

    assert parsed is not None
    assert parsed.kind == "env"
    assert parsed.value == "prod"


@pytest.mark.parametrize("raw", ["", "payments-api", "service:", "://prod"])
def test_invalid_resource_ref_inputs(raw: str):
    assert is_resource_ref(raw) is False
    with pytest.raises(ValueError):
        parse_resource_ref(raw)
