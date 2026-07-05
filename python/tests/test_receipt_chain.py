from agentauth.receipts.receipt_chain import (
    extract_poison_captures,
    extract_security_executions,
    link_receipt_chain,
    verify_receipt_at_merge,
    verify_receipt_chain,
)


def _capture_receipt(**overrides):
    body = {
        "receipt_id": "rcpt_i1",
        "receipt_hash": "hash_i1",
        "created_at": "2026-06-29T00:00:00Z",
        "decision": {"outcome": "allow_with_review"},
        "git": {
            "changed_files": [{"path": ".devin/knowledge.md", "operation": "modify"}],
        },
    }
    body.update(overrides)
    return body


def _execute_receipt(**overrides):
    body = {
        "receipt_id": "rcpt_i2",
        "receipt_hash": "hash_i2",
        "created_at": "2026-06-29T01:00:00Z",
        "decision": {"outcome": "deny"},
        "flags": [
            {
                "code": "cross_session_poison_attribution",
                "message": "prior poison",
            }
        ],
        "git": {
            "changed_files": [{"path": "swe_triage/parser.py", "operation": "modify"}],
        },
        "receipt_chain": {
            "prior_receipt_refs": [{"receipt_id": "rcpt_i1", "receipt_hash": "hash_i1"}],
            "links": [
                {
                    "cause_receipt_id": "rcpt_i1",
                    "cause_receipt_hash": "hash_i1",
                    "effect_receipt_id": "rcpt_i2",
                    "effect_path": "swe_triage/parser.py",
                    "prior_surface": ".devin/knowledge.md",
                }
            ],
        },
    }
    body.update(overrides)
    return body


def test_extract_poison_capture_from_instruction_surface_write():
    captures = extract_poison_captures(_capture_receipt())
    assert len(captures) == 1
    assert captures[0].surface_path == ".devin/knowledge.md"


def test_link_i1_capture_to_i2_execution():
    links = link_receipt_chain(_execute_receipt(), [_capture_receipt()])
    assert len(links) == 1
    assert links[0].cause_receipt_id == "rcpt_i1"
    assert links[0].effect_path == "swe_triage/parser.py"


def test_verify_receipt_chain_valid_with_matching_prior():
    current = _execute_receipt()
    result = verify_receipt_chain(current, [_capture_receipt()])
    assert result["valid"] is True
    assert result["links"]


def test_verify_receipt_at_merge_rejects_stale_head():
    receipt = {
        "receipt_id": "rcpt_p1",
        "receipt_hash": "abc",
        "git": {
            "head_sha": "sha_p1",
            "evaluated_head_sha": "sha_p1",
            "merge_base": "sha_base",
            "diff_hash": "deadbeef",
        },
    }
    result = verify_receipt_at_merge(receipt, merge_head_sha="sha_p2")
    assert result["valid"] is False
    assert result["toctou_ok"] is False
    assert any("TOCTOU" in issue for issue in result["issues"])


def test_verify_receipt_at_merge_accepts_matching_head():
    receipt = {
        "receipt_id": "rcpt_p1",
        "receipt_hash": "abc",
        "git": {
            "head_sha": "sha_p1",
            "evaluated_head_sha": "sha_p1",
        },
    }
    result = verify_receipt_at_merge(receipt, merge_head_sha="sha_p1")
    assert result["valid"] is True
    assert result["toctou_ok"] is True


def test_extract_security_executions_detects_parser_change():
    paths = extract_security_executions(_execute_receipt())
    assert paths == ["swe_triage/parser.py"]
