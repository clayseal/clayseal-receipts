"""Agent Receipts: cryptographic receipts for autonomous AI agents."""

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.budget import BudgetType, CapabilityBudget
from agentauth.core.decision import (
    STANDARD_OBLIGATION_TYPES,
    ApprovalMetadata,
    ApprovalState,
    BudgetEffect,
    DecisionResult,
    Obligation,
    is_standard_obligation_type,
)
from agentauth.core.delegation import (
    DelegationToken,
    issue_delegation,
    sign_delegation,
    verify_delegation_chain,
    verify_delegation_envelope,
)
from agentauth.core.lineage import AuthorityLineage, AuthorityTransitionType
from agentauth.core.mandate import (
    Mandate,
    check_receipt_against_mandate,
    issue_mandate,
    mandate_bundle_section,
    verify_bundle_mandate,
    verify_mandate_envelope,
    verify_mandate_signature,
)
from agentauth.core.operations import (
    CapabilityOperation,
    capability_allows,
    mcp_tool_capability,
    operation_for_action,
    operation_for_mcp_tool,
)
from agentauth.core.runtime import (
    ActionDescriptor,
    ActorKind,
    ActorRef,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)
from agentauth.core.signing import (
    SigningKey,
    generate_keypair,
    load_or_create_key,
    sign_bundle,
    verify_bundle_signatures,
)
from agentauth.core.task_scope import (
    TaskScope,
    compile_human_authorization,
    compile_mandate_scope,
    compile_task_scope,
    compile_task_scope_envelope,
    resolve_task_mandate,
)

from agentauth.receipts.action_features import FEATURE_NAMES, feature_vector_from_actions
from agentauth.receipts.action_monitor import (
    MonitoringSignal,
    SessionActionMonitor,
)
from agentauth.receipts.anomaly_baseline import AnomalyBaselineModel, load_anomaly_model
from agentauth.receipts.approval import infer_approval_state
from agentauth.receipts.assurance import (
    AssuranceLevel,
    AssuranceSummary,
    RatsRole,
    TrustTier,
    assurance_from_bundle,
    assurance_from_proof,
    enrich_assurance_dict,
    meets_assurance_threshold,
    parse_trust_tier,
    rats_roles_reference,
    tier_ordinal,
    trust_tier_for_level,
)
from agentauth.receipts.audit import AuditChain
from agentauth.receipts.auditor import auditor_evidence_summary
from agentauth.receipts.certificate import AgentCertificate, PrincipalRef, load_certificate
from agentauth.receipts.compliance import (
    export_compliance_mapped,
    export_siem_record,
    load_compliance_profile,
    validate_profile_completeness,
)
from agentauth.receipts.compose import prove_composed, verify_composed
from agentauth.receipts.diagnostics import run_diagnostics
from agentauth.receipts.evidence import (
    AuthorityContextRef,
    DecisionRecord,
    EvidenceSummary,
    decision_record_from_run,
    evidence_block_from_run,
    evidence_summary_from_run,
)
from agentauth.receipts.evidence_refs import EvidenceRefs
from agentauth.receipts.explain import explain_receipt_bundle
from agentauth.receipts.export import (
    build_receipt_bundle,
    compact_receipt_bundle,
    export_bundle_for_audience,
    export_run_result,
    load_receipt_bundle,
    load_receipts_ndjson,
    verify_receipt_bundle,
    write_receipt_bundle,
    write_receipts_ndjson,
)
from agentauth.receipts.fraud_tools import FRAUD_TOOL_NAMES
from agentauth.receipts.handoff import SessionHandoffArtifact
from agentauth.receipts.inference import amount_to_score, prove_inference, verify_inference
from agentauth.receipts.identity_providers import (
    build_identity_session,
    get_identity_provider,
    list_identity_providers,
    register_identity_provider,
)
from agentauth.receipts.invariant_policy_engine import InvariantPolicyEngine
from agentauth.receipts.mcp import ReceiptedMcpGateway, ToolCallResult
from agentauth.receipts.mcp_client import (
    McpConnectionSpec,
    ReceiptedMcpClient,
    connect_fraud_mcp_http,
    connect_fraud_mcp_server,
    connect_fraud_mcp_sse,
    connect_mcp,
    default_fraud_server_spec,
    default_sse_spec,
    default_stdio_spec,
    default_streamable_http_spec,
    parse_call_tool_result,
    require_mcp,
    sse_url,
    streamable_http_url,
)
from agentauth.receipts.partner_config import PartnerConfig
from agentauth.receipts.policy import Policy, PolicyCapability, PolicyTier
from agentauth.receipts.policy_engine import (
    PolicyEngine,
    ReservationCallback,
    ReservationResult,
    YamlPolicyEngine,
    noop_reservation_callback,
    pre_execution_violations,
)
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.receipts.prover import locate_cli, prove_structural_policy, verify_structural_policy
from agentauth.receipts.receipt_schema import (
    RECEIPT_BUNDLE_SCHEMA,
    RECEIPT_BUNDLE_SCHEMA_V1,
    RECEIPT_BUNDLE_SCHEMA_V2,
    SUPPORTED_RECEIPT_BUNDLE_SCHEMAS,
    migrate_v1_to_v2,
)
from agentauth.receipts.replay import (
    compare_budget_effects,
    compare_stored_decision,
    re_evaluate_policy_decision,
    rebuild_context_from_bundle,
)
from agentauth.receipts.session import parse_session, prove_session, verify_session
from agentauth.receipts.structural_invariants import PrGateEvidence, evaluate_pr_gate
from agentauth.receipts.tee import TeeQuote, TeeQuoteFormat, verify_tee_quote
from agentauth.receipts.wrapper import AgentWrapper, RunResult

# Dynamic-sandbox scoping (capability leases, repo chunk indexes) needs the
# capabilities layer: an optional extra, resolved lazily via PEP 562 so plain
# receipt flows never import it.
_SCOPING_EXPORTS = {
    "CapabilityLease",
    "GoalSpec",
    "build_capability_lease",
    "build_repo_chunk_index",
}


def __getattr__(name: str):
    if name in _SCOPING_EXPORTS:
        try:
            from agentauth.capabilities import scoping as _scoping
        except ImportError as exc:
            raise ImportError(
                f"agentauth.receipts.{name} needs the capabilities layer. "
                "Install with: pip install 'clayseal-receipts[scoping]'"
            ) from exc
        return getattr(_scoping, name)
    raise AttributeError(f"module 'agentauth.receipts' has no attribute {name!r}")

__all__ = [
    "__version__",
    "AssuranceLevel",
    "AssuranceSummary",
    "RatsRole",
    "TrustTier",
    "ActionDescriptor",
    "AgentCertificate",
    "AgentWrapper",
    "ActorKind",
    "ActorRef",
    "ApprovalMetadata",
    "ApprovalState",
    "AttestationPath",
    "AuditChain",
    "AuthorityBinding",
    "AuthorityContext",
    "MonitoringSignal",
    "SessionActionMonitor",
    "CapabilityLease",
    "GoalSpec",
    "build_capability_lease",
    "build_repo_chunk_index",
    "build_identity_session",
    "get_identity_provider",
    "list_identity_providers",
    "register_identity_provider",
    "TaskScope",
    "compile_human_authorization",
    "compile_mandate_scope",
    "compile_task_scope",
    "compile_task_scope_envelope",
    "resolve_task_mandate",
    "SigningKey",
    "generate_keypair",
    "load_or_create_key",
    "sign_bundle",
    "verify_bundle_signatures",
    "BudgetEffect",
    "DecisionResult",
    "DecisionRecord",
    "EvidenceSummary",
    "EvidenceRefs",
    "CapabilityOperation",
    "capability_allows",
    "mcp_tool_capability",
    "operation_for_action",
    "operation_for_mcp_tool",
    "AuthorityContextRef",
    "PolicyEngine",
    "ReservationCallback",
    "ReservationResult",
    "InvariantPolicyEngine",
    "PrGateEvidence",
    "evaluate_pr_gate",
    "AnomalyBaselineModel",
    "load_anomaly_model",
    "FEATURE_NAMES",
    "pre_execution_violations",
    "DecisionOutcome",
    "DelegationToken",
    "BudgetType",
    "CapabilityBudget",
    "AuthorityLineage",
    "AuthorityTransitionType",
    "ExecutionProof",
    "ExecutionContext",
    "SessionHandoffArtifact",
    "TeeQuote",
    "TeeQuoteFormat",
    "FRAUD_TOOL_NAMES",
    "Obligation",
    "STANDARD_OBLIGATION_TYPES",
    "is_standard_obligation_type",
    "Policy",
    "ReceiptedMcpClient",
    "PolicyCapability",
    "PolicyTier",
    "PrincipalRef",
    "ReceiptedMcpGateway",
    "RunResult",
    "SideEffectLevel",
    "ToolCallResult",
    "issue_delegation",
    "sign_delegation",
    "issue_mandate",
    "Mandate",
    "load_certificate",
    "amount_to_score",
    "locate_cli",
    "prove_composed",
    "prove_inference",
    "prove_structural_policy",
    "verify_composed",
    "verify_delegation_chain",
    "verify_delegation_envelope",
    "verify_bundle_mandate",
    "verify_mandate_envelope",
    "verify_mandate_signature",
    "check_receipt_against_mandate",
    "mandate_bundle_section",
    "parse_session",
    "prove_session",
    "verify_session",
    "verify_inference",
    "verify_structural_policy",
    "McpConnectionSpec",
    "connect_fraud_mcp_server",
    "connect_fraud_mcp_sse",
    "connect_fraud_mcp_http",
    "connect_mcp",
    "default_fraud_server_spec",
    "default_sse_spec",
    "default_streamable_http_spec",
    "default_stdio_spec",
    "parse_call_tool_result",
    "require_mcp",
    "sse_url",
    "streamable_http_url",
    "compare_stored_decision",
    "compare_budget_effects",
    "rebuild_context_from_bundle",
    "export_bundle_for_audience",
    "export_compliance_mapped",
    "export_siem_record",
    "load_compliance_profile",
    "validate_profile_completeness",
    "auditor_evidence_summary",
    "infer_approval_state",
    "re_evaluate_policy_decision",
    "verify_tee_quote",
    "build_receipt_bundle",
    "RECEIPT_BUNDLE_SCHEMA",
    "RECEIPT_BUNDLE_SCHEMA_V1",
    "RECEIPT_BUNDLE_SCHEMA_V2",
    "SUPPORTED_RECEIPT_BUNDLE_SCHEMAS",
    "migrate_v1_to_v2",
    "load_receipts_ndjson",
    "write_receipts_ndjson",
    "compact_receipt_bundle",
    "evidence_block_from_run",
    "evidence_summary_from_run",
    "decision_record_from_run",
    "noop_reservation_callback",
    "explain_receipt_bundle",
    "export_run_result",
    "assurance_from_bundle",
    "assurance_from_proof",
    "enrich_assurance_dict",
    "meets_assurance_threshold",
    "parse_trust_tier",
    "rats_roles_reference",
    "tier_ordinal",
    "trust_tier_for_level",
    "load_receipt_bundle",
    "verify_receipt_bundle",
    "write_receipt_bundle",
    "PartnerConfig",
    "run_diagnostics",
]

from agentauth.receipts._version import __version__  # noqa: E402
