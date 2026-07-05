from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from harness.config import AdapterOptions
from harness.corpus_paths import resolve_csv
from harness.paths import CORPUS
from harness.types import BenchmarkCase, SuiteName

SourceKind = Literal["repo_corpus", "external_corpus", "synthetic", "generated"]
AssetKind = Literal["file", "directory", "synthetic"]

_MAX_HASH_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class AssetSpec:
    label: str
    kind: AssetKind
    source_kind: SourceKind
    relative_path: str | None = None
    env_var: str | None = None
    arl_filename: str | None = None
    upstream: str | None = None
    license_label: str | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SuiteProvenanceSpec:
    suite: SuiteName
    corpus_name: str
    source_kind: SourceKind
    evaluation_layer: str
    summary: str
    selection_method: str
    assets: tuple[AssetSpec, ...]
    contamination_notes: tuple[str, ...] = ()


@dataclass
class CorpusAssetRecord:
    label: str
    kind: AssetKind
    source_kind: SourceKind
    resolved_path: str | None
    exists: bool
    upstream: str | None = None
    license_label: str | None = None
    bytes: int | None = None
    modified_at: str | None = None
    sha256: str | None = None
    digest_status: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CorpusProvenanceRecord:
    suite: str
    corpus_name: str
    source_kind: SourceKind
    evaluation_layer: str
    summary: str
    selection_method: str
    cases_loaded: int
    sample_mode: str | None = None
    shard: int | None = None
    shards: list[int] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    contamination_notes: list[str] = field(default_factory=list)
    assets: list[CorpusAssetRecord] = field(default_factory=list)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["assets"] = [asset.to_dict() for asset in self.assets]
        return payload


def _repo_path(relative_path: str | None) -> Path | None:
    if not relative_path:
        return None
    return CORPUS / Path(relative_path)


def _resolve_asset_path(spec: AssetSpec, suite: SuiteName) -> Path | None:
    if spec.env_var and spec.arl_filename and spec.relative_path:
        return resolve_csv(
            env_var=spec.env_var,
            corpus_relative=Path(spec.relative_path),
            arl_filename=spec.arl_filename,
        )
    if spec.relative_path:
        return _repo_path(spec.relative_path)
    return None


def _file_digest(path: Path) -> tuple[str | None, str]:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return None, "missing"
    if size > _MAX_HASH_BYTES:
        return None, "skipped_file_too_large"
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest(), "computed"


def _asset_record(spec: AssetSpec, suite: SuiteName) -> CorpusAssetRecord:
    path = _resolve_asset_path(spec, suite)
    exists = bool(path and path.exists())
    record = CorpusAssetRecord(
        label=spec.label,
        kind=spec.kind,
        source_kind=spec.source_kind,
        resolved_path=str(path) if path else None,
        exists=exists,
        upstream=spec.upstream,
        license_label=spec.license_label,
        notes=list(spec.notes),
    )
    if not exists or path is None:
        record.digest_status = "missing"
        return record
    stat = path.stat()
    record.bytes = stat.st_size if path.is_file() else None
    record.modified_at = datetime.fromtimestamp(stat.st_mtime, UTC).isoformat()
    if path.is_file():
        digest, status = _file_digest(path)
        record.sha256 = digest
        record.digest_status = status
    else:
        record.digest_status = "not_a_file"
    return record


PROVENANCE_SPECS: dict[SuiteName, SuiteProvenanceSpec] = {
    "ulb_fraud": SuiteProvenanceSpec(
        suite="ulb_fraud",
        corpus_name="ULB credit-card fraud",
        source_kind="repo_corpus",
        evaluation_layer="task_and_control_quality",
        summary="Tabular fraud benchmark over the ULB credit-card dataset.",
        selection_method="Sequential or stratified row sampling from a local CSV snapshot.",
        assets=(
            AssetSpec(
                label="creditcard_csv",
                kind="file",
                source_kind="repo_corpus",
                relative_path="ulb_creditcard/creditcard.csv",
                upstream="Kaggle ULB credit-card fraud dataset",
                license_label="See upstream dataset terms",
            ),
        ),
        contamination_notes=(
            "Pass rate measures policy and receipt pipeline behavior, "
            "not calibrated fraud-model accuracy.",
        ),
    ),
    "ieee_cis_fraud": SuiteProvenanceSpec(
        suite="ieee_cis_fraud",
        corpus_name="IEEE-CIS fraud",
        source_kind="external_corpus",
        evaluation_layer="task_and_control_quality",
        summary="Feature-based fraud replay over IEEE-CIS tabular data.",
        selection_method="Sequential row sampling from a resolved CSV path.",
        assets=(
            AssetSpec(
                label="fraud_csv",
                kind="file",
                source_kind="external_corpus",
                relative_path="ieee_cis/ieee_cis_full.csv",
                env_var="AGENTAUTH_CORPUS_IEEE_CIS",
                arl_filename="ieee_cis_full.csv",
                upstream="Kaggle IEEE-CIS Fraud Detection",
                license_label="See upstream dataset terms",
            ),
        ),
    ),
    "paysim_fraud": SuiteProvenanceSpec(
        suite="paysim_fraud",
        corpus_name="PaySim fraud",
        source_kind="external_corpus",
        evaluation_layer="task_and_control_quality",
        summary="Feature-based fraud replay over the PaySim transaction dataset.",
        selection_method="Sequential row sampling from a resolved CSV path.",
        assets=(
            AssetSpec(
                label="fraud_csv",
                kind="file",
                source_kind="external_corpus",
                relative_path="paysim/paysim.csv",
                env_var="AGENTAUTH_CORPUS_PAYSIM",
                arl_filename="paysim.csv",
                upstream="PaySim synthetic mobile-money dataset",
                license_label="See upstream dataset terms",
            ),
        ),
    ),
    "elliptic_fraud": SuiteProvenanceSpec(
        suite="elliptic_fraud",
        corpus_name="Elliptic fraud",
        source_kind="external_corpus",
        evaluation_layer="task_and_control_quality",
        summary="Feature-based fraud replay over Elliptic transaction data.",
        selection_method="Sequential row sampling from a resolved CSV path.",
        assets=(
            AssetSpec(
                label="fraud_csv",
                kind="file",
                source_kind="external_corpus",
                relative_path="elliptic/elliptic_fraud.csv",
                env_var="AGENTAUTH_CORPUS_ELLIPTIC",
                arl_filename="elliptic_fraud.csv",
                upstream="Elliptic Bitcoin transaction dataset",
                license_label="See upstream dataset terms",
            ),
        ),
    ),
    "baf_fraud": SuiteProvenanceSpec(
        suite="baf_fraud",
        corpus_name="BAF fraud",
        source_kind="external_corpus",
        evaluation_layer="task_and_control_quality",
        summary="Feature-based fraud replay over a BAF fraud snapshot.",
        selection_method="Sequential row sampling from a resolved CSV path.",
        assets=(
            AssetSpec(
                label="fraud_csv",
                kind="file",
                source_kind="external_corpus",
                relative_path="baf/baf_base_fraud.csv",
                env_var="AGENTAUTH_CORPUS_BAF",
                arl_filename="baf_base_fraud.csv",
                upstream="BAF fraud benchmark snapshot",
                license_label="See upstream dataset terms",
            ),
        ),
    ),
    "atif_mcp": SuiteProvenanceSpec(
        suite="atif_mcp",
        corpus_name="ATIF MCP trajectories",
        source_kind="repo_corpus",
        evaluation_layer="control_efficacy",
        summary="Replay benchmark over saved MCP agent trajectories.",
        selection_method="Directory-ordered replay of trajectory.json files.",
        assets=(
            AssetSpec(
                label="trajectory_root",
                kind="directory",
                source_kind="repo_corpus",
                relative_path="mcp_agent_trajectory_benchmark",
            ),
        ),
    ),
    "bfcl_caps": SuiteProvenanceSpec(
        suite="bfcl_caps",
        corpus_name="BFCL capability enforcement",
        source_kind="repo_corpus",
        evaluation_layer="control_efficacy",
        summary="Capability-enforcement replay over BFCL question and answer fixtures.",
        selection_method="Question-order replay over paired JSONL assets.",
        assets=(
            AssetSpec(
                label="questions_jsonl",
                kind="file",
                source_kind="repo_corpus",
                relative_path="gorilla/berkeley-function-call-leaderboard/bfcl_eval/data/BFCL_v4_simple_python.json",
            ),
            AssetSpec(
                label="answers_jsonl",
                kind="file",
                source_kind="repo_corpus",
                relative_path="gorilla/berkeley-function-call-leaderboard/bfcl_eval/data/possible_answer/BFCL_v4_simple_python.json",
            ),
        ),
    ),
    "tau2_policy": SuiteProvenanceSpec(
        suite="tau2_policy",
        corpus_name="TAU2 policy tasks",
        source_kind="repo_corpus",
        evaluation_layer="control_efficacy",
        summary="Tool-action replay benchmark over TAU2 domain tasks.",
        selection_method="Configured domain selection with task-order replay.",
        assets=(
            AssetSpec(
                label="domains_root",
                kind="directory",
                source_kind="repo_corpus",
                relative_path="tau2_bench/data/tau2/domains",
            ),
        ),
    ),
    "mcp_bench_tasks": SuiteProvenanceSpec(
        suite="mcp_bench_tasks",
        corpus_name="MCPBench single-runner tasks",
        source_kind="repo_corpus",
        evaluation_layer="control_efficacy",
        summary="Planned-tool replay benchmark over MCPBench tasks.",
        selection_method="Task-order replay from a JSON corpus.",
        assets=(
            AssetSpec(
                label="tasks_json",
                kind="file",
                source_kind="repo_corpus",
                relative_path="mcp_bench/tasks/mcpbench_tasks_single_runner_format.json",
            ),
        ),
    ),
    "swe_session": SuiteProvenanceSpec(
        suite="swe_session",
        corpus_name="SWE session trajectories",
        source_kind="repo_corpus",
        evaluation_layer="plumbing",
        summary="Session logging benchmark over SWE agent trajectory shards.",
        selection_method="Shard-selected parquet replay with one session per instance.",
        assets=(
            AssetSpec(
                label="swe_data_root",
                kind="directory",
                source_kind="repo_corpus",
                relative_path="swe_agent_trajectories/data",
            ),
        ),
    ),
    "red_team": SuiteProvenanceSpec(
        suite="red_team",
        corpus_name="Synthetic red-team controls",
        source_kind="synthetic",
        evaluation_layer="control_efficacy",
        summary="Synthetic adversarial and baseline cases generated in-repo.",
        selection_method="Fixed, code-defined attack set.",
        assets=(
            AssetSpec(
                label="synthetic_cases",
                kind="synthetic",
                source_kind="synthetic",
                notes=("Cases are generated from adapter code, not external corpora.",),
            ),
        ),
        contamination_notes=(
            "Synthetic controls are ideal for development but easier to "
            "optimize against than hidden holdouts.",
        ),
    ),
}


def collect_run_provenance(
    suites: list[SuiteName],
    *,
    options: AdapterOptions,
    cases_by_suite: dict[str, list[BenchmarkCase]],
) -> list[CorpusProvenanceRecord]:
    records: list[CorpusProvenanceRecord] = []
    for suite in suites:
        spec = PROVENANCE_SPECS.get(suite)
        if spec is None:
            continue
        cases = cases_by_suite.get(suite, [])
        sample_mode = None
        shard = None
        shards: list[int] = []
        domains: list[str] = []
        if suite.endswith("_fraud"):
            sample_mode = options.ulb_sample
        if suite == "swe_session":
            shards = list(options.swe_shards)
            shard = shards[0] if len(shards) == 1 else None
        if suite == "tau2_policy":
            domains = list(options.tau2_domains)
        records.append(
            CorpusProvenanceRecord(
                suite=suite,
                corpus_name=spec.corpus_name,
                source_kind=spec.source_kind,
                evaluation_layer=spec.evaluation_layer,
                summary=spec.summary,
                selection_method=spec.selection_method,
                cases_loaded=len(cases),
                sample_mode=sample_mode,
                shard=shard,
                shards=shards,
                domains=domains,
                contamination_notes=list(spec.contamination_notes),
                assets=[_asset_record(asset, suite) for asset in spec.assets],
            )
        )
    return records
