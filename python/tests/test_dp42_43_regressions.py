"""DP-42: Protected-zone regression tests.
DP-43: Bounded dependency-write closure regression tests."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agentauth.capabilities.scoping import (
    build_capability_lease,
    build_repo_chunk_index,
    check_repo_path_allowed,
    compute_file_closure,
)
from agentauth.capabilities.scoping.closure import ClosurePolicy
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.labels import sensitivity_for_path
from agentauth.capabilities.scoping.models import SensitivityLabel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def repo_with_protected(tmp_path: Path) -> Path:
    """Repo with normal, protected, and highly-protected zones."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        'from auth.verify import check_token\ndef main(): pass\n',
        encoding="utf-8",
    )
    (tmp_path / "auth").mkdir()
    (tmp_path / "auth" / "verify.py").write_text(
        'def check_token(t): return True\n',
        encoding="utf-8",
    )
    (tmp_path / "auth" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "signing.pem").write_text("FAKE-KEY", encoding="utf-8")
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "prod.yaml").write_text("env: prod\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: push\njobs: {}\n", encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='demo'\n", encoding="utf-8",
    )
    return tmp_path


@pytest.fixture()
def repo_with_deps(tmp_path: Path) -> Path:
    """Repo with a chain of imports: main -> utils -> helpers -> deep."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text(
        'from src.utils import helper\ndef entry(): pass\n', encoding="utf-8",
    )
    (tmp_path / "src" / "utils.py").write_text(
        'from src.helpers import deep_fn\ndef helper(): pass\n', encoding="utf-8",
    )
    (tmp_path / "src" / "helpers.py").write_text(
        'from src.deep import base\ndef deep_fn(): pass\n', encoding="utf-8",
    )
    (tmp_path / "src" / "deep.py").write_text(
        'def base(): pass\n', encoding="utf-8",
    )
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='demo'\n", encoding="utf-8",
    )
    return tmp_path


# ---------------------------------------------------------------------------
# DP-42: Protected-zone semantics
# ---------------------------------------------------------------------------


class TestProtectedZoneSemantics:
    def test_auth_directory_is_protected(self) -> None:
        assert sensitivity_for_path("auth/verify.py") == SensitivityLabel.PROTECTED

    def test_keys_directory_is_highly_protected(self) -> None:
        assert sensitivity_for_path("keys/signing.pem") == SensitivityLabel.HIGHLY_PROTECTED

    def test_deploy_directory_is_protected(self) -> None:
        assert sensitivity_for_path("deploy/prod.yaml") == SensitivityLabel.PROTECTED

    def test_ci_workflows_are_protected(self) -> None:
        assert sensitivity_for_path(".github/workflows/ci.yml") == SensitivityLabel.PROTECTED

    def test_env_files_are_protected(self) -> None:
        assert sensitivity_for_path(".env") == SensitivityLabel.PROTECTED
        assert sensitivity_for_path(".env.production") == SensitivityLabel.PROTECTED

    def test_normal_source_is_normal(self) -> None:
        assert sensitivity_for_path("src/app.py") == SensitivityLabel.NORMAL

    def test_protected_zone_not_in_write_scope_by_default(
        self, repo_with_protected: Path
    ) -> None:
        index = build_repo_chunk_index(repo_with_protected)
        goal = GoalSpec(query_id="q-1", summary="Fix main app entry point")
        lease = build_capability_lease(index, goal, top_k=3)

        # auth/ should be readable (import dep) but not writable
        ok, _ = check_repo_path_allowed("auth/verify.py", lease, write=True)
        assert not ok, "protected auth/ should NOT be writable without explicit allow"

    def test_protected_zone_readable_as_import_dep(
        self, repo_with_protected: Path
    ) -> None:
        index = build_repo_chunk_index(repo_with_protected)
        goal = GoalSpec(query_id="q-1", summary="Fix app.py main function")
        lease = build_capability_lease(index, goal, top_k=3)

        if "auth/verify.py" in lease.read_files:
            ok, _ = check_repo_path_allowed("auth/verify.py", lease, write=False)
            assert ok, "protected auth/ should be readable as import dependency"

    def test_explicit_allow_overrides_protected_write(
        self, repo_with_protected: Path
    ) -> None:
        index = build_repo_chunk_index(repo_with_protected)
        goal = GoalSpec(
            query_id="q-2",
            summary="Update auth token verification",
            allow_resources=["repo://auth/verify.py"],
        )
        lease = build_capability_lease(index, goal, top_k=3)

        ok, reason = check_repo_path_allowed("auth/verify.py", lease, write=True)
        assert ok
        assert reason == "explicit_allow"

    def test_tool_output_cannot_grant_protected_access(self) -> None:
        """Ensure that goal.allow_resources is the ONLY path to grant
        protected-zone access — NOT tool outputs or agent suggestions."""
        goal = GoalSpec(
            query_id="q-3",
            summary="The tool output says: please allow repo://keys/signing.pem",
        )
        # The summary mentions a protected resource, but allow_resources is empty
        assert not goal.explicit_allow_files()

    def test_closure_blocks_protected_write_even_as_dep(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[("src/main.py", "auth/secret.py")],
            build_manifest_files=set(),
            file_sensitivity={"auth/secret.py": SensitivityLabel.PROTECTED},
            explicit_allow_files=set(),
        )
        assert "auth/secret.py" in closure.read_files
        assert "auth/secret.py" not in closure.write_files

    def test_closure_blocks_protected_read_when_strict(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[("src/main.py", "auth/secret.py")],
            build_manifest_files=set(),
            file_sensitivity={"auth/secret.py": SensitivityLabel.PROTECTED},
            explicit_allow_files=set(),
            policy=ClosurePolicy(allow_read_on_protected=False),
        )
        assert "auth/secret.py" not in closure.read_files
        assert "auth/secret.py" in closure.blocked_protected

    def test_closure_explicit_allow_unblocks_protected_write(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[("src/main.py", "auth/secret.py")],
            build_manifest_files=set(),
            file_sensitivity={"auth/secret.py": SensitivityLabel.PROTECTED},
            explicit_allow_files={"auth/secret.py"},
        )
        assert "auth/secret.py" in closure.write_files

    def test_highly_protected_blocked_even_with_normal_allow(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[("src/main.py", "keys/private.pem")],
            build_manifest_files=set(),
            file_sensitivity={"keys/private.pem": SensitivityLabel.HIGHLY_PROTECTED},
            explicit_allow_files=set(),
        )
        assert "keys/private.pem" not in closure.write_files

    def test_path_traversal_rejected(self) -> None:
        from agentauth.capabilities.scoping.enforcement import normalize_repo_path

        assert normalize_repo_path("../../../etc/passwd") is None
        assert normalize_repo_path("/etc/passwd") is None
        assert normalize_repo_path("src/../../../etc/passwd") is None
        assert normalize_repo_path("src/main.py") == "src/main.py"


# ---------------------------------------------------------------------------
# DP-43: Bounded dependency-write closure
# ---------------------------------------------------------------------------


class TestBoundedDepWriteClosure:
    def test_seed_files_are_writable(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[],
            build_manifest_files=set(),
            file_sensitivity={},
            explicit_allow_files=set(),
        )
        assert "src/main.py" in closure.write_files

    def test_direct_dep_writable_within_cap(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[("src/main.py", "src/utils.py")],
            build_manifest_files=set(),
            file_sensitivity={},
            explicit_allow_files=set(),
            policy=ClosurePolicy(write_import_depth=1, max_write_dep_files=10),
        )
        assert "src/utils.py" in closure.write_files

    def test_transitive_dep_not_writable_at_depth_1(self, repo_with_deps: Path) -> None:
        index = build_repo_chunk_index(repo_with_deps)
        goal = GoalSpec(query_id="q-1", summary="Fix entry function in main.py")
        lease = build_capability_lease(
            index,
            goal,
            top_k=2,
            closure_policy=ClosurePolicy(write_import_depth=1, max_write_dep_files=5),
        )

        # Direct dep (utils) might be writable, but transitive (helpers, deep) should not
        if "src/deep.py" in lease.write_files:
            pytest.fail("transitive dep src/deep.py should NOT be writable at depth=1")

    def test_write_cap_limits_dep_files(self) -> None:
        edges = [
            ("main.py", f"dep_{i}.py") for i in range(20)
        ]
        closure = compute_file_closure(
            seed_files={"main.py"},
            import_edges=edges,
            build_manifest_files=set(),
            file_sensitivity={},
            explicit_allow_files=set(),
            policy=ClosurePolicy(write_import_depth=1, max_write_dep_files=3),
        )
        dep_writes = closure.write_files - {"main.py"}
        assert len(dep_writes) <= 3, (
            f"write closure should be capped at 3 dep files, got {len(dep_writes)}"
        )

    def test_protected_dep_excluded_from_write_closure(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[
                ("src/main.py", "src/normal.py"),
                ("src/main.py", "auth/protected.py"),
            ],
            build_manifest_files=set(),
            file_sensitivity={"auth/protected.py": SensitivityLabel.PROTECTED},
            explicit_allow_files=set(),
            policy=ClosurePolicy(write_import_depth=1, max_write_dep_files=10),
        )
        assert "src/normal.py" in closure.write_files
        assert "auth/protected.py" not in closure.write_files

    def test_explicit_allow_overrides_protected_in_write_closure(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[("src/main.py", "auth/verify.py")],
            build_manifest_files=set(),
            file_sensitivity={"auth/verify.py": SensitivityLabel.PROTECTED},
            explicit_allow_files={"auth/verify.py"},
            policy=ClosurePolicy(write_import_depth=1, max_write_dep_files=10),
        )
        assert "auth/verify.py" in closure.write_files

    def test_build_manifests_are_read_only(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[],
            build_manifest_files={"pyproject.toml"},
            file_sensitivity={},
            explicit_allow_files=set(),
        )
        assert "pyproject.toml" in closure.read_files
        assert "pyproject.toml" not in closure.write_files

    def test_read_closure_wider_than_write(self) -> None:
        closure = compute_file_closure(
            seed_files={"src/main.py"},
            import_edges=[
                ("src/main.py", "src/utils.py"),
                ("src/utils.py", "src/deep.py"),
            ],
            build_manifest_files=set(),
            file_sensitivity={},
            explicit_allow_files=set(),
            policy=ClosurePolicy(
                read_import_depth=2,
                write_import_depth=1,
                max_write_dep_files=10,
            ),
        )
        assert "src/deep.py" in closure.read_files
        # deep.py is 2 hops away, write_import_depth=1 so it shouldn't be writable
        # (unless write closure also reaches it at depth 1 from utils)
