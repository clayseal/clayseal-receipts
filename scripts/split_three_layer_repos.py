#!/usr/bin/env python3
"""Split agent-receipts monorepo into three layer repos (identity, capabilities, receipts).

Run from monorepo root:
  python scripts/split_three_layer_repos.py --dest ~/Projects
"""
from __future__ import annotations

import argparse
import re
import shutil
import textwrap
from pathlib import Path

MONO = Path(__file__).resolve().parents[1]
VERSION = "0.3.0"

CAPABILITY_MODULES = {
    "commit.py",
    "delegation.py",
    "mandate.py",
    "task_scope.py",
    "value_budget.py",
    "budget.py",
    "capabilities.py",
    "step_up.py",
    "lineage.py",
}

CORE_MODULES = {
    "hash_util.py",
    "signing.py",
    "runtime.py",
    "decision.py",
    "proof.py",
    "_version.py",
    "resource_refs.py",
}

IDENTITY_FILES = [
    "agentauth/identity",
    "agentauth/backend",
    "agentauth/biscuit_scope.py",
    "agentauth/workload_keys.py",
    "backend/tests",
    "sdk/python/tests",
    "examples/01_quickstart.py",
    "examples/02_capabilities.py",
    "examples/common.py",
    "examples/requirements.txt",
    "LICENSE",
    "config/partner.example.yaml",
    "scripts/bootstrap.sh",
]

CAPABILITY_FILES_EXTRA = [
    "python/tests/test_delegation.py",
    "python/tests/test_mandate.py",
    "python/tests/test_task_scope.py",
    "python/tests/test_value_budget.py",
    "python/tests/test_scoping.py",
    "python/tests/test_biscuit_scope.py",
    "python/tests/conftest.py",
    "LICENSE",
]

RECEIPTS_KEEP_IN_RECEIPTS = {
    # everything under receipts/ except capability modules and scoping/
}


def copytree(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def rewrite(content: str, rules: list[tuple[str, str]]) -> str:
    for old, new in rules:
        content = content.replace(old, new)
    return content


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_identity(dest: Path) -> None:
    root = dest / "agentauth-identity"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    for rel in IDENTITY_FILES:
        src = MONO / rel
        if src.exists():
            copytree(src, root / rel)

    # Identity-only FastAPI app (no verifier router)
    main_src = (root / "agentauth/backend/main.py").read_text(encoding="utf-8")
    main_src = main_src.replace(
        "from agentauth.receipts.verifier_auth import (\n"
        "    ApiKeyMiddleware,\n"
        "    RateLimitMiddleware,\n"
        "    rate_limit_per_minute,\n"
        ")\n\n",
        "",
    )
    main_src = main_src.replace(
        "    app.add_middleware(RateLimitMiddleware, limit_per_minute=rate_limit_per_minute())\n"
        "    app.add_middleware(ApiKeyMiddleware, protected_paths={\"/v1/verify\"})\n",
        "",
    )
    main_src = main_src.replace("from .routers import identity, verifier\n", "from .routers import identity\n")
    main_src = main_src.replace("    app.include_router(verifier.router)\n", "")
    main_src = main_src.replace(
        '"-- issues JWT-SVID credentials and verifies receipt bundles."',
        '"-- attested agent identity: JWT-SVID credentials and Biscuit capabilities."',
    )
    write(root / "agentauth/backend/main.py", main_src)

    # Remove wrap() receipts coupling — optional extra documented in README
    session = (root / "agentauth/identity/session.py").read_text(encoding="utf-8")
    wrap_start = session.find("    # --- receipts (L3/L4)")
    wrap_end = session.find("    # --- capabilities (offline)")
    if wrap_start != -1 and wrap_end != -1:
        session = (
            session[:wrap_start]
            + textwrap.dedent(
                """
    # --- receipts (layer 3) ------------------------------------------------
    def wrap(self, model, *, policy, task_mandate=None, **kwargs):
        \"\"\"Optional: requires ``pip install agentauth-receipts``.\"\"\"
        try:
            from agentauth.receipts import AgentWrapper
            from agentauth.receipts.authority_binding import AuthorityBinding
        except ImportError as exc:
            raise ImportError(
                "AgentSession.wrap() requires the receipts layer. "
                "Install with: pip install agentauth-receipts"
            ) from exc
        binding = AuthorityBinding.from_agentauth_credential(
            self.credential.to_binding_dict()
        )
        capability_authorizer = self.authorize if self.credential.biscuit else None
        if task_mandate is not None:
            kwargs["task_mandate"] = task_mandate
        return AgentWrapper(
            model,
            policy,
            default_authority_binding=binding,
            capability_authorizer=capability_authorizer,
            **kwargs,
        )

"""
            )
            + session[wrap_end:]
        )
        write(root / "agentauth/identity/session.py", session)

    write(
        root / "agentauth/__init__.py",
        textwrap.dedent(
            '''"""AgentAuth Identity — attested agent credentials and Biscuit capabilities."""
from agentauth.identity import (
    AgentAuth,
    AgentInfo,
    AgentSession,
    Credential,
    ValidationResult,
)
from agentauth.identity.errors import (
    AgentAuthError,
    AgentNotFoundError,
    AgentRevokedError,
    BiscuitError,
    CapabilityDeniedError,
    InvalidAPIKeyError,
    InvalidTokenError,
    ProofOfPossessionError,
    TokenExpiredError,
    TransportError,
    TTLOutOfRangeError,
)

__version__ = "'''
            + VERSION
            + '''"

__all__ = [
    "__version__",
    "AgentAuth",
    "AgentSession",
    "Credential",
    "AgentInfo",
    "ValidationResult",
    "AgentAuthError",
    "TransportError",
    "InvalidAPIKeyError",
    "InvalidTokenError",
    "TokenExpiredError",
    "AgentRevokedError",
    "AgentNotFoundError",
    "TTLOutOfRangeError",
    "BiscuitError",
    "ProofOfPossessionError",
    "CapabilityDeniedError",
]
''',
        ),
    )

    write(
        root / "pyproject.toml",
        textwrap.dedent(
            f"""
            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"

            [project]
            name = "agentauth-identity"
            version = "{VERSION}"
            description = "AgentAuth layer 1 — attested agent identity and Biscuit capability tokens"
            readme = "README.md"
            license = {{ text = "MIT" }}
            requires-python = ">=3.10,<3.14"
            dependencies = [
              "httpx>=0.27",
              "biscuit-python>=0.4,<0.5",
              "PyJWT>=2.8,<3.0",
              "cryptography>=42.0",
              "fastapi>=0.110,<1.0",
              "uvicorn[standard]>=0.27,<1.0",
              "SQLAlchemy>=2.0,<3.0",
              "pydantic>=2.6,<3.0",
            ]

            [project.optional-dependencies]
            dev = ["pytest>=8.0", "pytest-asyncio>=0.24"]

            [tool.hatch.build.targets.wheel]
            packages = ["agentauth"]

            [tool.pytest.ini_options]
            testpaths = ["backend/tests", "sdk/python/tests"]
            pythonpath = ["."]
            asyncio_mode = "auto"
            """
        ).strip()
        + "\n",
    )

    write(
        root / "README.md",
        textwrap.dedent(
            """
            # AgentAuth Identity (layer 1)

            Attested agent credentials: JWT-SVID identity, Biscuit capability tokens,
            proof-of-possession, and optional hosted FastAPI identity service.

            ## Quickstart

            ```bash
            pip install -e ".[dev]"
            python examples/01_quickstart.py
            ```

            ## Run identity service

            ```bash
            uvicorn agentauth.backend.main:app --reload
            ```

            Layer 2 (dynamic capabilities): [agentauth-capabilities](https://github.com/pberlizov/agentauth-capabilities)
            Layer 3 (receipts + verify): [agentauth-receipts](https://github.com/pberlizov/agentauth-receipts)
            """
        ).strip()
        + "\n",
    )

    write(root / ".gitignore", (MONO / ".gitignore").read_text(encoding="utf-8"))


def build_capabilities(dest: Path, identity_repo: str) -> None:
    root = dest / "agentauth-capabilities"
    if root.exists():
        shutil.rmtree(root)
    (root / "agentauth/core").mkdir(parents=True)
    (root / "agentauth/capabilities").mkdir(parents=True)

    receipts = MONO / "agentauth/receipts"
    for name in CORE_MODULES:
        copytree(receipts / name, root / "agentauth/core" / name)

    for name in CAPABILITY_MODULES:
        dst_name = "operations.py" if name == "capabilities.py" else name
        copytree(receipts / name, root / "agentauth/capabilities" / dst_name)

    copytree(receipts / "scoping", root / "agentauth/capabilities/scoping")

    for rel in CAPABILITY_FILES_EXTRA:
        src = MONO / rel
        if src.exists():
            copytree(src, root / rel)

    # __init__ files
    write(
        root / "agentauth/core/__init__.py",
        'from agentauth.core.hash_util import hash_canonical_json, sha256_hex\n'
        'from agentauth.core.signing import SigningKey, generate_keypair, load_or_create_key, sign_bundle, verify\n'
        'from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext, SideEffectLevel\n'
        'from agentauth.core.decision import DecisionResult, DecisionOutcome\n'
        'from agentauth.receipts.proof import ExecutionProof\n'
        '__all__ = ["hash_canonical_json", "sha256_hex", "SigningKey", "generate_keypair", '
        '"ActionDescriptor", "AuthorityContext", "ExecutionContext", "DecisionResult", "ExecutionProof"]\n',
    )

    cap_init = (MONO / "agentauth/receipts/scoping/__init__.py").read_text(encoding="utf-8")
    write(root / "agentauth/capabilities/__init__.py", "")  # filled after rewrite pass

    # Rewrite all python files in capabilities repo
    rules = [
        ("agentauth.core.hash_util", "agentauth.core.hash_util"),
        ("agentauth.core.signing", "agentauth.core.signing"),
        ("agentauth.core.runtime", "agentauth.core.runtime"),
        ("agentauth.core.decision", "agentauth.core.decision"),
        ("agentauth.receipts.proof", "agentauth.receipts.proof"),
        ("agentauth.capabilities.scoping", "agentauth.capabilities.scoping"),
        ("agentauth.capabilities.commit", "agentauth.capabilities.commit"),
        ("agentauth.capabilities.delegation", "agentauth.capabilities.delegation"),
        ("agentauth.capabilities.mandate", "agentauth.capabilities.mandate"),
        ("agentauth.capabilities.task_scope", "agentauth.capabilities.task_scope"),
        ("agentauth.capabilities.value_budget", "agentauth.capabilities.value_budget"),
        ("agentauth.capabilities.budget", "agentauth.capabilities.budget"),
        ("agentauth.capabilities.operations", "agentauth.capabilities.operations"),
        ("agentauth.capabilities.step_up", "agentauth.capabilities.step_up"),
        ("agentauth.capabilities.lineage", "agentauth.capabilities.lineage"),
        ("agentauth.core.resource_refs", "agentauth.core.resource_refs"),
    ]

    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for old, new in rules:
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")

    write(
        root / "agentauth/capabilities/__init__.py",
        textwrap.dedent(
            """
            from agentauth.capabilities.commit import CommitToken, SignedCommitToken, issue_commit_token, verify_commit_token
            from agentauth.capabilities.delegation import DelegationToken, issue_delegation, sign_delegation, verify_delegation_chain
            from agentauth.capabilities.mandate import Mandate, issue_mandate, verify_mandate_signature
            from agentauth.capabilities.task_scope import TaskScope, compile_task_scope
            from agentauth.capabilities.value_budget import SessionValueBudget, ValueBudgetConfig
            from agentauth.capabilities.scoping import GoalSpec, CapabilityLease, build_capability_lease, build_repo_chunk_index
            from agentauth.capabilities.operations import capability_allows, operation_for_action, operation_for_mcp_tool

            __all__ = [
                "CommitToken", "SignedCommitToken", "issue_commit_token", "verify_commit_token",
                "DelegationToken", "issue_delegation", "sign_delegation", "verify_delegation_chain",
                "Mandate", "issue_mandate", "verify_mandate_signature",
                "TaskScope", "compile_task_scope",
                "SessionValueBudget", "ValueBudgetConfig",
                "GoalSpec", "CapabilityLease", "build_capability_lease", "build_repo_chunk_index",
                "capability_allows", "operation_for_action", "operation_for_mcp_tool",
            ]
            """
        ).strip()
        + "\n",
    )

    write(
        root / "agentauth/__init__.py",
        f'__version__ = "{VERSION}"\n',
    )

    write(
        root / "examples/03_commit_token.py",
        textwrap.dedent(
            '''"""Standalone commit-token mint and verify (layer 2)."""
            from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext
            from agentauth.core.signing import generate_keypair
            from agentauth.capabilities.commit import issue_commit_token, verify_commit_token

            key = generate_keypair()
            args = {"employee_id": "emp_001", "bonus_amount": 100}
            ctx = ExecutionContext(
                action=ActionDescriptor(
                    action_name="mcp.tools/call/issue_payroll_bonus",
                    resource_ref="rippling-hr:issue_payroll_bonus",
                ),
                input=args,
                authority=AuthorityContext(authority_id="rippling-action-agent", tenant_id="ten_demo"),
                query_id="q-demo",
            )
            signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
            ok, reason = verify_commit_token(signed, ctx=ctx)
            print("verified:", ok, reason)
            assert ok
            '''
        ).strip()
        + "\n",
    )

    write(
        root / "pyproject.toml",
        textwrap.dedent(
            f"""
            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"

            [project]
            name = "agentauth-capabilities"
            version = "{VERSION}"
            description = "AgentAuth layer 2 — dynamic capability tokens, leases, commit tokens, mandates"
            readme = "README.md"
            license = {{ text = "MIT" }}
            requires-python = ">=3.10,<3.14"
            dependencies = [
              "agentauth-identity @ git+https://github.com/pberlizov/agentauth-identity.git@v{VERSION}",
              "cryptography>=42.0",
              "pyyaml>=6.0",
            ]

            [project.optional-dependencies]
            dev = ["pytest>=8.0"]

            [tool.hatch.build.targets.wheel]
            packages = ["agentauth"]

            [tool.hatch.metadata]
            allow-direct-references = true

            [tool.pytest.ini_options]
            testpaths = ["python/tests"]
            pythonpath = ["."]
            """
        ).strip()
        + "\n",
    )

    write(
        root / "README.md",
        textwrap.dedent(
            """
            # AgentAuth Capabilities (layer 2)

            Dynamic capability narrowing: Biscuit attenuation (via identity), commit tokens,
            delegation, mandates, goal-bound leases, session value budgets.

            ## Quickstart

            ```bash
            pip install -e ".[dev]"
            python examples/03_commit_token.py
            ```

            Depends on [agentauth-identity](https://github.com/pberlizov/agentauth-identity) v0.3.0+.
            """
        ).strip()
        + "\n",
    )

    write(root / ".gitignore", (MONO / ".gitignore").read_text(encoding="utf-8"))
    write(root / "LICENSE", (MONO / "LICENSE").read_text(encoding="utf-8"))


def build_receipts(dest: Path) -> None:
    root = dest / "agentauth-receipts"
    if root.exists():
        shutil.rmtree(root)

    # Copy most of monorepo except agentauth/identity, backend identity-only paths, and moved capability files
    SKIP_DIRS = {".git", ".venv", "artifacts", "__pycache__", ".pytest_cache", ".ruff_cache"}
    for item in MONO.iterdir():
        if item.name in SKIP_DIRS or item.name.startswith("."):
            continue
        if item.name == "agentauth":
            continue
        copytree(item, root / item.name)

    # agentauth package: receipts layer only
    (root / "agentauth").mkdir(exist_ok=True)
    shutil.copy2(MONO / "agentauth/biscuit_scope.py", root / "agentauth/biscuit_scope.py")
    shutil.copy2(MONO / "agentauth/workload_keys.py", root / "agentauth/workload_keys.py")

    receipts_src = MONO / "agentauth/receipts"
    receipts_dst = root / "agentauth/receipts"
    receipts_dst.mkdir(exist_ok=True)

    for path in receipts_src.rglob("*"):
        if path.is_dir():
            continue
        rel = path.relative_to(receipts_src)
        if rel.parts and rel.parts[0] == "scoping":
            continue
        if path.name in CAPABILITY_MODULES:
            continue
        if path.name in CORE_MODULES:
            continue
        copytree(path, receipts_dst / rel)

    # Remove verifier from backend in receipts? Keep full backend with verifier - receipts owns verify
    copytree(MONO / "agentauth/backend", root / "agentauth/backend")
    copytree(MONO / "agentauth/identity", root / "agentauth/identity")

    rules = [
        ("agentauth.core.hash_util", "agentauth.core.hash_util"),
        ("agentauth.core.signing", "agentauth.core.signing"),
        ("agentauth.core.runtime", "agentauth.core.runtime"),
        ("agentauth.core.decision", "agentauth.core.decision"),
        ("agentauth.receipts.proof", "agentauth.receipts.proof"),
        ("agentauth.capabilities.scoping", "agentauth.capabilities.scoping"),
        ("agentauth.capabilities.commit", "agentauth.capabilities.commit"),
        ("agentauth.capabilities.delegation", "agentauth.capabilities.delegation"),
        ("agentauth.capabilities.mandate", "agentauth.capabilities.mandate"),
        ("agentauth.capabilities.task_scope", "agentauth.capabilities.task_scope"),
        ("agentauth.capabilities.value_budget", "agentauth.capabilities.value_budget"),
        ("agentauth.capabilities.budget", "agentauth.capabilities.budget"),
        ("agentauth.capabilities.operations", "agentauth.capabilities.operations"),
        ("agentauth.capabilities.step_up", "agentauth.capabilities.step_up"),
        ("agentauth.capabilities.lineage", "agentauth.capabilities.lineage"),
        ("agentauth.core.resource_refs", "agentauth.core.resource_refs"),
    ]

    for path in root.rglob("*.py"):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for old, new in rules:
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")

    # Shim: re-export core + capabilities under agentauth.receipts for backward compat in remaining files
    write(
        root / "agentauth/core_shim.py",
        "# Installed via agentauth-capabilities dependency\n",
    )

    write(
        root / "pyproject.toml",
        (MONO / "pyproject.toml")
        .read_text(encoding="utf-8")
        .replace('name = "agentauth-receipts"', 'name = "agentauth-receipts"')
        .replace('version = "0.2.1"', f'version = "{VERSION}"')
        .replace(
            'dependencies = [',
            textwrap.dedent(
                f"""
            dependencies = [
              "agentauth-identity @ git+https://github.com/pberlizov/agentauth-identity.git@v{VERSION}",
              "agentauth-capabilities @ git+https://github.com/pberlizov/agentauth-capabilities.git@v{VERSION}",
            """
            ).strip()
            + "\n  ",
        ),
    )

    # Fix pyproject - read original and patch properly
    orig = (MONO / "pyproject.toml").read_text(encoding="utf-8")
    orig = orig.replace('version = "0.2.1"', f'version = "{VERSION}"')
    deps_start = orig.index("dependencies = [")
    deps_end = orig.index("]", deps_start) + 1
    new_deps = textwrap.dedent(
        f"""
        dependencies = [
          "agentauth-identity @ git+https://github.com/pberlizov/agentauth-identity.git@v{VERSION}",
          "agentauth-capabilities @ git+https://github.com/pberlizov/agentauth-capabilities.git@v{VERSION}",
          "pyyaml>=6.0",
          "cryptography>=42.0",
          "cbor2>=5.4",
          "httpx>=0.27",
          "biscuit-python>=0.4,<0.5",
          "PyJWT>=2.8,<3.0",
        ]
        """
    ).strip()
    orig = orig[:deps_start] + new_deps + orig[deps_end:]
    if "[tool.hatch.metadata]" not in orig:
        orig = orig.replace(
            "[tool.hatch.build.targets.wheel]",
            "[tool.hatch.metadata]\nallow-direct-references = true\n\n[tool.hatch.build.targets.wheel]",
        )
    write(root / "pyproject.toml", orig)

    write(
        root / "README.md",
        (MONO / "README.md").read_text(encoding="utf-8")[:2000]
        + textwrap.dedent(
            """

            ## Three-layer install

            This repo is layer 3 (receipts + verification). It depends on:

            - [agentauth-identity](https://github.com/pberlizov/agentauth-identity)
            - [agentauth-capabilities](https://github.com/pberlizov/agentauth-capabilities)

            ```bash
            pip install -e ".[dev]"
            python demo/poisoned_mcp_demo.py
            arctl doctor
            ```
            """
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", type=Path, default=Path.home() / "Projects")
    args = parser.parse_args()

    build_identity(args.dest)
    build_capabilities(args.dest, "pberlizov/agentauth-identity")
    build_receipts(args.dest)
    print(f"Created layer repos under {args.dest}")
    print("  agentauth-identity")
    print("  agentauth-capabilities")
    print("  agentauth-receipts")


if __name__ == "__main__":
    main()
