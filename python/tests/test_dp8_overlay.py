"""Tests for DP-8: Session chunk overlay (incremental updates)."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agentauth.capabilities.scoping.index_builder import build_repo_chunk_index
from agentauth.capabilities.scoping.session_overlay import SessionChunkOverlay


@pytest.fixture()
def sample_repo(tmp_path: Path) -> Path:
    (tmp_path / "swe_triage").mkdir()
    (tmp_path / "swe_triage" / "parser.py").write_text(
        textwrap.dedent(
            '''
            """Parser module."""
            from swe_triage.auth import verify_token

            def parse_ticket(raw: str) -> dict:
                verify_token(raw)
                return {"ok": True}
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "swe_triage" / "auth.py").write_text(
        textwrap.dedent(
            '''
            def verify_token(raw: str) -> bool:
                return bool(raw)
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    return tmp_path


def test_overlay_rechunks_changed_file(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    new_text = textwrap.dedent(
        '''
        """Parser module."""
        from swe_triage.auth import verify_token

        def parse_ticket(raw: str) -> dict:
            verify_token(raw)
            return {"ok": True}

        def parse_ticket_v2(raw: str) -> dict:
            return {"v2": True}
        '''
    ).strip() + "\n"

    new_chunks = overlay.update_file("swe_triage/parser.py", new_text)
    assert any(c.qualified_name == "parse_ticket_v2" for c in new_chunks)


def test_overlay_merged_index_contains_new_chunks(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    new_text = textwrap.dedent(
        '''
        def helper() -> None:
            pass
        '''
    ).strip() + "\n"
    overlay.update_file("swe_triage/auth.py", new_text)

    merged = overlay.merged_index()
    assert any(c.qualified_name == "helper" for c in merged.chunks)
    assert not any(
        c.qualified_name == "verify_token"
        and c.file_path == "swe_triage/auth.py"
        for c in merged.chunks
    )


def test_overlay_preserves_untouched_files(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    overlay.update_file("swe_triage/auth.py", "def new_fn(): pass\n")

    merged = overlay.merged_index()
    parser_chunks = [c for c in merged.chunks if c.file_path == "swe_triage/parser.py"]
    assert parser_chunks


def test_overlay_updates_import_edges(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    new_text = "from swe_triage.parser import parse_ticket\ndef call_parser(): pass\n"
    overlay.update_file("swe_triage/auth.py", new_text)

    edges = overlay.merged_import_edges()
    assert ("swe_triage/auth.py", "swe_triage/parser.py") in edges


def test_overlay_changed_files(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    overlay.update_file("swe_triage/auth.py", "x = 1\n")
    assert "swe_triage/auth.py" in overlay.changed_files
    assert "swe_triage/parser.py" not in overlay.changed_files


def test_overlay_reads_from_disk_when_no_text(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    chunks = overlay.update_file("swe_triage/parser.py")
    assert chunks
    assert any(c.qualified_name == "parse_ticket" for c in chunks)
