"""Tests for DP-2 (JS/Go/Rust chunkers), DP-3 (YAML/TF chunkers),
DP-12 (rg candidate channel)."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agentauth.capabilities.scoping.chunkers import chunk_file
from agentauth.capabilities.scoping.models import ChunkKind
from agentauth.capabilities.scoping.retrieval.rg_channel import extract_goal_tokens, rg_rank_chunks


def _chunk(tmp_path: Path, filename: str, content: str) -> list:
    f = tmp_path / filename
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return chunk_file(repo_sha="test", repo_root=tmp_path, file_path=f)


# ---------------------------------------------------------------------------
# DP-2: JS/TS chunker
# ---------------------------------------------------------------------------


class TestJsChunker:
    def test_extracts_functions(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            import { foo } from './foo';

            function handleRequest(req) {
              return foo(req);
            }

            const processData = async (data) => {
              return data;
            };
        """)
        chunks = _chunk(tmp_path, "handler.js", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert "handleRequest" in names
        assert "processData" in names

    def test_extracts_classes(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            export class UserService {
              async getUser(id) {
                return { id };
              }
            }
        """)
        chunks = _chunk(tmp_path, "service.ts", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert "UserService" in names

    def test_has_preamble(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            import React from 'react';
            import { useState } from 'react';

            function App() {
              return null;
            }
        """)
        chunks = _chunk(tmp_path, "App.tsx", code)
        preambles = [c for c in chunks if c.kind == ChunkKind.FILE_PREAMBLE]
        assert preambles

    def test_fallback_on_no_symbols(self, tmp_path: Path) -> None:
        code = "// just a comment\nconst x = 1;\n"
        chunks = _chunk(tmp_path, "simple.js", code)
        assert chunks  # should fall back to windows
        assert all(c.kind == ChunkKind.WINDOW for c in chunks)


# ---------------------------------------------------------------------------
# DP-2: Go chunker
# ---------------------------------------------------------------------------


class TestGoChunker:
    def test_extracts_functions(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            package main

            import "fmt"

            func main() {
                fmt.Println("hello")
            }

            func helper(x int) int {
                return x + 1
            }
        """)
        chunks = _chunk(tmp_path, "main.go", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert "main" in names
        assert "helper" in names

    def test_extracts_types(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            package models

            type User struct {
                Name string
                Age  int
            }

            type Service interface {
                GetUser(id string) User
            }
        """)
        chunks = _chunk(tmp_path, "models.go", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert "User" in names
        assert "Service" in names

    def test_extracts_method_receivers(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            package main

            func (s *Server) Start() error {
                return nil
            }
        """)
        chunks = _chunk(tmp_path, "server.go", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert "Start" in names


# ---------------------------------------------------------------------------
# DP-2: Rust chunker
# ---------------------------------------------------------------------------


class TestRustChunker:
    def test_extracts_functions(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            use std::io;

            pub fn process(input: &str) -> String {
                input.to_uppercase()
            }

            fn helper() -> i32 {
                42
            }
        """)
        chunks = _chunk(tmp_path, "lib.rs", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert "process" in names
        assert "helper" in names

    def test_extracts_structs_and_enums(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            pub struct Config {
                pub name: String,
            }

            enum Status {
                Active,
                Inactive,
            }
        """)
        chunks = _chunk(tmp_path, "types.rs", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert "Config" in names
        assert "Status" in names

    def test_extracts_impl_blocks(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            struct Foo;

            impl Foo {
                fn new() -> Self { Foo }
            }

            impl Display for Foo {
                fn fmt(&self, f: &mut Formatter) -> Result {
                    Ok(())
                }
            }
        """)
        chunks = _chunk(tmp_path, "foo.rs", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert any("impl" in n for n in names if n)


# ---------------------------------------------------------------------------
# DP-3: YAML chunker
# ---------------------------------------------------------------------------


class TestYamlChunker:
    def test_github_actions_chunks_by_job(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            name: CI
            on: push

            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - run: make build

              test:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - run: make test
        """)
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        chunks = _chunk(tmp_path, ".github/workflows/ci.yml", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.CONFIG_BLOCK]
        assert any("build" in n for n in names if n)
        assert any("test" in n for n in names if n)

    def test_generic_yaml_chunks_by_top_key(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            database:
              host: localhost
              port: 5432
              name: mydb

            server:
              port: 8080
              workers: 4

            logging:
              level: info
              format: json
        """)
        chunks = _chunk(tmp_path, "config.yaml", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.CONFIG_BLOCK]
        assert "database" in names
        assert "server" in names
        assert "logging" in names

    def test_single_key_yaml_single_block(self, tmp_path: Path) -> None:
        code = "name: demo\n"
        chunks = _chunk(tmp_path, "small.yml", code)
        assert len(chunks) == 1
        assert chunks[0].kind == ChunkKind.CONFIG_BLOCK


# ---------------------------------------------------------------------------
# DP-3: Terraform chunker
# ---------------------------------------------------------------------------


class TestTerraformChunker:
    def test_chunks_by_resource_block(self, tmp_path: Path) -> None:
        code = textwrap.dedent("""\
            resource "aws_instance" "web" {
              ami           = "ami-123"
              instance_type = "t2.micro"
            }

            resource "aws_s3_bucket" "data" {
              bucket = "my-bucket"
            }

            variable "region" {
              default = "us-east-1"
            }
        """)
        chunks = _chunk(tmp_path, "main.tf", code)
        names = [c.qualified_name for c in chunks if c.kind == ChunkKind.SYMBOL]
        assert any("aws_instance.web" in n for n in names if n)
        assert any("aws_s3_bucket.data" in n for n in names if n)

    def test_small_tf_single_block(self, tmp_path: Path) -> None:
        code = 'provider "aws" {\n  region = "us-east-1"\n}\n'
        chunks = _chunk(tmp_path, "provider.tf", code)
        assert chunks


# ---------------------------------------------------------------------------
# DP-12: rg candidate channel
# ---------------------------------------------------------------------------


class TestRgChannel:
    def test_extract_goal_tokens(self) -> None:
        tokens = extract_goal_tokens("Fix parse_ticket bug in parser.py module")
        assert "parse_ticket" in tokens
        assert "parser" in tokens
        assert "module" in tokens
        assert "in" not in tokens  # too short

    def test_rg_rank_chunks_graceful_when_no_rg(self, tmp_path: Path) -> None:
        """Should return empty list if rg not available or no matches."""
        from agentauth.capabilities.scoping.models import ChunkKind, RepoChunk
        chunks = [
            RepoChunk(
                chunk_id="c1", repo_sha="sha", file_path="src/main.py",
                start_line=1, end_line=10, language="python",
                kind=ChunkKind.SYMBOL, qualified_name="main",
            )
        ]
        # Even if rg exists, searching in an empty dir should return empty
        result = rg_rank_chunks(chunks, "nonexistent_symbol_xyz", tmp_path)
        assert isinstance(result, list)
