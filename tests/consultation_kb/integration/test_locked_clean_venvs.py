from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import networkx as nx
import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from graphify.cluster import cluster_with_metadata


@dataclass(frozen=True, slots=True)
class _Target:
    python: tuple[int, int]
    profile: Literal["core", "ml"]
    lock_name: str
    graph_backend: Literal["leiden", "louvain"]
    degraded: bool


_TARGETS = {
    "py312-core": _Target(
        (3, 12), "core", "consultation-win-py312.lock.txt", "leiden", False
    ),
    "py312-ml": _Target(
        (3, 12), "ml", "consultation-ml-win-py312.lock.txt", "leiden", False
    ),
    "py313-core": _Target(
        (3, 13), "core", "consultation-win-py313.lock.txt", "louvain", True
    ),
    "py313-ml": _Target(
        (3, 13), "ml", "consultation-ml-win-py313.lock.txt", "louvain", True
    ),
}
_TARGET_NAME = os.environ.get("CONSULTATION_LOCK_TARGET")
_TARGET = _TARGETS.get(_TARGET_NAME or "")

pytestmark = pytest.mark.skipif(
    _TARGET is None,
    reason="requires an explicitly selected clean locked environment",
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _lock_requirements(target: _Target) -> tuple[Requirement, ...]:
    text = (_repo_root() / "requirements" / target.lock_name).read_text(
        encoding="utf-8"
    )
    requirements: list[Requirement] = []
    for line in text.splitlines():
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:==| @ )", line):
            continue
        candidate = line.partition(" --hash=")[0].rstrip()
        if candidate.endswith("\\"):
            candidate = candidate[:-1].rstrip()
        requirements.append(Requirement(candidate))
    return tuple(requirements)


def test_locked_environment_matches_every_active_pin() -> None:
    assert _TARGET is not None
    assert sys.platform == "win32"
    assert sys.version_info[:2] == _TARGET.python

    for requirement in _lock_requirements(_TARGET):
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        installed = Version(importlib.metadata.version(requirement.name))
        if requirement.url is not None:
            assert canonicalize_name(requirement.name) == "torch"
            assert installed == Version("2.13.0+cpu")
            continue
        specifiers = list(requirement.specifier)
        assert len(specifiers) == 1 and specifiers[0].operator == "=="
        assert installed == Version(specifiers[0].version)


def test_locked_environment_core_runtime_contract() -> None:
    assert _TARGET is not None
    for module_name in (
        "consultation_kb",
        "graphify",
        "jieba",
        "mcp",
        "networkx",
        "numpy",
        "pydantic",
        "win32crypt",
        "yaml",
    ):
        importlib.import_module(module_name)

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE VIRTUAL TABLE lock_probe USING fts5(value)")
        connection.execute("INSERT INTO lock_probe(value) VALUES ('synthetic probe')")
        row = connection.execute(
            "SELECT count(*) FROM lock_probe WHERE lock_probe MATCH 'synthetic'"
        ).fetchone()
        assert row == (1,)
    finally:
        connection.close()

    win32crypt = importlib.import_module("win32crypt")
    probe = b"consultation-lock-synthetic-probe"
    protected = win32crypt.CryptProtectData(
        probe,
        "consultation-lock-probe",
        b"lock-contract-v1",
        None,
        None,
        0,
    )
    _description, recovered = win32crypt.CryptUnprotectData(
        protected,
        b"lock-contract-v1",
        None,
        None,
        0,
    )
    assert recovered == probe

    server_module = importlib.import_module("consultation_kb.mcp.server")
    lifespan_module = importlib.import_module("consultation_kb.mcp.lifespan")
    mcp_module = importlib.import_module("consultation_kb.mcp")
    server = server_module.create_mcp(
        services=lifespan_module.DeferredHandlerServices()
    )
    tools = asyncio.run(server.list_tools())
    assert tuple(tool.name for tool in tools) == mcp_module.P9_TOOL_NAMES


def test_locked_environment_graph_backend_contract() -> None:
    assert _TARGET is not None
    graph: nx.Graph[str] = nx.Graph()
    graph.add_edges_from((("alpha", "beta"), ("beta", "gamma"), ("gamma", "delta")))
    result = cluster_with_metadata(graph, seed=42)
    assert result.backend == _TARGET.graph_backend
    assert result.degraded is _TARGET.degraded
    assert result.reproducible is True


def test_locked_environment_ml_is_cpu_only() -> None:
    assert _TARGET is not None
    if _TARGET.profile != "ml":
        pytest.skip("core lock intentionally excludes ML dependencies")
    sentence_transformers = importlib.import_module("sentence_transformers")
    torch = importlib.import_module("torch")
    assert sentence_transformers.__version__
    assert torch.__version__ == "2.13.0+cpu"
    assert torch.cuda.is_available() is False
