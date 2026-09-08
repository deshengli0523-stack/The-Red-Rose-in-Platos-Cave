from __future__ import annotations

import ast
from pathlib import Path


def test_client_graph_never_imports_upstream_graph_queries_or_shortest_paths() -> None:
    root = Path(__file__).resolve().parents[3] / "consultation_kb" / "client"
    forbidden_modules = {"graphify.build", "graphify.serve", "graphify.wiki"}
    forbidden_calls = {
        "shortest_path",
        "all_shortest_paths",
        "bidirectional_dijkstra",
        "dijkstra_path",
        "dijkstra_path_length",
    }
    for source_path in root.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not ({alias.name for alias in node.names} & forbidden_modules)
            if isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden_modules
                assert node.module != "networkx.algorithms.shortest_paths"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden_calls
