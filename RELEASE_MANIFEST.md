# Private consultation knowledge-base snapshot

This repository is a clean source snapshot of the Graphify-based consultation
knowledge-base system.

## Source identity

- Source branch: `consultation-kb-design`
- Source commit: `e6c004a72ad80e05ef9fe6efb6ce59b51b2e300e`
- Source tree: `fedd4c3f8a1d346f1e5b340367f1a79662ae64a4`
- Snapshot date: `2026-09-07`

## Packaging boundary

The snapshot contains the application source, tests, policies, schemas,
Codex/MCP integration files, governed synthetic fixtures, formal operations
documentation, and the upstream license.

It intentionally excludes internal development plans under `docs/superpowers/`,
Git history, local virtual environments, model weights, generated indexes,
test caches, worktrees, vault contents, databases, secrets, local Codex
configuration, and all client or consultation records.

The repository therefore contains no production knowledge corpus. Knowledge
materials, local embedding/reranker model snapshots, and the encrypted vault
must be provisioned separately according to `docs/consultation-kb/operations.md`.
