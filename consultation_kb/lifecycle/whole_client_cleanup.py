"""Approval-bound final removal of one retired client vault.

The coordinator consumes only a global v6 ``physical_delete`` intent for the
client authority row.  It retains the global catalog row, tombstones and audit
records; this module performs verified physical removal and deliberately makes
no cryptographic-erasure claim.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, cast

from consultation_kb.lifecycle.cleanup_authority import (
    CleanupAuthorityResolver,
    CleanupIntentAuthority,
)
from consultation_kb.models.deletion import DeletionActionType
from consultation_kb.security.path_guard import PathGuard, ScopePathDenied
from consultation_kb.storage.catalog import (
    ClientCreationFailed,
    IdentityMapEraseResult,
)
from consultation_kb.storage.cleanup_inventory import SqlitePhysicalCleanupInventory
from consultation_kb.storage.connection import transaction
from consultation_kb.storage.deletion_inventory import client_authority_sha256
from consultation_kb.storage.tombstones import target_hash


_CLIENT_ID_RE = re.compile(r"client_[a-z0-9]{12}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_REPARSE_ATTRIBUTE = 0x400
_SCOPE_MARKER = ".scope-id"
_CLIENT_DATABASE = "client.sqlite3"
_MAX_TREE_ENTRIES = 100_000
_MAX_TREE_DEPTH = 64

WholeClientProcessState = Literal["succeeded", "retry_pending"]


class WholeClientCleanupError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ClientVaultScopeError(WholeClientCleanupError):
    pass


class _RetryableGate(WholeClientCleanupError):
    pass


class ClientContributorHasher(Protocol):
    def hash_client_id(self, client_id: str) -> str: ...


@dataclass(frozen=True, slots=True)
class ClientQuiescenceProof:
    client_id: str
    worker_handles_closed: bool
    sqlite_handles_closed: bool
    mmap_handles_closed: bool
    proof_sha256: str

    def __post_init__(self) -> None:
        if _CLIENT_ID_RE.fullmatch(self.client_id) is None:
            raise ValueError("CLIENT_QUIESCENCE_PROOF_INVALID")
        if any(
            type(value) is not bool
            for value in (
                self.worker_handles_closed,
                self.sqlite_handles_closed,
                self.mmap_handles_closed,
            )
        ):
            raise ValueError("CLIENT_QUIESCENCE_PROOF_INVALID")
        expected = client_quiescence_proof_sha256(
            client_id=self.client_id,
            worker_handles_closed=self.worker_handles_closed,
            sqlite_handles_closed=self.sqlite_handles_closed,
            mmap_handles_closed=self.mmap_handles_closed,
        )
        if not hmac.compare_digest(self.proof_sha256, expected):
            raise ValueError("CLIENT_QUIESCENCE_PROOF_INVALID")


def client_quiescence_proof_sha256(
    *,
    client_id: str,
    worker_handles_closed: bool,
    sqlite_handles_closed: bool,
    mmap_handles_closed: bool,
) -> str:
    if _CLIENT_ID_RE.fullmatch(client_id) is None or any(
        type(value) is not bool
        for value in (
            worker_handles_closed,
            sqlite_handles_closed,
            mmap_handles_closed,
        )
    ):
        raise ValueError("CLIENT_QUIESCENCE_PROOF_INVALID")
    material = "\x1f".join(
        (
            "consultation-kb-client-quiescence-v1",
            client_id,
            str(int(worker_handles_closed)),
            str(int(sqlite_handles_closed)),
            str(int(mmap_handles_closed)),
        )
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


class ClientScopeQuiescer(Protocol):
    def close_and_verify(self, client_id: str) -> ClientQuiescenceProof: ...

    def verify_closed(self, proof: ClientQuiescenceProof) -> bool: ...


class IdentityMapEntryRegistry(Protocol):
    def has_exact_identity_entry(
        self,
        *,
        client_id: str,
        alias_lookup_sha256: str,
        directory_object_id: str,
    ) -> bool: ...

    def erase_exact_identity_entry(
        self,
        *,
        client_id: str,
        alias_lookup_sha256: str,
        directory_object_id: str,
        allow_absent: bool = False,
    ) -> IdentityMapEraseResult: ...


@dataclass(frozen=True, slots=True)
class ClientVaultEraseResult:
    client_id: str
    removed_file_count: int
    removed_directory_count: int
    sanitized_database_count: int
    final_directory_absent: bool
    staging_directory_absent: bool


@dataclass(frozen=True, slots=True)
class WholeClientCleanupResult:
    intent_id: str
    request_id: str
    client_id: str
    state: WholeClientProcessState
    attempt_count: int
    removed_file_count: int
    removed_directory_count: int
    identity_entry_removed: bool
    evidence_sha256: str
    tombstone_active: Literal[True] = True
    cryptographic_erasure_claimed: Literal[False] = False


@dataclass(frozen=True, slots=True)
class _ClientCatalogProof:
    client_id: str
    directory_object_id: str
    alias_lookup_sha256: str
    created_at: str
    contributor_client_hash: str


class AnchoredClientVaultEraser:
    """Remove exact final/staging scopes without following filesystem links."""

    def __init__(
        self,
        clients_root: Path,
        *,
        file_unlink: Callable[[Path], None] | None = None,
        directory_rmdir: Callable[[Path], None] | None = None,
    ) -> None:
        candidate = Path(clients_root)
        try:
            if (
                not candidate.is_absolute()
                or ".." in candidate.parts
                or not _safe_directory(candidate)
                or (candidate / ".git").exists()
            ):
                raise ClientVaultScopeError("CLIENT_VAULT_SCOPE_INVALID")
            root = candidate.resolve(strict=True)
            if root != candidate:
                raise ClientVaultScopeError("CLIENT_VAULT_SCOPE_INVALID")
            with PathGuard(root).pin_root():
                pass
        except ClientVaultScopeError:
            raise
        except (OSError, RuntimeError, ScopePathDenied, ValueError):
            raise ClientVaultScopeError("CLIENT_VAULT_SCOPE_INVALID") from None
        self._root = root
        self._guard = PathGuard(root)
        self._file_unlink = file_unlink or (lambda path: path.unlink())
        self._directory_rmdir = directory_rmdir or (lambda path: path.rmdir())

    @property
    def clients_root(self) -> Path:
        return self._root

    def directories_absent(self, client_id: str) -> bool:
        final, staging = self._paths(client_id)
        return not _lexists(final) and not _lexists(staging)

    def erase(
        self,
        *,
        client_id: str,
        directory_object_id: str,
        allow_partial: bool,
    ) -> ClientVaultEraseResult:
        checked = _valid_client_id(client_id)
        if type(directory_object_id) is not str or not directory_object_id:
            raise ClientVaultScopeError("CLIENT_VAULT_DIRECTORY_ID_INVALID")
        if type(allow_partial) is not bool:
            raise ClientVaultScopeError("CLIENT_VAULT_PARTIAL_FLAG_INVALID")
        final, staging = self._paths(checked)
        files = directories = databases = 0
        for path, relative, require_database in (
            (staging, Path(".staging") / checked, False),
            (final, Path(checked), True),
        ):
            if not _lexists(path):
                continue
            result = self._erase_one(
                path,
                relative=relative,
                directory_object_id=directory_object_id,
                allow_partial=allow_partial,
                require_database=require_database,
            )
            files += result[0]
            directories += result[1]
            databases += result[2]
        return ClientVaultEraseResult(
            client_id=checked,
            removed_file_count=files,
            removed_directory_count=directories,
            sanitized_database_count=databases,
            final_directory_absent=not _lexists(final),
            staging_directory_absent=not _lexists(staging),
        )

    def _paths(self, client_id: str) -> tuple[Path, Path]:
        checked = _valid_client_id(client_id)
        return self._root / checked, self._root / ".staging" / checked

    def _erase_one(
        self,
        path: Path,
        *,
        relative: Path,
        directory_object_id: str,
        allow_partial: bool,
        require_database: bool,
    ) -> tuple[int, int, int]:
        context = (
            self._guard.pin_scoped_directory(Path(".staging"))
            if relative.parts[0] == ".staging"
            else self._guard.pin_root()
        )
        try:
            with context:
                self._validate_root_path(path, relative)
                entries = self._inspect_tree(path)
                marker = path / _SCOPE_MARKER
                if _lexists(marker):
                    if not _safe_regular_file(marker) or not hmac.compare_digest(
                        marker.read_bytes(),
                        f"{directory_object_id}\n".encode("ascii"),
                    ):
                        raise ClientVaultScopeError(
                            "CLIENT_VAULT_SCOPE_MARKER_INVALID"
                        )
                elif entries or (require_database and not allow_partial):
                    raise ClientVaultScopeError("CLIENT_VAULT_SCOPE_MARKER_REQUIRED")
                database = path / _CLIENT_DATABASE
                if require_database and not database.is_file() and not allow_partial:
                    raise ClientVaultScopeError("CLIENT_VAULT_DATABASE_REQUIRED")
                sanitized = int(database.is_file())
                if sanitized:
                    self._sanitize_database(database)
                self._validate_root_path(path, relative)
                self._inspect_tree(path)
                removed_files, removed_directories = self._remove_tree(path, depth=0)
                if _lexists(path):
                    raise ClientVaultScopeError("CLIENT_VAULT_DIRECTORY_STILL_PRESENT")
                return removed_files, removed_directories, sanitized
        except (ClientVaultScopeError, OSError, sqlite3.Error):
            raise
        except (RuntimeError, ScopePathDenied, UnicodeError, ValueError):
            raise ClientVaultScopeError("CLIENT_VAULT_SCOPE_INVALID") from None

    def _validate_root_path(self, path: Path, relative: Path) -> None:
        if not _safe_directory(path) or (path / ".git").exists():
            raise ClientVaultScopeError("CLIENT_VAULT_SCOPE_INVALID")
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise ClientVaultScopeError("CLIENT_VAULT_SCOPE_INVALID") from None
        if resolved != self._root / relative or not resolved.is_relative_to(self._root):
            raise ClientVaultScopeError("CLIENT_VAULT_SCOPE_INVALID")

    def _inspect_tree(self, root: Path) -> tuple[Path, ...]:
        found: list[Path] = []

        def visit(directory: Path, depth: int) -> None:
            if depth > _MAX_TREE_DEPTH or not _safe_directory(directory):
                raise ClientVaultScopeError("CLIENT_VAULT_TREE_INVALID")
            for entry in os.scandir(directory):
                candidate = Path(entry.path)
                if entry.name == ".git":
                    raise ClientVaultScopeError("CLIENT_VAULT_REPOSITORY_REFUSED")
                try:
                    status = os.lstat(candidate)
                except OSError:
                    raise ClientVaultScopeError("CLIENT_VAULT_TREE_INVALID") from None
                attributes = int(getattr(status, "st_file_attributes", 0))
                if stat.S_ISLNK(status.st_mode) or attributes & _REPARSE_ATTRIBUTE:
                    raise ClientVaultScopeError("CLIENT_VAULT_LINK_REFUSED")
                if stat.S_ISDIR(status.st_mode):
                    visit(candidate, depth + 1)
                elif not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    raise ClientVaultScopeError("CLIENT_VAULT_LINK_REFUSED")
                found.append(candidate)
                if len(found) > _MAX_TREE_ENTRIES:
                    raise ClientVaultScopeError("CLIENT_VAULT_TREE_TOO_LARGE")

        visit(root, 0)
        return tuple(found)

    @staticmethod
    def _sanitize_database(database: Path) -> None:
        connection = sqlite3.connect(database, isolation_level=None, timeout=5.0)
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            journal = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if journal is None or str(journal[0]).lower() != "wal":
                raise WholeClientCleanupError("CLIENT_SQLITE_WAL_REQUIRED")
            connection.execute("PRAGMA secure_delete = ON")
            if connection.execute("PRAGMA secure_delete").fetchone() != (1,):
                raise WholeClientCleanupError("CLIENT_SQLITE_SECURE_DELETE_REQUIRED")
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or int(checkpoint[0]) != 0:
                raise WholeClientCleanupError("CLIENT_SQLITE_CHECKPOINT_FAILED")
            connection.execute("VACUUM")
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or int(checkpoint[0]) != 0:
                raise WholeClientCleanupError("CLIENT_SQLITE_CHECKPOINT_FAILED")
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise WholeClientCleanupError("CLIENT_SQLITE_INTEGRITY_FAILED")
        finally:
            connection.close()

    def _remove_tree(self, directory: Path, *, depth: int) -> tuple[int, int]:
        if depth > _MAX_TREE_DEPTH or not _safe_directory(directory):
            raise ClientVaultScopeError("CLIENT_VAULT_TREE_INVALID")
        files = directories = 0
        children = sorted(
            (Path(entry.path) for entry in os.scandir(directory)),
            key=lambda value: (value.name == _SCOPE_MARKER, value.name),
        )
        for child in children:
            if child.name == ".git":
                raise ClientVaultScopeError("CLIENT_VAULT_REPOSITORY_REFUSED")
            try:
                status = os.lstat(child)
            except OSError:
                raise
            attributes = int(getattr(status, "st_file_attributes", 0))
            if stat.S_ISLNK(status.st_mode) or attributes & _REPARSE_ATTRIBUTE:
                raise ClientVaultScopeError("CLIENT_VAULT_LINK_REFUSED")
            if stat.S_ISDIR(status.st_mode):
                child_files, child_directories = self._remove_tree(
                    child,
                    depth=depth + 1,
                )
                files += child_files
                directories += child_directories
            elif stat.S_ISREG(status.st_mode) and status.st_nlink == 1:
                self._file_unlink(child)
                if _lexists(child):
                    raise ClientVaultScopeError("CLIENT_VAULT_FILE_STILL_PRESENT")
                files += 1
            else:
                raise ClientVaultScopeError("CLIENT_VAULT_LINK_REFUSED")
        self._directory_rmdir(directory)
        if _lexists(directory):
            raise ClientVaultScopeError("CLIENT_VAULT_DIRECTORY_STILL_PRESENT")
        return files, directories + 1


class WholeClientCleanupCoordinator:
    """Finalize one client deletion only after all global dependents are closed."""

    def __init__(
        self,
        connection_factory: Callable[[], sqlite3.Connection],
        *,
        global_database_path: Path,
        clients_root: Path,
        contributor_hasher: ClientContributorHasher,
        quiescer: ClientScopeQuiescer,
        identity_registry: IdentityMapEntryRegistry,
        vault_eraser: AnchoredClientVaultEraser | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("WHOLE_CLIENT_CONNECTION_FACTORY_REQUIRED")
        if not callable(getattr(contributor_hasher, "hash_client_id", None)):
            raise TypeError("WHOLE_CLIENT_HASHER_REQUIRED")
        if not callable(getattr(quiescer, "close_and_verify", None)) or not callable(
            getattr(quiescer, "verify_closed", None)
        ):
            raise TypeError("WHOLE_CLIENT_QUIESCER_REQUIRED")
        if not callable(
            getattr(identity_registry, "has_exact_identity_entry", None)
        ) or not callable(
            getattr(identity_registry, "erase_exact_identity_entry", None)
        ):
            raise TypeError("WHOLE_CLIENT_IDENTITY_REGISTRY_REQUIRED")
        self._connection_factory = connection_factory
        self._database_path = Path(global_database_path).resolve(strict=True)
        self._hasher = contributor_hasher
        self._quiescer = quiescer
        self._identity = identity_registry
        self._eraser = vault_eraser or AnchoredClientVaultEraser(clients_root)
        if self._eraser.clients_root != Path(clients_root).resolve(strict=True):
            raise ValueError("WHOLE_CLIENT_ERASER_SCOPE_MISMATCH")
        self._clock = clock or (lambda: datetime.now(UTC))

    def process(self, intent_id: str) -> WholeClientCleanupResult:
        authority, proof = self._resolve(intent_id)
        if authority.state == "SUCCEEDED":
            self._verify_global_closure(authority, proof)
            if not self._eraser.directories_absent(proof.client_id) or (
                self._identity.has_exact_identity_entry(
                    client_id=proof.client_id,
                    alias_lookup_sha256=proof.alias_lookup_sha256,
                    directory_object_id=proof.directory_object_id,
                )
            ):
                raise WholeClientCleanupError("WHOLE_CLIENT_RESIDUE_REAPPEARED")
            return self._result(
                authority,
                proof,
                state="succeeded",
                removed_files=0,
                removed_directories=0,
                identity_removed=False,
            )
        if authority.state not in {"PENDING", "FAILED", "CLAIMED"}:
            raise WholeClientCleanupError(
                f"WHOLE_CLIENT_BAD_INTENT_STATE:{authority.state}"
            )
        authority = self._claim(authority)
        try:
            self._verify_global_closure(authority, proof)
            directories_absent_before = self._eraser.directories_absent(proof.client_id)
            identity_present = self._identity.has_exact_identity_entry(
                client_id=proof.client_id,
                alias_lookup_sha256=proof.alias_lookup_sha256,
                directory_object_id=proof.directory_object_id,
            )
            if authority.attempt_count == 1 and (
                directories_absent_before or not identity_present
            ):
                raise WholeClientCleanupError("WHOLE_CLIENT_INITIAL_SCOPE_INCOMPLETE")
            if not identity_present and not directories_absent_before:
                raise WholeClientCleanupError("WHOLE_CLIENT_IDENTITY_SCOPE_MISMATCH")
            quiescence = self._quiescer.close_and_verify(proof.client_id)
            if (
                not isinstance(quiescence, ClientQuiescenceProof)
                or quiescence.client_id != proof.client_id
                or not quiescence.worker_handles_closed
                or not quiescence.sqlite_handles_closed
                or not quiescence.mmap_handles_closed
                or not self._quiescer.verify_closed(quiescence)
            ):
                raise _RetryableGate("CLIENT_HANDLES_OPEN")
            erased = self._eraser.erase(
                client_id=proof.client_id,
                directory_object_id=proof.directory_object_id,
                allow_partial=authority.attempt_count > 1,
            )
            identity = self._identity.erase_exact_identity_entry(
                client_id=proof.client_id,
                alias_lookup_sha256=proof.alias_lookup_sha256,
                directory_object_id=proof.directory_object_id,
                allow_absent=authority.attempt_count > 1,
            )
            if (
                not erased.final_directory_absent
                or not erased.staging_directory_absent
                or not self._eraser.directories_absent(proof.client_id)
                or self._identity.has_exact_identity_entry(
                    client_id=proof.client_id,
                    alias_lookup_sha256=proof.alias_lookup_sha256,
                    directory_object_id=proof.directory_object_id,
                )
                or not self._quiescer.verify_closed(quiescence)
            ):
                raise WholeClientCleanupError("WHOLE_CLIENT_POSTCHECK_FAILED")
            current, current_proof = self._resolve(intent_id)
            if current.state != "CLAIMED" or current_proof != proof:
                raise WholeClientCleanupError("WHOLE_CLIENT_CLAIM_LOST")
            self._verify_global_closure(current, current_proof)
            self._mark_succeeded(current.intent_id)
            completed, completed_proof = self._resolve(intent_id)
            return self._result(
                completed,
                completed_proof,
                state="succeeded",
                removed_files=erased.removed_file_count,
                removed_directories=erased.removed_directory_count,
                identity_removed=identity.entry_removed,
            )
        except _RetryableGate as error:
            self._mark_failed(intent_id, error.code)
            failed, failed_proof = self._resolve(intent_id)
            return self._result(
                failed,
                failed_proof,
                state="retry_pending",
                removed_files=0,
                removed_directories=0,
                identity_removed=False,
            )
        except sqlite3.OperationalError as error:
            if not _is_sqlite_lock_or_busy(error):
                self._mark_failed_if_claimed(intent_id)
                raise
            self._mark_failed(intent_id, "SQLITE_LOCK_RETRY")
            failed, failed_proof = self._resolve(intent_id)
            return self._result(
                failed,
                failed_proof,
                state="retry_pending",
                removed_files=0,
                removed_directories=0,
                identity_removed=False,
            )
        except OSError as error:
            code = (
                "FILE_LOCK_RETRY"
                if _is_windows_lock_or_busy(error)
                else "WHOLE_CLIENT_IO_RETRY"
            )
            self._mark_failed(intent_id, code)
            failed, failed_proof = self._resolve(intent_id)
            return self._result(
                failed,
                failed_proof,
                state="retry_pending",
                removed_files=0,
                removed_directories=0,
                identity_removed=False,
            )
        except (
            ClientCreationFailed,
            WholeClientCleanupError,
            sqlite3.Error,
            ScopePathDenied,
        ):
            self._mark_failed_if_claimed(intent_id)
            raise

    def _resolve(
        self,
        intent_id: str,
    ) -> tuple[CleanupIntentAuthority, _ClientCatalogProof]:
        connection = self._open_connection()
        try:
            authority = CleanupAuthorityResolver(
                connection,
                authority_scope="global",
            ).resolve(intent_id, expected_action_type="physical_delete")
            if (
                authority.object_type != "client"
                or authority.root_object_type != "client"
                or authority.target_id_hash != authority.root_target_id_hash
                or authority.target_version != 1
            ):
                raise WholeClientCleanupError("WHOLE_CLIENT_AUTHORITY_INVALID")
            matches: list[tuple[object, ...]] = []
            for row in connection.execute(
                "SELECT client_id, directory_object_id, alias_lookup_sha256, "
                "state, created_at FROM clients"
            ).fetchall():
                if target_hash("client", str(row[0])) == authority.target_id_hash:
                    matches.append(tuple(row))
            if len(matches) != 1:
                raise WholeClientCleanupError("WHOLE_CLIENT_CATALOG_CARDINALITY")
            row = matches[0]
            client_id = _valid_client_id(str(row[0]))
            directory_object_id = str(row[1])
            alias_lookup_sha256 = _valid_sha256(str(row[2]))
            created_at = str(row[4])
            if row[3] != "RETIRED" or not directory_object_id:
                raise WholeClientCleanupError("WHOLE_CLIENT_NOT_RETIRED")
            expected = client_authority_sha256(
                client_id=client_id,
                directory_object_id=directory_object_id,
                alias_lookup_sha256=alias_lookup_sha256,
                created_at=created_at,
            )
            if not hmac.compare_digest(expected, authority.target_content_sha256):
                raise WholeClientCleanupError("WHOLE_CLIENT_CATALOG_AUTHORITY_MISMATCH")
            contributor_hash = _valid_sha256(
                self._hasher.hash_client_id(client_id)
            )
            return authority, _ClientCatalogProof(
                client_id=client_id,
                directory_object_id=directory_object_id,
                alias_lookup_sha256=alias_lookup_sha256,
                created_at=created_at,
                contributor_client_hash=contributor_hash,
            )
        finally:
            connection.close()

    def _verify_global_closure(
        self,
        authority: CleanupIntentAuthority,
        proof: _ClientCatalogProof,
    ) -> None:
        connection = self._open_connection()
        try:
            current = CleanupAuthorityResolver(
                connection,
                authority_scope="global",
            ).resolve(authority.intent_id, expected_action_type="physical_delete")
            if current != authority:
                raise WholeClientCleanupError("WHOLE_CLIENT_AUTHORITY_CHANGED")
            catalog = connection.execute(
                "SELECT directory_object_id, alias_lookup_sha256, state, created_at "
                "FROM clients WHERE client_id = ?",
                (proof.client_id,),
            ).fetchone()
            if catalog != (
                proof.directory_object_id,
                proof.alias_lookup_sha256,
                "RETIRED",
                proof.created_at,
            ):
                raise WholeClientCleanupError("WHOLE_CLIENT_CATALOG_PROOF_INVALID")
            self._verify_capabilities(connection, current, proof)
            self._verify_case_contributions(connection, current, proof)
            sibling_rows = connection.execute(
                "SELECT intent_id, action_type, state FROM deletion_queue_intents "
                "WHERE request_id = ? AND intent_id != ? ORDER BY intent_id",
                (current.request_id, current.intent_id),
            ).fetchall()
            if not sibling_rows:
                raise WholeClientCleanupError("WHOLE_CLIENT_SIBLING_CLOSURE_MISSING")
            for sibling_id, action_type, state in sibling_rows:
                if action_type not in {"physical_delete", "rebuild", "backup_expiry"}:
                    raise WholeClientCleanupError("WHOLE_CLIENT_SIBLING_INVALID")
                sibling = CleanupAuthorityResolver(
                    connection,
                    authority_scope="global",
                ).resolve(
                    str(sibling_id),
                    expected_action_type=cast(DeletionActionType, action_type),
                )
                if sibling.request_id != current.request_id:
                    raise WholeClientCleanupError("WHOLE_CLIENT_SIBLING_INVALID")
                if state != "SUCCEEDED":
                    raise _RetryableGate("CLIENT_GLOBAL_CLOSURE_PENDING")
            self._verify_backup_closure(connection, current.request_id)
        finally:
            connection.close()

    @staticmethod
    def _verify_capabilities(
        connection: sqlite3.Connection,
        authority: CleanupIntentAuthority,
        proof: _ClientCatalogProof,
    ) -> None:
        for capability_id, state in connection.execute(
            "SELECT capability_id, state FROM capabilities WHERE client_id = ?",
            (proof.client_id,),
        ).fetchall():
            if state != "REVOKED" or not _exact_tombstone(
                connection,
                object_type="client_capability",
                object_id=str(capability_id),
                root_lineage_hash=authority.root_lineage_hash,
            ):
                raise _RetryableGate("CLIENT_CAPABILITY_CLOSURE_PENDING")

    @staticmethod
    def _verify_case_contributions(
        connection: sqlite3.Connection,
        authority: CleanupIntentAuthority,
        proof: _ClientCatalogProof,
    ) -> None:
        rows = connection.execute(
            """
            SELECT ca.case_id, ca.case_version, c.state, cv.state
              FROM case_authorizations AS ca
              JOIN cases AS c ON c.case_id = ca.case_id
              JOIN case_versions AS cv
                ON cv.case_id = ca.case_id AND cv.version = ca.case_version
             WHERE ca.contributor_client_hash = ?
            """,
            (proof.contributor_client_hash,),
        ).fetchall()
        for case_id, _version, case_state, version_state in rows:
            if (
                case_state != "REVOKED"
                or version_state != "REVOKED"
                or not _exact_tombstone(
                    connection,
                    object_type="case",
                    object_id=str(case_id),
                    root_lineage_hash=authority.root_lineage_hash,
                )
            ):
                raise _RetryableGate("CLIENT_CASE_CLOSURE_PENDING")
        for kind, object_id, raw_contributors in connection.execute(
            "SELECT artifact_kind, artifact_object_id, "
            "contributor_client_hashes_json FROM case_provenance"
        ).fetchall():
            try:
                contributors = json.loads(str(raw_contributors))
            except (TypeError, ValueError, json.JSONDecodeError):
                raise WholeClientCleanupError("WHOLE_CLIENT_PROVENANCE_INVALID") from None
            if (
                type(contributors) is not list
                or any(_SHA256_RE.fullmatch(str(value)) is None for value in contributors)
                or len(contributors) != len(set(contributors))
            ):
                raise WholeClientCleanupError("WHOLE_CLIENT_PROVENANCE_INVALID")
            if proof.contributor_client_hash not in contributors:
                continue
            if not _exact_tombstone(
                connection,
                object_type=str(kind),
                object_id=str(object_id),
                root_lineage_hash=authority.root_lineage_hash,
            ):
                raise _RetryableGate("CLIENT_CASE_CLOSURE_PENDING")

    @staticmethod
    def _verify_backup_closure(
        connection: sqlite3.Connection,
        request_id: str,
    ) -> None:
        backup_intents = connection.execute(
            "SELECT count(*) FROM deletion_queue_intents "
            "WHERE request_id = ? AND action_type = 'backup_expiry'",
            (request_id,),
        ).fetchone()
        if backup_intents is None or int(backup_intents[0]) < 1:
            raise WholeClientCleanupError("WHOLE_CLIENT_BACKUP_INTENT_MISSING")
        backup_rows = connection.execute(
            "SELECT backup_id, state, operator_proof_sha256, finished_at "
            "FROM backup_destruction_queue WHERE request_id = ?",
            (request_id,),
        ).fetchall()
        if not backup_rows:
            raise _RetryableGate("CLIENT_BACKUP_CLOSURE_PENDING")
        if any(
            state != "succeeded" or proof is None or finished is None
            for _backup_id, state, proof, finished in backup_rows
        ):
            raise _RetryableGate("CLIENT_BACKUP_CLOSURE_PENDING")
        actual = {
            str(row[0])
            for row in connection.execute(
                "SELECT o.object_sha256 FROM backup_destruction_objects AS o "
                "JOIN backup_destruction_queue AS q ON q.backup_id = o.backup_id "
                "WHERE q.request_id = ?",
                (request_id,),
            ).fetchall()
        }
        expected: set[str] = set()
        inventory = SqlitePhysicalCleanupInventory(
            connection,
            authority_scope="global",
        )
        for (physical_intent_id,) in connection.execute(
            "SELECT intent_id FROM deletion_queue_intents "
            "WHERE request_id = ? AND action_type = 'physical_delete'",
            (request_id,),
        ).fetchall():
            physical = CleanupAuthorityResolver(
                connection,
                authority_scope="global",
            ).resolve(str(physical_intent_id), expected_action_type="physical_delete")
            expected.update(inventory.resolve(physical).content_sha256s)
        if not expected or actual != expected:
            raise WholeClientCleanupError("WHOLE_CLIENT_BACKUP_CLOSURE_INVALID")

    def _open_connection(self) -> sqlite3.Connection:
        connection = self._connection_factory()
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("WHOLE_CLIENT_CONNECTION_FACTORY_INVALID")
        main = tuple(
            row
            for row in connection.execute("PRAGMA database_list").fetchall()
            if str(row[1]) == "main"
        )
        try:
            actual = Path(str(main[0][2])).resolve(strict=True)
        except (IndexError, OSError, RuntimeError, ValueError):
            connection.close()
            raise WholeClientCleanupError("WHOLE_CLIENT_DATABASE_SCOPE_MISMATCH") from None
        if len(main) != 1 or actual != self._database_path:
            connection.close()
            raise WholeClientCleanupError("WHOLE_CLIENT_DATABASE_SCOPE_MISMATCH")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _claim(self, authority: CleanupIntentAuthority) -> CleanupIntentAuthority:
        connection = self._open_connection()
        try:
            now = _utc_text(self._clock())
            with transaction(connection):
                changed = connection.execute(
                    "UPDATE deletion_queue_intents SET state = 'CLAIMED', "
                    "attempt_count = attempt_count + 1, claimed_at = ?, "
                    "finished_at = NULL, last_error_code = NULL "
                    "WHERE intent_id = ? AND state IN ('PENDING','FAILED','CLAIMED')",
                    (now, authority.intent_id),
                ).rowcount
                if changed != 1:
                    raise WholeClientCleanupError("WHOLE_CLIENT_CLAIM_FAILED")
                connection.execute(
                    "UPDATE deletion_requests SET queue_state = 'RUNNING' "
                    "WHERE request_id = ? AND queue_state != 'RUNNING'",
                    (authority.request_id,),
                )
            claimed = CleanupAuthorityResolver(
                connection,
                authority_scope="global",
            ).resolve(authority.intent_id, expected_action_type="physical_delete")
            if claimed.state != "CLAIMED":
                raise WholeClientCleanupError("WHOLE_CLIENT_CLAIM_FAILED")
            return claimed
        finally:
            connection.close()

    def _mark_failed(self, intent_id: str, code: str) -> None:
        connection = self._open_connection()
        try:
            with transaction(connection):
                row = connection.execute(
                    "SELECT request_id, state FROM deletion_queue_intents "
                    "WHERE intent_id = ?",
                    (intent_id,),
                ).fetchone()
                if row is None:
                    raise WholeClientCleanupError("WHOLE_CLIENT_INTENT_NOT_FOUND")
                if row[1] == "FAILED":
                    return
                if row[1] != "CLAIMED":
                    raise WholeClientCleanupError("WHOLE_CLIENT_CLAIM_LOST")
                connection.execute(
                    "UPDATE deletion_queue_intents SET state = 'FAILED', "
                    "last_error_code = ?, finished_at = NULL WHERE intent_id = ?",
                    (code, intent_id),
                )
                connection.execute(
                    "UPDATE deletion_requests SET queue_state = 'FAILED' "
                    "WHERE request_id = ? AND queue_state IN ('RUNNING','PARTIAL')",
                    (str(row[0]),),
                )
        finally:
            connection.close()

    def _mark_failed_if_claimed(self, intent_id: str) -> None:
        try:
            self._mark_failed(intent_id, "WHOLE_SCOPE_VERIFICATION_FAILED")
        except (WholeClientCleanupError, sqlite3.Error):
            pass

    def _mark_succeeded(self, intent_id: str) -> None:
        connection = self._open_connection()
        try:
            with transaction(connection):
                row = connection.execute(
                    "SELECT request_id FROM deletion_queue_intents "
                    "WHERE intent_id = ? AND state = 'CLAIMED'",
                    (intent_id,),
                ).fetchone()
                if row is None:
                    raise WholeClientCleanupError("WHOLE_CLIENT_CLAIM_LOST")
                request_id = str(row[0])
                changed = connection.execute(
                    "UPDATE deletion_queue_intents SET state = 'SUCCEEDED', "
                    "finished_at = ?, last_error_code = NULL "
                    "WHERE intent_id = ? AND state = 'CLAIMED'",
                    (_utc_text(self._clock()), intent_id),
                ).rowcount
                if changed != 1:
                    raise WholeClientCleanupError("WHOLE_CLIENT_ACK_FAILED")
                remaining = int(
                    connection.execute(
                        "SELECT count(*) FROM deletion_queue_intents "
                        "WHERE request_id = ? "
                        "AND state != 'SUCCEEDED'",
                        (request_id,),
                    ).fetchone()[0]
                )
                backup_pending = int(
                    connection.execute(
                        "SELECT count(*) FROM backup_destruction_queue "
                        "WHERE request_id = ? AND state != 'succeeded'",
                        (request_id,),
                    ).fetchone()[0]
                )
                if remaining != 0 or backup_pending != 0:
                    raise WholeClientCleanupError("WHOLE_CLIENT_ACK_CLOSURE_INVALID")
                connection.execute(
                    "UPDATE deletion_requests SET queue_state = 'SUCCEEDED', "
                    "state = 'PHYSICAL_CLEANUP_COMPLETE' WHERE request_id = ?",
                    (request_id,),
                )
        finally:
            connection.close()

    @staticmethod
    def _result(
        authority: CleanupIntentAuthority,
        proof: _ClientCatalogProof,
        *,
        state: WholeClientProcessState,
        removed_files: int,
        removed_directories: int,
        identity_removed: bool,
    ) -> WholeClientCleanupResult:
        evidence = "\x1f".join(
            (
                authority.intent_id,
                authority.request_id,
                proof.client_id,
                authority.action_descriptor_sha256,
                state,
                str(authority.attempt_count),
                str(removed_files),
                str(removed_directories),
                str(int(identity_removed)),
            )
        ).encode("ascii")
        return WholeClientCleanupResult(
            intent_id=authority.intent_id,
            request_id=authority.request_id,
            client_id=proof.client_id,
            state=state,
            attempt_count=authority.attempt_count,
            removed_file_count=removed_files,
            removed_directory_count=removed_directories,
            identity_entry_removed=identity_removed,
            evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )


def _valid_client_id(value: str) -> str:
    if type(value) is not str or _CLIENT_ID_RE.fullmatch(value) is None:
        raise WholeClientCleanupError("WHOLE_CLIENT_ID_INVALID")
    return value


def _valid_sha256(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise WholeClientCleanupError("WHOLE_CLIENT_HASH_INVALID")
    return value


def _safe_directory(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    attributes = int(getattr(status, "st_file_attributes", 0))
    return (
        stat.S_ISDIR(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not attributes & _REPARSE_ATTRIBUTE
    )


def _safe_regular_file(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    attributes = int(getattr(status, "st_file_attributes", 0))
    return (
        stat.S_ISREG(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not attributes & _REPARSE_ATTRIBUTE
        and status.st_nlink == 1
    )


def _lexists(path: Path) -> bool:
    return bool(os.path.lexists(path))


def _exact_tombstone(
    connection: sqlite3.Connection,
    *,
    object_type: str,
    object_id: str,
    root_lineage_hash: str,
) -> bool:
    return bool(
        connection.execute(
            "SELECT count(*) FROM tombstones WHERE target_type = ? "
            "AND target_id_hash = ? AND source_lineage_hash = ?",
            (object_type, target_hash(object_type, object_id), root_lineage_hash),
        ).fetchone()
        == (1,)
    )


def _is_windows_lock_or_busy(error: OSError) -> bool:
    winerror = getattr(error, "winerror", None)
    return bool(
        isinstance(error, PermissionError)
        or winerror in {32, 33}
        or error.errno in {errno.EACCES, errno.EBUSY}
    )


def _is_sqlite_lock_or_busy(error: sqlite3.OperationalError) -> bool:
    code = getattr(error, "sqlite_errorcode", None)
    if type(code) is int and code & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }:
        return True
    message = str(error).casefold()
    return "database is locked" in message or "database table is locked" in message


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("WHOLE_CLIENT_CLOCK_NOT_UTC")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


__all__ = [
    "AnchoredClientVaultEraser",
    "ClientContributorHasher",
    "ClientQuiescenceProof",
    "ClientScopeQuiescer",
    "ClientVaultEraseResult",
    "ClientVaultScopeError",
    "IdentityMapEntryRegistry",
    "WholeClientCleanupCoordinator",
    "WholeClientCleanupError",
    "WholeClientCleanupResult",
    "WholeClientProcessState",
    "client_quiescence_proof_sha256",
]
