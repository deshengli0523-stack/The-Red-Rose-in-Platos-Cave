"""Out-of-band approval providers and signature verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, runtime_checkable

from consultation_kb.core.clock import Clock
from consultation_kb.models.manifests import ApprovalReceipt
from consultation_kb.security.dpapi import SecretProtector
from consultation_kb.security.path_guard import PathGuard

from .attestation import (
    LocalHmacTargetExecutionAttestor,
    LocalHmacTargetExecutionProofVerifier,
)
from .models import ApprovalChallenge


class ApprovalProviderError(RuntimeError):
    """A provider could not issue or verify a controlled confirmation."""


class ProviderSecretUnavailable(ApprovalProviderError):
    pass


@runtime_checkable
class ApprovalProvider(Protocol):
    """Verifier-only boundary available to the model-facing control plane."""

    @property
    def provider_id(self) -> str: ...

    def verify(
        self,
        receipt: ApprovalReceipt,
        challenge: ApprovalChallenge,
    ) -> bool: ...


@runtime_checkable
class ApprovalSigner(Protocol):
    """Signer capability confined to the interactive local review process."""

    @property
    def provider_id(self) -> str: ...

    def confirm(self, challenge: ApprovalChallenge) -> ApprovalReceipt: ...


def _signature_payload(
    receipt: ApprovalReceipt,
    challenge: ApprovalChallenge,
) -> bytes:
    payload = {
        "receipt": receipt.model_dump(mode="json", exclude={"signature"}),
        "request": challenge.request.model_dump(mode="json"),
    }
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


class _LocalHmacKey:
    __slots__ = ("_provider_id", "_secret")

    def __init__(self, *, secret: bytes, provider_id: str) -> None:
        if type(secret) is not bytes or len(secret) < 32:
            raise ValueError("approval provider secret must contain at least 256 bits")
        if type(provider_id) is not str or not provider_id.strip():
            raise ValueError("approval provider ID must be a nonblank string")
        self._secret = bytes(secret)
        self._provider_id = provider_id

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def _signature(
        self,
        receipt: ApprovalReceipt,
        challenge: ApprovalChallenge,
    ) -> str:
        return hmac.new(
            self._secret,
            _signature_payload(receipt, challenge),
            hashlib.sha256,
        ).hexdigest()


class LocalHmacApprovalSigner(_LocalHmacKey):
    """Signer instantiated only by the independent interactive review process."""

    __slots__ = ("_clock",)

    def __init__(self, *, secret: bytes, provider_id: str, clock: Clock) -> None:
        super().__init__(secret=secret, provider_id=provider_id)
        self._clock = clock

    def confirm(self, challenge: ApprovalChallenge) -> ApprovalReceipt:
        validated = ApprovalChallenge.model_validate(challenge)
        now = self._clock.now()
        if now < validated.request.created_at or now >= validated.request.expires_at:
            raise ApprovalProviderError("approval request is outside its review window")
        unsigned = ApprovalReceipt(
            request_id=validated.request.request_id,
            descriptor_sha256=validated.request.descriptor_sha256,
            approver_role="primary_counselor",
            approved_at=now,
            expires_at=validated.request.expires_at,
            nonce=validated.nonce,
            provider_id=self._provider_id,
            signature="pending",
        )
        return unsigned.model_copy(
            update={"signature": self._signature(unsigned, validated)}
        )


class LocalHmacApprovalVerifier(_LocalHmacKey):
    """Verify signed events without exposing a confirmation method."""

    __slots__ = ()

    def verify(
        self,
        receipt: ApprovalReceipt,
        challenge: ApprovalChallenge,
    ) -> bool:
        try:
            validated_receipt = ApprovalReceipt.model_validate(receipt)
            validated_challenge = ApprovalChallenge.model_validate(challenge)
        except (TypeError, ValueError):
            return False
        request = validated_challenge.request
        fixed_fields_match = (
            validated_receipt.request_id == request.request_id
            and validated_receipt.descriptor_sha256 == request.descriptor_sha256
            and validated_receipt.approver_role == "primary_counselor"
            and validated_receipt.approved_at >= request.created_at
            and validated_receipt.approved_at < request.expires_at
            and validated_receipt.expires_at == request.expires_at
            and validated_receipt.nonce == validated_challenge.nonce
            and validated_receipt.provider_id == self._provider_id
        )
        if not fixed_fields_match:
            return False
        expected = self._signature(
            validated_receipt.model_copy(update={"signature": "pending"}),
            validated_challenge,
        )
        return hmac.compare_digest(expected, validated_receipt.signature)


class ProtectedProviderSecretStore:
    """Explicitly initialize and load one DPAPI-protected review-agent key."""

    __slots__ = ("_path", "_protector", "_vault_id")

    def __init__(
        self,
        path: Path,
        *,
        protector: SecretProtector,
        vault_id: str,
    ) -> None:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("provider secret path must be an absolute pathlib.Path")
        if type(vault_id) is not str or not vault_id.strip():
            raise ValueError("provider secret store requires a vault ID")
        self._path = path
        self._protector = protector
        self._vault_id = vault_id

    def initialize(
        self,
        *,
        random_source: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        secret = random_source(32)
        if type(secret) is not bytes or len(secret) != 32:
            raise ApprovalProviderError("provider secret generation failed")
        protected = self._protector.protect(
            secret,
            purpose="review_agent_hmac",
            vault_id=self._vault_id,
        )
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                self._path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                if os.write(descriptor, protected) != len(protected):
                    raise OSError("short provider secret write")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            raise ProviderSecretUnavailable(
                "provider secret initialization failed"
            ) from None

    def load(self) -> bytes:
        try:
            with PathGuard(self._path.parent).open_scoped(
                self._path.name,
                mode="rb",
            ) as stream:
                protected = stream.read()
            secret = self._protector.unprotect(
                protected,
                purpose="review_agent_hmac",
                vault_id=self._vault_id,
            )
        except Exception:
            raise ProviderSecretUnavailable("provider secret is unavailable") from None
        if type(secret) is not bytes or len(secret) != 32:
            raise ProviderSecretUnavailable("provider secret is unavailable")
        return secret

    def load_signer(self, *, clock: Clock) -> LocalHmacApprovalSigner:
        return LocalHmacApprovalSigner(
            secret=self.load(),
            provider_id="local-review-agent",
            clock=clock,
        )

    def load_verifier(self) -> LocalHmacApprovalVerifier:
        return LocalHmacApprovalVerifier(
            secret=self.load(),
            provider_id="local-review-agent",
        )

    def load_execution_secret(self) -> bytes:
        return hmac.new(
            self.load(),
            b"consultation-kb/approval-execution/v1",
            hashlib.sha256,
        ).digest()

    def load_target_execution_attestation_secret(self) -> bytes:
        """Derive a role-separated key distinct from ticket issuance."""

        return hmac.new(
            self.load(),
            b"consultation-kb/target-execution-attestation/v1",
            hashlib.sha256,
        ).digest()

    def load_target_execution_attestor(self) -> LocalHmacTargetExecutionAttestor:
        return LocalHmacTargetExecutionAttestor(
            secret=self.load_target_execution_attestation_secret(),
            attestor_id="target-approval-execution",
        )

    def load_target_execution_proof_verifier(
        self,
    ) -> LocalHmacTargetExecutionProofVerifier:
        return LocalHmacTargetExecutionProofVerifier(
            secret=self.load_target_execution_attestation_secret(),
            attestor_id="target-approval-execution",
        )


__all__ = [
    "ApprovalProvider",
    "ApprovalProviderError",
    "ApprovalSigner",
    "LocalHmacApprovalSigner",
    "LocalHmacApprovalVerifier",
    "ProtectedProviderSecretStore",
    "ProviderSecretUnavailable",
]
