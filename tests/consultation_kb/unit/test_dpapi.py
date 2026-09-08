from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from consultation_kb.security import dpapi as dpapi_module
from consultation_kb.security.dpapi import (
    InvalidSecretContext,
    SecretDecryptionFailed,
    UnsupportedSecurityPlatform,
    WindowsDpapiProtector,
    create_secret_protector,
)


@dataclass
class _RecordingDpapiBackend:
    calls: list[tuple[str, bytes, str, bytes, int]] = field(default_factory=list)
    protected: dict[bytes, tuple[bytes, bytes, str]] = field(default_factory=dict)

    def protect(
        self,
        data: bytes,
        *,
        description: str,
        entropy: bytes,
        flags: int,
    ) -> bytes:
        blob = b"ciphertext:" + bytes([len(self.protected)])
        self.calls.append(("protect", data, description, entropy, flags))
        self.protected[blob] = (data, entropy, description)
        return blob

    def unprotect(
        self,
        blob: bytes,
        *,
        entropy: bytes,
        flags: int,
    ) -> tuple[str, bytes]:
        self.calls.append(("unprotect", blob, "", entropy, flags))
        data, expected_entropy, description = self.protected[blob]
        if entropy != expected_entropy:
            raise OSError("wrong entropy")
        return description, data


def test_dpapi_round_trip_binds_vault_and_purpose_without_machine_scope() -> None:
    backend = _RecordingDpapiBackend()
    protector = WindowsDpapiProtector(backend=backend)

    blob = protector.protect(
        b"review-secret",
        purpose="review-agent-secret",
        vault_id="vault_01",
    )

    assert blob != b"review-secret"
    assert protector.unprotect(
        blob,
        purpose="review-agent-secret",
        vault_id="vault_01",
    ) == b"review-secret"
    protect_call = backend.calls[0]
    assert protect_call[2] == "consultation-kb:review-agent-secret"
    assert protect_call[4] & 0x1
    assert protect_call[4] & 0x4 == 0


def test_dpapi_entropy_changes_for_vault_and_purpose() -> None:
    backend = _RecordingDpapiBackend()
    protector = WindowsDpapiProtector(backend=backend)

    protector.protect(b"x", purpose="identity-map", vault_id="vault_a")
    protector.protect(b"x", purpose="review-agent-secret", vault_id="vault_a")
    protector.protect(b"x", purpose="identity-map", vault_id="vault_b")

    entropies = {call[3] for call in backend.calls}
    assert len(entropies) == 3
    assert all(len(entropy) == 32 for entropy in entropies)


@pytest.mark.parametrize(
    ("purpose", "vault_id"),
    [
        ("review-agent-secret", "vault_b"),
        ("identity-map", "vault_a"),
    ],
)
def test_dpapi_rejects_different_entropy_context(
    purpose: str,
    vault_id: str,
) -> None:
    backend = _RecordingDpapiBackend()
    protector = WindowsDpapiProtector(backend=backend)
    blob = protector.protect(
        b"secret",
        purpose="review-agent-secret",
        vault_id="vault_a",
    )

    with pytest.raises(SecretDecryptionFailed, match="SECRET_DECRYPTION_FAILED"):
        protector.unprotect(blob, purpose=purpose, vault_id=vault_id)


def test_dpapi_decryption_error_does_not_chain_backend_details() -> None:
    backend = _RecordingDpapiBackend()
    protector = WindowsDpapiProtector(backend=backend)
    blob = protector.protect(b"secret", purpose="identity-map", vault_id="vault_a")

    with pytest.raises(SecretDecryptionFailed) as denied:
        protector.unprotect(
            blob,
            purpose="identity-map",
            vault_id="vault_b",
        )

    assert denied.value.__cause__ is None


@pytest.mark.parametrize(
    ("data", "purpose", "vault_id"),
    [
        (b"", "identity-map", "vault_a"),
        (b"x", "", "vault_a"),
        (b"x", "identity-map", ""),
        (b"x", "bad\ncontext", "vault_a"),
        (b"x", "identity-map", "bad\x00vault"),
    ],
)
def test_dpapi_rejects_invalid_secret_context(
    data: bytes,
    purpose: str,
    vault_id: str,
) -> None:
    protector = WindowsDpapiProtector(backend=_RecordingDpapiBackend())

    with pytest.raises(InvalidSecretContext, match="SECRET_CONTEXT_INVALID"):
        protector.protect(data, purpose=purpose, vault_id=vault_id)


def test_production_factory_fails_closed_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dpapi_module, "_PLATFORM", "linux")

    with pytest.raises(
        UnsupportedSecurityPlatform,
        match="SECURITY_PLATFORM_UNSUPPORTED",
    ):
        create_secret_protector()
