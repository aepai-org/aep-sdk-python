"""Credential storage and redaction for the Python SDK."""

import re
from collections.abc import Mapping, Sequence
from itertools import pairwise
from typing import Any

MASKED_CREDENTIAL = "***masked***"

_SENSITIVE_KEY = re.compile(
    r"(?:^|[_\-.])(?:api[_-]?key|authorization|bearer|credential|password|"
    r"cookie|private[_-]?key|secret|seed|signature|token)(?:$|[_\-.])",
    re.IGNORECASE,
)
_AEP_KEY = re.compile(
    r"\baep_(?:dev|agent|provider|verifier|settlement)_[A-Za-z0-9._~-]+"
)
_AUTHORIZATION = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*)(?:bearer|basic)\s+[^\s,;]+"
)
_AUTH_SCHEME = re.compile(r"(?i)\b((?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def _is_sensitive_key(key: str) -> bool:
    if _SENSITIVE_KEY.search(key):
        return True
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    words = re.sub(r"[^A-Za-z0-9]+", " ", words).casefold().split()
    return any(
        item in words
        for item in (
            "authorization",
            "bearer",
            "cookie",
            "credential",
            "password",
            "secret",
            "seed",
            "signature",
            "token",
        )
    ) or any(
        left in ("api", "private") and right == "key" for left, right in pairwise(words)
    )


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY)"
    r"\s*=\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)


class SecretValue:
    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Developer API key must not be empty")
        self.__value = normalized

    def _reveal_for_transport(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return f"SecretValue({MASKED_CREDENTIAL!r})"

    def __str__(self) -> str:
        return MASKED_CREDENTIAL

    def __getstate__(self) -> dict[str, str]:
        return {"value": MASKED_CREDENTIAL}


def redact_text(value: str, *, known_secrets: Sequence[str] = ()) -> str:
    redacted = value
    for secret in sorted(
        {item for item in known_secrets if item}, key=len, reverse=True
    ):
        redacted = redacted.replace(secret, MASKED_CREDENTIAL)
    redacted = _PRIVATE_KEY.sub(MASKED_CREDENTIAL, redacted)
    redacted = _AUTHORIZATION.sub(rf"\1{MASKED_CREDENTIAL}", redacted)
    redacted = _AUTH_SCHEME.sub(rf"\1{MASKED_CREDENTIAL}", redacted)
    redacted = _AEP_KEY.sub(MASKED_CREDENTIAL, redacted)
    return _SECRET_ASSIGNMENT.sub(rf"\1{MASKED_CREDENTIAL}", redacted)


def redact_value(
    value: Any,
    *,
    key: str = "",
    known_secrets: Sequence[str] = (),
    _depth: int = 0,
) -> Any:
    if key and _is_sensitive_key(key):
        return MASKED_CREDENTIAL
    if _depth >= 8:
        return "[TRUNCATED]"
    if isinstance(value, Mapping):
        return {
            str(item_key): redact_value(
                item_value,
                key=str(item_key),
                known_secrets=known_secrets,
                _depth=_depth + 1,
            )
            for item_key, item_value in list(value.items())[:100]
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            redact_value(item, known_secrets=known_secrets, _depth=_depth + 1)
            for item in value[:100]
        ]
    if isinstance(value, str):
        return redact_text(value, known_secrets=known_secrets)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value), known_secrets=known_secrets)
