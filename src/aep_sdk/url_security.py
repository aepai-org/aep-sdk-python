"""Credential transport policy shared by Python SDK clients."""

from ipaddress import ip_address
from urllib.parse import SplitResult, urlsplit

HTTPS_REQUIRED = "HTTPS_REQUIRED"


class CredentialTransportError(ValueError):
    """Raised before credentials can be attached to an unsafe request."""

    code = HTTPS_REQUIRED

    def __init__(self) -> None:
        super().__init__(
            f"{HTTPS_REQUIRED}: Developer API credentials require HTTPS; "
            "loopback HTTP is allowed only with allow_insecure_localhost=True"
        )


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_credential_transport_url(
    value: str,
    *,
    allow_insecure_localhost: bool = False,
) -> SplitResult:
    """Validate an AEP API URL before a credential may enter request headers."""

    parsed = urlsplit(value)
    if not parsed.hostname:
        raise ValueError("AEP base_url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("AEP base_url must not contain credentials")
    if parsed.scheme == "https":
        return parsed
    if (
        parsed.scheme == "http"
        and allow_insecure_localhost
        and _is_loopback(parsed.hostname)
    ):
        return parsed
    if parsed.scheme == "http":
        raise CredentialTransportError()
    raise ValueError("AEP base_url must use HTTPS")
