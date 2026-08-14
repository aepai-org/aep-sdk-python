­r‡^Ñf¥–Ø¦{MìyÊ'vÃ®¶›­"""Public Python SDK exceptions."""

from .credential import redact_text


class AEPApiError(RuntimeError):
    """Structured non-success response returned by the AEP API."""

    def __init__(self, status: int, detail: str) -> None:
        detail = redact_text(detail)
        super().__init__(f"AEP API request failed ({status}): {detail}")
        self.status = status
        self.detail = detail
