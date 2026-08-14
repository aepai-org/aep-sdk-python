­r‡^Ñf¥–Ø¦{MìyÊ'vÃ®¶›­"""Small standard A2A Agent Card construction helpers."""

from typing import Any
from urllib.parse import urlsplit

WELL_KNOWN_AGENT_CARD_PATH = "/.well-known/agent-card.json"


def _validate_endpoint(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Agent endpoint must be a valid HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("Agent endpoint must not contain credentials")


def create_agent_card(
    *,
    name: str,
    endpoint: str,
    description: str = "",
    protocol_version: str = "1.0",
    skills: list[dict[str, Any]] | None = None,
    **additional_fields: Any,
) -> dict[str, Any]:
    """Create a minimal A2A-compatible Card without changing the protocol."""

    normalized_name = name.strip()
    if not normalized_name:
        raise ValueError("Agent Card name is required")
    _validate_endpoint(endpoint)
    normalized_skills = skills or []
    for skill in normalized_skills:
        if (
            not str(skill.get("id", "")).strip()
            or not str(skill.get("name", "")).strip()
        ):
            raise ValueError("Every Agent skill requires id and name")
    return {
        **additional_fields,
        "name": normalized_name,
        "description": description.strip(),
        "url": endpoint,
        "protocolVersion": protocol_version,
        "skills": normalized_skills,
    }
