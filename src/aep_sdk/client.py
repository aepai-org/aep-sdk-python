"""Synchronous, dependency-free AEP Developer API client."""

import json
from collections.abc import Callable, Mapping
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .credential import MASKED_CREDENTIAL, SecretValue, redact_value
from .errors import AEPApiError
from .url_security import validate_credential_transport_url

JsonValue = dict[str, Any] | list[Any] | str | int | float | bool | None
Transport = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, JsonValue]]


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = build_opener(_RejectRedirects)


def _default_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
) -> tuple[int, JsonValue]:
    request = Request(url, data=body, headers=dict(headers), method=method)
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=15) as response:
            payload = response.read()
            return response.status, json.loads(payload) if payload else None
    except HTTPError as error:
        payload = error.read()
        try:
            detail: JsonValue = json.loads(payload) if payload else error.reason
        except json.JSONDecodeError:
            detail = payload.decode("utf-8", errors="replace")
        return error.code, detail


class AEPClient:
    """Thin client for existing AEP Registry, Runtime, Task, and Collaboration APIs."""

    __slots__ = (
        "__credential",
        "_allow_insecure_localhost",
        "_transport",
        "base_url",
    )

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        transport: Transport | None = None,
        allow_insecure_localhost: bool = False,
    ) -> None:
        validate_credential_transport_url(
            base_url,
            allow_insecure_localhost=allow_insecure_localhost,
        )
        self.base_url = base_url.rstrip("/")
        self.__credential = SecretValue(api_key) if api_key else None
        self._transport = transport or _default_transport
        self._allow_insecure_localhost = allow_insecure_localhost

    def register_agent(
        self,
        *,
        name: str,
        endpoint: str,
        protocol_version: str,
        capabilities: list[str],
        description: str = "",
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/v1/agents/register",
            {
                "name": name,
                "description": description,
                "endpoint": endpoint,
                "protocolVersion": protocol_version,
                "capabilities": capabilities,
            },
            authenticated=True,
        )

    def apply_for_early_access(
        self,
        *,
        name: str,
        email: str,
        github: str,
        agent_use_case: str,
        runtime_type: str,
        organization: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "name": name,
            "email": email,
            "github": github,
            "agent_use_case": agent_use_case,
            "runtime_type": runtime_type,
        }
        if organization:
            payload["organization"] = organization
        return self._request("POST", "/v1/early-access/applications", payload)

    def get_early_access_status(
        self, application_id: str, status_token: str
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/v1/early-access/applications/{application_id}",
            headers={"X-AEP-Access-Token": status_token},
            sensitive_values=(status_token,),
        )

    def activate_early_access_identity(
        self, *, invite_code: str, identity_name: str
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/v1/early-access/activate",
            {"invite_code": invite_code, "identity_name": identity_name},
            sensitive_values=(invite_code,),
        )

    def verify_agent(self, agent_id: str) -> dict[str, Any]:
        return self._request(
            "POST", f"/v1/agents/{agent_id}/verify", authenticated=True
        )

    def suspend_agent(self, agent_id: str) -> dict[str, Any]:
        return self._request(
            "POST", f"/v1/agents/{agent_id}/suspend", authenticated=True
        )

    def create_capability(
        self, *, name: str, category: str, description: str = ""
    ) -> dict[str, Any]:
        """Create one Capability through the authenticated public contract."""

        return self._request(
            "POST",
            "/v1/capabilities",
            {"name": name, "category": category, "description": description},
            authenticated=True,
        )

    def publish_capability(self, agent_id: str, capability_id: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/developers/agents/{agent_id}/capabilities",
            {"capability_id": capability_id},
            authenticated=True,
        )

    def heartbeat(self, agent_id: str, **heartbeat: Any) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/agents/{agent_id}/heartbeat",
            heartbeat,
            authenticated=True,
        )

    def get_network_live(self) -> dict[str, Any]:
        return self._request("GET", "/v1/network/live")

    def get_network_activity(
        self, *, limit: int = 20, offset: int = 0
    ) -> dict[str, Any]:
        query = urlencode({"limit": limit, "offset": offset})
        return self._request("GET", f"/v1/network/activity?{query}")

    def list_network_directory(
        self,
        *,
        capability: str | None = None,
        runtime: str | None = None,
        trust_level: str | None = None,
        minimum_reputation: float = 0,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        options: dict[str, str | int | float] = {
            "minimum_reputation": minimum_reputation,
            "limit": limit,
            "offset": offset,
        }
        if capability:
            options["capability"] = capability
        if runtime:
            options["runtime"] = runtime
        if trust_level:
            options["trust_level"] = trust_level
        return self._request("GET", f"/v1/network/directory?{urlencode(options)}")

    def get_network_identity(self) -> dict[str, Any]:
        return self._request("GET", "/v1/network/identity", authenticated=True)

    def create_network_task(
        self,
        *,
        requirement: str,
        title: str | None = None,
        required_capability: str | None = None,
        deadline: str | None = None,
        constraints: dict[str, Any] | None = None,
        risk_level: str = "STANDARD",
        optional_reward_amount: str | None = None,
        optional_reward_currency: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "requirement": requirement,
            "constraints": constraints or {},
            "risk_level": risk_level,
        }
        if title:
            payload["title"] = title
        if required_capability:
            payload["required_capability"] = required_capability
        if deadline:
            payload["deadline"] = deadline
        if optional_reward_amount is not None:
            payload["optional_reward_amount"] = optional_reward_amount
        if optional_reward_currency is not None:
            payload["optional_reward_currency"] = optional_reward_currency
        return self._request("POST", "/v1/network/tasks", payload, authenticated=True)

    def get_network_task_journey(self, task_id: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/v1/network/tasks/{task_id}/journey",
            authenticated=True,
        )

    def link_network_wallet(
        self,
        *,
        role: str,
        network: str,
        address: str,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        payload = {"role": role, "network": network, "address": address}
        if agent_id:
            payload["agent_id"] = agent_id
        return self._request("POST", "/v1/network/wallets", payload, authenticated=True)

    def request_agent_verification(self, agent_id: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/agents/{agent_id}/verification-requests",
            authenticated=True,
        )

    def get_agent_trust(self, agent_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/agents/{agent_id}/trust", authenticated=True)

    def create_task(self, *, title: str, description: str = "") -> dict[str, Any]:
        return self._request(
            "POST", "/v1/tasks", {"title": title, "description": description}
        )

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/tasks/{task_id}")

    def list_tasks(self, *, limit: int = 20, offset: int = 0) -> dict[str, Any]:
        query = urlencode({"limit": limit, "offset": offset})
        return self._request("GET", f"/v1/tasks?{query}")

    def add_task_capability(
        self,
        task_id: str,
        capability_id: str,
        requirement_type: str = "REQUIRED",
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/tasks/{task_id}/capabilities",
            {
                "capability_id": capability_id,
                "requirement_type": requirement_type,
            },
        )

    def create_collaboration_session(
        self,
        task_id: str,
        *,
        title: str,
        participants: list[dict[str, Any]],
        workflow_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/tasks/{task_id}/collaboration-sessions",
            {
                "title": title,
                "workflow_id": workflow_id,
                "participants": participants,
            },
            authenticated=True,
        )

    def get_collaboration_session(self, session_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/collaboration-sessions/{session_id}")

    def send_collaboration_message(
        self, session_id: str, **message: Any
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/collaboration-sessions/{session_id}/messages",
            message,
            authenticated=True,
        )

    def list_collaboration_messages(self, session_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/collaboration-sessions/{session_id}/messages")

    def sync_collaboration_channel(self, channel_id: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/collaboration-channels/{channel_id}/sync",
            authenticated=True,
        )

    def close_collaboration_session(self, session_id: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/collaboration-sessions/{session_id}/close",
            authenticated=True,
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        authenticated: bool = False,
        headers: Mapping[str, str] | None = None,
        sensitive_values: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        if authenticated and self.__credential is None:
            raise ValueError("Developer API key is required for this operation")
        validate_credential_transport_url(
            self.base_url,
            allow_insecure_localhost=self._allow_insecure_localhost,
        )
        request_headers = {"Accept": "application/json"}
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        if self.__credential is not None:
            request_headers["X-AEP-API-Key"] = self.__credential._reveal_for_transport()
        if headers:
            request_headers.update(headers)
        body = json.dumps(payload).encode() if payload is not None else None
        status, response = self._transport(
            method, f"{self.base_url}{path}", request_headers, body
        )
        if status < 200 or status >= 300:
            detail = (
                response.get("detail", "Unknown API error")
                if isinstance(response, dict)
                else str(response)
            )
            secrets = (
                (self.__credential._reveal_for_transport(),)
                if self.__credential is not None
                else ()
            ) + sensitive_values
            raise AEPApiError(status, str(redact_value(detail, known_secrets=secrets)))
        if not isinstance(response, dict):
            raise AEPApiError(status, "Expected a JSON object response")
        return response

    def __repr__(self) -> str:
        credential = MASKED_CREDENTIAL if self.__credential is not None else None
        return f"AEPClient(base_url={self.base_url!r}, credential={credential!r})"

    def __getstate__(self) -> dict[str, str | None]:
        credential = MASKED_CREDENTIAL if self.__credential is not None else None
        return {"base_url": self.base_url, "credential": credential}
