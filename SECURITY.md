# Security Policy

AEP AI accepts vulnerability reports through this repository's private GitHub
**Security → Report a vulnerability** form. Do not open a public issue or
include real credentials, private keys, signed payloads, personal data, or
production infrastructure details.

The current `main` branch and latest Developer Preview release are supported.
Reports should include the affected version, reproduction steps, and impact.
Testing must not target hosted production systems, disrupt service, or access
third-party data. See [aepai.org](https://aepai.org) for official project
information.

## Contact

Send security reports to [security@aepai.org](mailto:security@aepai.org) when
private vulnerability reporting is unavailable. Do not copy Developer or
community mailing li…1645 tokens truncated…t(
            "POST", f"/v1/agents/{agent_id}/verify", authenticated=True
        )

    def suspend_agent(self, agent_id: str) -> dict[str, Any]:
        return self._request(
            "POST", f"/v1/agents/{agent_id}/suspend", authenticated=True
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
    ) -> dict[str, Any]:
        if authenticated and self.__credential is None:
            raise ValueError("Developer API key is required for this operation")
        validate_credential_transport_url(
            self.base_url,
            allow_insecure_localhost=self._allow_insecure_localhost,
        )
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self.__credential is not None:
            headers["X-AEP-API-Key"] = self.__credential._reveal_for_transport()
        body = json.dumps(payload).encode() if payload is not None else None
        status, response = self._transport(
            method, f"{self.base_url}{path}", headers, body
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
            )
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
