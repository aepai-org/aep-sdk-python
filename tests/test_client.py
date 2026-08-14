import json
from urllib.parse import urlsplit

import pytest
from aep_sdk import (
    HTTPS_REQUIRED,
    MASKED_CREDENTIAL,
    AEPApiError,
    AEPClient,
    CredentialTransportError,
    create_agent_card,
    redact_value,
)


class FakeTransport:
    def __init__(self) -> None:
        self.calls = []

    def __call__(self, method, url, headers, body):
        path = urlsplit(url).path
        payload = json.loads(body) if body else None
        self.calls.append((method, path, dict(headers), payload))
        if path == "/v1/agents/register":
            return 201, {"id": "agent-1", "status": "REGISTERED"}
        if path == "/v1/agents/agent-1/verify":
            return 200, {"id": "agent-1", "status": "ACTIVE"}
        if path.endswith("/capabilities"):
            return 200, {"agent_id": "agent-1", "capabilities": []}
        if path.endswith("/heartbeat"):
            return 200, {"agent_id": "agent-1", "status": "AVAILABLE"}
        if path == "/v1/tasks":
            return 201, {"id": "task-1", "status": "CREATED"}
        if path.endswith("/collaboration-sessions"):
            return 201, {"id": "session-1", "status": "ACTIVE"}
        if path.endswith("/messages"):
            return 200, {"id": "message-1", "delivery_status": "SENT"}
        return 404, {"detail": "Not found"}


def test_sdk_agent_capability_heartbeat_lifecycle() -> None:
    transport = FakeTransport()
    client = AEPClient(
        base_url="https://aep.example/",
        api_key="aep_dev_test_key_long_enough",
        transport=transport,
    )

    agent = client.register_agent(
        name="Research Agent",
        description="Research",
        endpoint="https://agent.example/a2a",
        protocol_version="1.0",
        capabilities=["capability-1"],
    )
    active = client.verify_agent(agent["id"])
    client.publish_capability(agent["id"], "capability-2")
    runtime = client.heartbeat(
        agent["id"],
        status="AVAILABLE",
        health_status="HEALTHY",
        current_load=0,
        max_concurrency=2,
        timestamp="2026-08-12T10:00:00Z",
        metadata={},
    )

    assert active["status"] == "ACTIVE"
    assert runtime["status"] == "AVAILABLE"
    assert all(
        call[2]["X-AEP-API-Key"] == "aep_dev_test_key_long_enough"
        for call in transport.calls
    )
    assert transport.calls[0][3]["protocolVersion"] == "1.0"


def test_sdk_task_and_collaboration_flow() -> None:
    transport = FakeTransport()
    client = AEPClient(
        base_url="https://aep.example",
        api_key="aep_dev_test_key_long_enough",
        transport=transport,
    )
    task = client.create_task(title="Research EV market")
    session = client.create_collaboration_session(
        task["id"],
        title="Research handoff",
        participants=[
            {"agent_id": "agent-1", "participant_role": "RESEARCHER"},
            {"agent_id": "agent-2", "participant_role": "VERIFIER"},
        ],
    )
    message = client.send_collaboration_message(
        session["id"],
        sender_agent_id="agent-1",
        recipient_agent_id="agent-2",
        message_kind="HANDOFF",
        parts=[{"kind": "text", "text": "Review the report"}],
        client_message_id="handoff-1",
    )

    assert task["status"] == "CREATED"
    assert session["status"] == "ACTIVE"
    assert message["delivery_status"] == "SENT"


def test_sdk_requires_authentication_and_returns_api_errors() -> None:
    client = AEPClient(base_url="https://aep.example", transport=FakeTransport())
    with pytest.raises(ValueError, match="API key"):
        client.register_agent(
            name="Agent",
            endpoint="https://agent.example/a2a",
            protocol_version="1.0",
            capabilities=["capability-1"],
        )

    client = AEPClient(
        base_url="https://aep.example",
        api_key="key",
        transport=lambda *_: (401, {"detail": "Invalid API key"}),
    )
    with pytest.raises(AEPApiError) as error:
        client.publish_capability("agent-1", "capability-1")
    assert error.value.status == 401


def test_python_agent_card_helper() -> None:
    card = create_agent_card(
        name="Simple Agent",
        endpoint="https://simple.example/a2a",
        skills=[{"id": "echo", "name": "Echo", "description": "Echoes text"}],
    )
    assert card["protocolVersion"] == "1.0"
    with pytest.raises(ValueError, match="credentials"):
        create_agent_card(
            name="Unsafe",
            endpoint="https://user:secret@simple.example/a2a",
        )


def test_sdk_credential_transport_policy_blocks_before_transport() -> None:
    transport = FakeTransport()
    with pytest.raises(CredentialTransportError) as error:
        AEPClient(
            base_url="http://api.aep.example",
            api_key="must-not-leave-process",
            transport=transport,
        )
    assert error.value.code == HTTPS_REQUIRED
    assert transport.calls == []

    with pytest.raises(CredentialTransportError):
        AEPClient(
            base_url="http://localhost:8000",
            api_key="development-key-without-explicit-flag",
            transport=transport,
        )
    assert transport.calls == []

    local = AEPClient(
        base_url="http://localhost:8000",
        api_key="development-only-key",
        transport=lambda method, url, headers, body: (
            transport.calls.append((method, url, dict(headers), body))
            or (200, {"id": "task-1"})
        ),
        allow_insecure_localhost=True,
    )
    local.get_task("task-1")
    assert len(transport.calls) == 1

    https = AEPClient(
        base_url="https://api.aep.example",
        api_key="production-key",
        transport=lambda method, url, headers, body: (
            transport.calls.append((method, url, dict(headers), body))
            or (200, {"id": "task-2"})
        ),
    )
    https.get_task("task-2")
    assert len(transport.calls) == 2

    with pytest.raises(CredentialTransportError):
        AEPClient(
            base_url="http://api.aep.example",
            api_key="must-not-leave-process",
            transport=transport,
            allow_insecure_localhost=True,
        )
    assert len(transport.calls) == 2


def test_sdk_credential_repr_exception_and_serialization_are_redacted() -> None:
    credential = "aep_dev_python_sdk_super_secret"

    def failing_transport(method, url, headers, body):
        assert headers["X-AEP-API-Key"] == credential
        return 401, {"detail": f"Authorization: Bearer {credential}"}

    client = AEPClient(
        base_url="https://api.aep.example",
        api_key=credential,
        transport=failing_transport,
    )
    serialized = json.dumps(client.__getstate__())
    assert credential not in repr(client)
    assert credential not in serialized
    assert MASKED_CREDENTIAL in repr(client)
    assert not hasattr(client, "__dict__")
    with pytest.raises(AEPApiError) as error:
        client.publish_capability("agent-1", "capability-1")
    assert credential not in str(error.value)
    assert credential not in error.value.detail
    assert MASKED_CREDENTIAL in error.value.detail
    telemetry = redact_value(
        {
            "apiKey": credential,
            "privateKey": (
                "-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----"
            ),
        },
        known_secrets=(credential,),
    )
    rendered = json.dumps(telemetry)
    assert credential not in rendered
    assert "BEGIN EC PRIVATE KEY" not in rendered
