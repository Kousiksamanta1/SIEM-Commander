from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock

import pytest

from siem_commander.wazuh_client import (
    ConnectionSettings,
    JsonHttpClient,
    WazuhApiClient,
    WazuhClientError,
    WazuhIndexerClient,
)


def settings() -> ConnectionSettings:
    return ConnectionSettings("https://wazuh.example:55000", "analyst", "secret")


def test_http_client_rejects_non_http_urls_and_embedded_credentials() -> None:
    with pytest.raises(WazuhClientError, match="http"):
        JsonHttpClient(ConnectionSettings("file:///tmp/data.json", "", ""))

    with pytest.raises(WazuhClientError, match="must not contain credentials"):
        JsonHttpClient(ConnectionSettings("https://user:password@wazuh.example", "", ""))


def test_json_http_client_calls_a_real_http_endpoint() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = json.dumps({"status": "green"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        host, port = server.server_address
        client = JsonHttpClient(ConnectionSettings(f"http://{host}:{port}", "", "", timeout=2))
        assert client.request("GET", "/health") == {"status": "green"}
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


def test_api_authentication_uses_raw_jwt_endpoint() -> None:
    client = WazuhApiClient(settings())
    client.http.request = MagicMock(return_value="header.payload.signature")

    token = client.authenticate()

    assert token == "header.payload.signature"
    client.http.request.assert_called_once_with(
        "POST",
        "/security/user/authenticate",
        headers={"Authorization": "Basic YW5hbHlzdDpzZWNyZXQ="},
        params={"raw": "true"},
        expect_json=False,
    )


def test_api_overview_parses_current_wazuh_response_shape() -> None:
    client = WazuhApiClient(settings())
    client._token = "jwt"
    client.http.request = MagicMock(
        side_effect=[
            {"error": 0, "data": {"api_version": "4.14.5", "title": "Wazuh API"}},
            {"error": 0, "data": {"affected_items": [{"wazuh-analysisd": "running"}]}},
            {
                "error": 0,
                "data": {
                    "connection": {"active": 4, "disconnected": 1},
                    "configuration": {"synced": 5},
                },
            },
            {
                "error": 0,
                "data": {"affected_items": [{"id": "001", "name": "server-01", "status": "active", "ip": "10.0.0.10"}]},
            },
        ]
    )

    overview = client.fetch_overview()

    assert overview["api_version"] == "4.14.5"
    assert overview["manager_daemons"] == {"wazuh-analysisd": "running"}
    assert overview["agent_connection"]["active"] == 4
    assert overview["agents"][0]["name"] == "server-01"


def test_api_error_payload_is_raised() -> None:
    client = WazuhApiClient(settings())
    client._token = "jwt"
    client.http.request = MagicMock(return_value={"error": 1701, "message": "Unauthorized"})

    with pytest.raises(WazuhClientError, match="Unauthorized"):
        client._request("GET", "/manager/status")


def test_indexer_query_parses_alerts_and_escapes_index_pattern() -> None:
    client = WazuhIndexerClient(settings())
    client.http.request = MagicMock(
        return_value={
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "@timestamp": "2026-06-12T12:00:00Z",
                            "rule": {"level": "12", "id": "5712", "description": "SSH brute force"},
                            "agent": {"id": "001", "name": "server-01"},
                            "manager": {"name": "wazuh-manager"},
                            "data": {"srcip": "203.0.113.10"},
                            "location": "journald",
                        }
                    }
                ]
            }
        }
    )

    alerts = client.fetch_recent_alerts(limit=500, index_pattern="wazuh-alerts-*")

    assert alerts[0]["timestamp"] == "2026-06-12T12:00:00Z"
    assert alerts[0]["severity"] == 12
    assert alerts[0]["source_ip"] == "203.0.113.10"
    request = client.http.request.call_args
    assert request.args[:2] == ("POST", "/wazuh-alerts-*/_search")
    assert request.kwargs["payload"]["size"] == 200


def test_indexer_rejects_unsafe_index_pattern() -> None:
    client = WazuhIndexerClient(settings())

    with pytest.raises(WazuhClientError, match="index pattern"):
        client.fetch_recent_alerts(index_pattern="../../_all")
