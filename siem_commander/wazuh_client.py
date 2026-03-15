from __future__ import annotations

import base64
import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class WazuhClientError(RuntimeError):
    """Raised when a Wazuh API or indexer request fails."""


@dataclass(frozen=True)
class ConnectionSettings:
    base_url: str
    username: str
    password: str
    verify_tls: bool = True
    timeout: float = 10.0

    @property
    def normalized_base_url(self) -> str:
        return self.base_url.rstrip("/")


def _to_text(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _basic_auth_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return f"Basic {base64.b64encode(raw).decode('ascii')}"


def _ssl_context(verify_tls: bool) -> ssl.SSLContext:
    if verify_tls:
        return ssl.create_default_context()
    return ssl._create_unverified_context()  # type: ignore[attr-defined]


def _first_affected_item(payload: dict[str, Any]) -> Any:
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    items = data.get("affected_items")
    if isinstance(items, list) and items:
        return items[0]
    return {}


def _affected_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    items = data.get("affected_items")
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    return []


def _nested_get(payload: dict[str, Any], *path: str, default: Any = "") -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


class JsonHttpClient:
    def __init__(self, settings: ConnectionSettings) -> None:
        self.settings = settings

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        expect_json: bool = True,
    ) -> dict[str, Any] | str:
        url = f"{self.settings.normalized_base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"

        request_headers = {"Accept": "application/json"}
        if headers:
            request_headers.update(headers)

        body = None
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")

        request = Request(url, data=body, headers=request_headers, method=method.upper())
        try:
            with urlopen(
                request,
                timeout=self.settings.timeout,
                context=_ssl_context(self.settings.verify_tls),
            ) as response:
                raw_text = _to_text(response.read())
        except HTTPError as exc:
            detail = _to_text(exc.read()).strip()
            message = detail or exc.reason
            raise WazuhClientError(f"HTTP {exc.code} from {url}: {message}") from exc
        except URLError as exc:
            raise WazuhClientError(f"Unable to reach {url}: {exc.reason}") from exc
        except OSError as exc:
            raise WazuhClientError(f"Network error while calling {url}: {exc}") from exc

        if not expect_json:
            return raw_text

        try:
            parsed = json.loads(raw_text) if raw_text else {}
        except json.JSONDecodeError as exc:
            raise WazuhClientError(f"Expected JSON from {url}, received invalid data.") from exc

        if isinstance(parsed, dict):
            return parsed
        raise WazuhClientError(f"Unexpected response type from {url}.")


class WazuhApiClient:
    def __init__(self, settings: ConnectionSettings) -> None:
        self.settings = settings
        self.http = JsonHttpClient(settings)
        self._token: str | None = None

    def authenticate(self) -> str:
        if self._token:
            return self._token

        headers = {"Authorization": _basic_auth_header(self.settings.username, self.settings.password)}
        token_response = self.http.request(
            "POST",
            "/security/user/authenticate",
            headers=headers,
        )
        if isinstance(token_response, str):
            token = token_response.strip()
        else:
            token = _nested_get(token_response, "data", "token", default="").strip()

        if not token:
            raw_response = self.http.request(
                "POST",
                "/security/user/authenticate",
                headers=headers,
                params={"raw": "true"},
                expect_json=False,
            )
            token = str(raw_response).strip()

        if not token:
            raise WazuhClientError("Wazuh API authentication succeeded without returning a token.")

        self._token = token
        return token

    def _request(self, method: str, path: str, *, params: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.authenticate()}"}
        response = self.http.request(method, path, headers=headers, params=params)
        if not isinstance(response, dict):
            raise WazuhClientError(f"Unexpected non-JSON response from {path}.")
        return response

    def fetch_overview(self) -> dict[str, Any]:
        api_info = self._request("GET", "/")
        manager_status = self._request("GET", "/manager/status")
        agent_summary = self._request("GET", "/agents/summary/status")
        agents = self._request(
            "GET",
            "/agents",
            params={
                "limit": "10",
                "select": "id,name,status,ip,version,lastKeepAlive",
            },
        )

        agent_summary_data = agent_summary.get("data", {}) if isinstance(agent_summary.get("data"), dict) else {}

        return {
            "api_version": _nested_get(api_info, "data", "api_version", default="Unknown"),
            "api_title": _nested_get(api_info, "data", "title", default="Wazuh API"),
            "manager_daemons": _first_affected_item(manager_status),
            "agent_connection": agent_summary_data.get("connection", {}),
            "agent_configuration": agent_summary_data.get("configuration", {}),
            "agents": _affected_items(agents),
        }


class WazuhIndexerClient:
    def __init__(self, settings: ConnectionSettings) -> None:
        self.settings = settings
        self.http = JsonHttpClient(settings)
        self._headers = {"Authorization": _basic_auth_header(settings.username, settings.password)}

    def fetch_cluster_health(self) -> dict[str, Any]:
        response = self.http.request("GET", "/_cluster/health", headers=self._headers)
        if not isinstance(response, dict):
            raise WazuhClientError("Unexpected Wazuh indexer cluster health response.")
        return response

    def fetch_recent_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        query = {
            "size": limit,
            "sort": [
                {
                    "timestamp": {
                        "order": "desc",
                        "unmapped_type": "date",
                    }
                }
            ],
            "_source": [
                "timestamp",
                "location",
                "manager.name",
                "agent.id",
                "agent.name",
                "rule.id",
                "rule.level",
                "rule.description",
                "data.srcip",
                "data.dstuser",
            ],
            "query": {"match_all": {}},
        }
        response = self.http.request(
            "POST",
            "/wazuh-alerts*/_search",
            headers=self._headers,
            payload=query,
        )
        if not isinstance(response, dict):
            raise WazuhClientError("Unexpected Wazuh indexer alerts response.")

        hits_root = response.get("hits", {})
        hits = hits_root.get("hits", []) if isinstance(hits_root, dict) else []
        alerts: list[dict[str, Any]] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            source = hit.get("_source", {})
            if not isinstance(source, dict):
                continue
            alerts.append(
                {
                    "timestamp": str(source.get("timestamp", "")),
                    "severity": int(_nested_get(source, "rule", "level", default=0) or 0),
                    "rule_id": str(_nested_get(source, "rule", "id", default="")),
                    "rule_description": str(
                        _nested_get(source, "rule", "description", default="Unknown rule")
                    ),
                    "agent_name": str(_nested_get(source, "agent", "name", default="manager")),
                    "agent_id": str(_nested_get(source, "agent", "id", default="")),
                    "manager_name": str(_nested_get(source, "manager", "name", default="")),
                    "source_ip": str(_nested_get(source, "data", "srcip", default="")),
                    "destination_user": str(_nested_get(source, "data", "dstuser", default="")),
                    "location": str(source.get("location", "")),
                }
            )
        return alerts

