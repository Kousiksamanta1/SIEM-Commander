from __future__ import annotations

import base64
import json
import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen


class WazuhClientError(RuntimeError):
    """Raised when a Wazuh API or indexer request fails."""


DEFAULT_TIMEOUT = 15.0
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
INDEX_PATTERN_RE = re.compile(r"^[A-Za-z0-9._,*-]+$")


@dataclass(frozen=True)
class ConnectionSettings:
    base_url: str
    username: str
    password: str
    verify_tls: bool = True
    ca_bundle: str = ""
    timeout: float = DEFAULT_TIMEOUT

    @property
    def normalized_base_url(self) -> str:
        return self.base_url.rstrip("/")


def _to_text(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _basic_auth_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return f"Basic {base64.b64encode(raw).decode('ascii')}"


def _ssl_context(verify_tls: bool, ca_bundle: str = "") -> ssl.SSLContext:
    if verify_tls:
        if ca_bundle:
            bundle = Path(ca_bundle).expanduser()
            if not bundle.is_file():
                raise WazuhClientError(f"CA certificate bundle does not exist: {bundle}")
            return ssl.create_default_context(cafile=str(bundle))
        return ssl.create_default_context()
    # Lab-only mode explicitly selected by the operator for self-signed deployments.
    return ssl._create_unverified_context()  # nosec B323


def _read_limited(response: Any, url: str) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > MAX_RESPONSE_BYTES:
                raise WazuhClientError(f"Response from {url} exceeds the {MAX_RESPONSE_BYTES}-byte limit.")
        except ValueError:
            pass

    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise WazuhClientError(f"Response from {url} exceeds the {MAX_RESPONSE_BYTES}-byte limit.")
    return body


def _ensure_wazuh_success(payload: dict[str, Any], endpoint: str) -> None:
    error = payload.get("error")
    if error in (None, 0, "0"):
        return
    message = payload.get("message") or payload.get("detail") or "Unknown Wazuh API error"
    raise WazuhClientError(f"Wazuh API error from {endpoint}: {message}")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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
        parsed_url = urlparse(settings.normalized_base_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
            raise WazuhClientError("Connection URL must use http:// or https:// and include a hostname.")
        if parsed_url.username or parsed_url.password:
            raise WazuhClientError("Connection URL must not contain credentials.")

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

        request_headers = {
            "Accept": "application/json",
            "User-Agent": "SIEM-Commander/1.0",
        }
        if headers:
            request_headers.update(headers)

        body = None
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")

        request = Request(url, data=body, headers=request_headers, method=method.upper())
        try:
            # The constructor restricts base URLs to HTTP(S).
            with urlopen(  # nosec B310
                request,
                timeout=self.settings.timeout,
                context=_ssl_context(self.settings.verify_tls, self.settings.ca_bundle),
            ) as response:
                raw_text = _to_text(_read_limited(response, url))
        except HTTPError as exc:
            detail = _to_text(exc.read(4096)).strip()
            message = detail or exc.reason
            raise WazuhClientError(f"HTTP {exc.code} from {url}: {message}") from exc
        except URLError as exc:
            raise WazuhClientError(f"Unable to reach {url}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise WazuhClientError(f"Request to {url} timed out after {self.settings.timeout:g} seconds.") from exc
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
        raw_response = self.http.request(
            "POST",
            "/security/user/authenticate",
            headers=headers,
            params={"raw": "true"},
            expect_json=False,
        )
        token = str(raw_response).strip().strip('"')

        if not token:
            raise WazuhClientError("Wazuh API authentication succeeded without returning a token.")

        self._token = token
        return token

    def _request(self, method: str, path: str, *, params: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.authenticate()}"}
        response = self.http.request(method, path, headers=headers, params=params)
        if not isinstance(response, dict):
            raise WazuhClientError(f"Unexpected non-JSON response from {path}.")
        _ensure_wazuh_success(response, path)
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

    def fetch_recent_alerts(
        self,
        limit: int = 20,
        index_pattern: str = "wazuh-alerts-*",
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 200))
        index_pattern = index_pattern.strip()
        if not index_pattern or not INDEX_PATTERN_RE.fullmatch(index_pattern):
            raise WazuhClientError(
                "Alert index pattern may only contain letters, numbers, dots, underscores, commas, hyphens, and *."
            )

        query = {
            "size": limit,
            "track_total_hits": False,
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
                "@timestamp",
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
            f"/{quote(index_pattern, safe='*,._-')}/_search",
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
                    "timestamp": str(source.get("timestamp") or source.get("@timestamp") or ""),
                    "severity": _safe_int(_nested_get(source, "rule", "level", default=0)),
                    "rule_id": str(_nested_get(source, "rule", "id", default="")),
                    "rule_description": str(_nested_get(source, "rule", "description", default="Unknown rule")),
                    "agent_name": str(_nested_get(source, "agent", "name", default="manager")),
                    "agent_id": str(_nested_get(source, "agent", "id", default="")),
                    "manager_name": str(_nested_get(source, "manager", "name", default="")),
                    "source_ip": str(_nested_get(source, "data", "srcip", default="")),
                    "destination_user": str(_nested_get(source, "data", "dstuser", default="")),
                    "location": str(source.get("location", "")),
                }
            )
        return alerts
