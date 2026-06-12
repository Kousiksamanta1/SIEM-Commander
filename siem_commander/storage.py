from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Protocol


class KeyringBackend(Protocol):
    def get_password(self, service_name: str, username: str) -> str | None: ...

    def set_password(self, service_name: str, username: str, password: str) -> None: ...

    def delete_password(self, service_name: str, username: str) -> None: ...


@dataclass(frozen=True)
class StoredCredential:
    username: str
    password: str = field(repr=False)


class CredentialStore:
    """Stores secrets in the operating system keyring, never in QSettings."""

    SERVICE_NAME = "SIEM-Commander"

    def __init__(self, backend: KeyringBackend | None = None) -> None:
        if backend is None:
            try:
                import keyring
            except ImportError as exc:
                raise RuntimeError("Secure credential storage requires the 'keyring' package.") from exc
            try:
                if keyring.get_keyring().priority <= 0:
                    raise RuntimeError("No secure operating system keyring backend is available.")
            except RuntimeError:
                raise
            except Exception as exc:
                raise RuntimeError(f"Unable to initialize the operating system keyring: {exc}") from exc
            backend = keyring
        self.backend = backend

    def load(self, name: str) -> StoredCredential | None:
        try:
            raw_value = self.backend.get_password(self.SERVICE_NAME, name)
        except Exception as exc:
            raise RuntimeError(f"Unable to read {name} credentials from the OS keyring: {exc}") from exc
        if not raw_value:
            return None

        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Stored {name} credentials are invalid.") from exc
        username = payload.get("username")
        password = payload.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise RuntimeError(f"Stored {name} credentials are invalid.")
        return StoredCredential(username=username, password=password)

    def save(self, name: str, username: str, password: str) -> None:
        payload = json.dumps({"username": username, "password": password})
        try:
            self.backend.set_password(self.SERVICE_NAME, name, payload)
        except Exception as exc:
            raise RuntimeError(f"Unable to save {name} credentials to the OS keyring: {exc}") from exc

    def delete(self, name: str) -> None:
        try:
            self.backend.delete_password(self.SERVICE_NAME, name)
        except Exception as exc:
            if exc.__class__.__name__ != "PasswordDeleteError":
                raise RuntimeError(f"Unable to delete {name} credentials from the OS keyring: {exc}") from exc
