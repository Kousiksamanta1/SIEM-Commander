from __future__ import annotations

from siem_commander.storage import CredentialStore


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        self.values.pop((service_name, username), None)


def test_credentials_round_trip_through_keyring() -> None:
    backend = FakeKeyring()
    store = CredentialStore(backend)

    store.save("wazuh-api", "analyst", "correct horse battery staple")
    credential = store.load("wazuh-api")

    assert credential is not None
    assert credential.username == "analyst"
    assert credential.password == "correct horse battery staple"
    assert "correct horse battery staple" not in repr(credential)

    store.delete("wazuh-api")
    assert store.load("wazuh-api") is None
