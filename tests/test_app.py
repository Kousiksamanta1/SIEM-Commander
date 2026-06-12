from __future__ import annotations

import os
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication, QFileDialog

from siem_commander.app import (
    SIEMCommanderWindow,
    ensure_https_url,
    format_count_map,
    summarize_manager_daemons,
    validate_host,
    validate_service_url,
)
from siem_commander.storage import CredentialStore

from .test_storage import FakeKeyring


@pytest.fixture(scope="session")
def application() -> QApplication:
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(application: QApplication, tmp_path: Path) -> SIEMCommanderWindow:
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    credential_store = CredentialStore(FakeKeyring())
    app_window = SIEMCommanderWindow(settings=settings, credential_store=credential_store)
    yield app_window
    app_window.close()
    application.processEvents()


def test_helpers_validate_operator_input() -> None:
    assert ensure_https_url("wazuh.example:55000") == "https://wazuh.example:55000"
    assert validate_service_url("https://wazuh.example:55000") is None
    assert validate_service_url("ftp://wazuh.example") is not None
    assert validate_host("wazuh.example") is None
    assert validate_host("https://wazuh.example") is not None
    assert format_count_map({"active": 2, "disconnected": 1}) == "active: 2 | disconnected: 1"
    assert summarize_manager_daemons({"analysisd": "running", "remoted": "stopped"}) == "1/2 daemons running"


def test_window_is_usable_at_normal_desktop_size(window: SIEMCommanderWindow) -> None:
    window.show()
    QApplication.processEvents()

    assert window.width() == 1360
    assert window.height() == 860
    assert window.minimumSizeHint().height() < 700
    assert window.stack.count() == 3


def test_passwords_are_not_written_to_qsettings(window: SIEMCommanderWindow) -> None:
    window.wazuh_api_user_input.setText("api-user")
    window.wazuh_api_password_input.setText("api-secret")
    window.indexer_user_input.setText("indexer-user")
    window.indexer_password_input.setText("indexer-secret")

    window._save_settings()

    serialized_values = " ".join(str(window.settings.value(key)) for key in window.settings.allKeys())
    assert "api-secret" not in serialized_values
    assert "indexer-secret" not in serialized_values


def test_recent_alert_payload_updates_table(window: SIEMCommanderWindow) -> None:
    window._apply_recent_alerts(
        {
            "cluster_health": {"status": "green", "number_of_nodes": 3},
            "critical_count": 1,
            "alerts": [
                {
                    "timestamp": "2026-06-12T12:00:00Z",
                    "severity": 12,
                    "rule_id": "5712",
                    "rule_description": "SSH brute force",
                    "agent_name": "server-01",
                    "manager_name": "wazuh-manager",
                    "source_ip": "203.0.113.10",
                    "location": "journald",
                }
            ],
        }
    )

    assert window.alerts_table.rowCount() == 1
    assert window.alerts_table.item(0, 2).text() == "5712 - SSH brute force"
    assert window.indexer_card.value_label.text() == "green | nodes: 3"
    assert window.export_alerts_button.isEnabled()


def test_alerts_export_to_csv(
    window: SIEMCommanderWindow,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window._apply_recent_alerts(
        {
            "cluster_health": {"status": "green", "number_of_nodes": 1},
            "critical_count": 0,
            "alerts": [
                {
                    "timestamp": "2026-06-12T12:00:00Z",
                    "severity": 5,
                    "rule_id": "1001",
                    "rule_description": "Test alert",
                    "agent_name": "server-01",
                    "manager_name": "manager",
                    "source_ip": "192.0.2.10",
                    "location": "test",
                }
            ],
        }
    )
    output_path = tmp_path / "alerts.csv"
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *args, **kwargs: (str(output_path), "CSV Files (*.csv)"),
    )

    window.export_alerts_csv()

    output = output_path.read_text()
    assert "Timestamp,Severity,Rule" in output
    assert "1001 - Test alert" in output


def test_close_cancels_running_subprocess(
    application: QApplication,
    window: SIEMCommanderWindow,
) -> None:
    window.show()
    window.start_attack_task("nmap", "Nmap Stealth Scan")
    application.processEvents()
    assert window.active_jobs == 1

    window.close()
    deadline = time.monotonic() + 3
    while window.isVisible() and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert not window.isVisible()
    assert window.active_jobs == 0
    assert window._threads == []
