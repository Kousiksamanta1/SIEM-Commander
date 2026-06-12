from __future__ import annotations

import csv
import platform
import subprocess  # nosec B404
import sys
import threading
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import paramiko
from PyQt6.QtCore import QObject, QSettings, Qt, QThread, QTime, QTimer, QUrl, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QDesktopServices, QFontDatabase
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from siem_commander.storage import CredentialStore
from siem_commander.wazuh_client import ConnectionSettings, WazuhApiClient, WazuhClientError, WazuhIndexerClient

MOCK_TASK_SCRIPT = Path(__file__).with_name("mock_tasks.py")
ACCENT = "#177245"
ACCENT_ALT = "#0f5c38"
BACKGROUND = "#f2f5f1"
SURFACE = "#ffffff"
PANEL = "#f8faf7"
TEXT = "#18231d"
MUTED = "#647168"
SUCCESS = "#1f8a55"
WARNING = "#b7791f"
ERROR = "#c2414b"
DEFAULT_ALERT_INDEX = "wazuh-alerts-*"
SETTINGS_ORGANIZATION = "SIEM-Commander"
SETTINGS_APPLICATION = "SIEM-Commander"


def normalize_text(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        return value.decode(errors="replace")
    return str(value)


def base_mock_command(mode: str, *args: str) -> list[str]:
    return [sys.executable, "-u", str(MOCK_TASK_SCRIPT), mode, *args]


def build_attack_command(action: str, target: str) -> list[str]:
    return base_mock_command("attack", action, target)


@dataclass(frozen=True)
class DashboardLink:
    title: str
    description: str
    template: str


def format_count_map(values: dict[str, Any]) -> str:
    if not values:
        return "No data"
    parts: list[str] = []
    for key in ("active", "disconnected", "pending", "never_connected"):
        if key in values:
            label = key.replace("_", " ")
            parts.append(f"{label}: {values[key]}")
    if not parts:
        parts.extend(f"{key}: {value}" for key, value in values.items())
    return " | ".join(parts)


def summarize_manager_daemons(daemons: dict[str, Any]) -> str:
    if not daemons:
        return "No data"
    running = 0
    total = 0
    for state in daemons.values():
        total += 1
        if str(state).lower() == "running":
            running += 1
    return f"{running}/{total} daemons running"


def ensure_https_url(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        return ""
    if "://" not in cleaned:
        return f"https://{cleaned}"
    return cleaned


def validate_service_url(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "http"}:
        return "URL must use http:// or https://."
    if not parsed.hostname:
        return "URL must include a valid hostname or IP address."
    if parsed.username or parsed.password:
        return "Do not place credentials inside the URL."
    if parsed.query or parsed.fragment:
        return "URL query strings and fragments are not supported."
    return None


def validate_host(value: str) -> str | None:
    if not value:
        return "A hostname or IP address is required."
    if "://" in value or any(character in value for character in "/?#@"):
        return "Enter only a hostname or IP address, without a URL scheme or path."
    if any(character.isspace() for character in value):
        return "Hostname or IP address cannot contain spaces."
    return None


def url_host(value: str) -> str:
    return f"[{value}]" if ":" in value and not value.startswith("[") else value


def table_item(value: object) -> QTableWidgetItem:
    item = QTableWidgetItem(normalize_text(value))
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "Unknown") -> None:
        super().__init__()
        self.setObjectName("statCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        title_label = QLabel(title)
        title_label.setObjectName("cardTitle")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("cardValue")
        self.value_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(self.value_label)
        layout.addStretch()

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


class CancellableWorker(QObject):
    def __init__(self) -> None:
        super().__init__()
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()


class ProcessWorker(CancellableWorker):
    log_message = pyqtSignal(str)
    finished = pyqtSignal(str, bool)

    def __init__(self, task_name: str, command: list[str]) -> None:
        super().__init__()
        self.task_name = task_name
        self.command = command
        self._process: subprocess.Popen[str] | None = None

    def cancel(self) -> None:
        super().cancel()
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    @pyqtSlot()
    def run(self) -> None:
        if self.cancelled:
            self.finished.emit(self.task_name, False)
            return
        self.log_message.emit(f"[{self.task_name}] Launching subprocess: {' '.join(self.command)}")
        try:
            # The command is an argv list and shell=False.
            process = subprocess.Popen(  # nosec B603
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self._process = process
            if self.cancelled:
                process.terminate()
        except FileNotFoundError as exc:
            self.log_message.emit(f"[{self.task_name}] Unable to start subprocess: {exc}")
            self.finished.emit(self.task_name, False)
            return
        except Exception as exc:  # pragma: no cover - defensive guard
            self.log_message.emit(f"[{self.task_name}] Unexpected launch failure: {exc}")
            self.finished.emit(self.task_name, False)
            return

        try:
            if process.stdout is not None:
                for line in process.stdout:
                    clean_line = line.rstrip()
                    if clean_line:
                        self.log_message.emit(f"[{self.task_name}] {clean_line}")
                    if self.cancelled:
                        break

            return_code = process.wait()
            success = return_code == 0 and not self.cancelled
            if self.cancelled:
                state = "cancelled"
            else:
                state = "completed successfully" if success else f"failed with exit code {return_code}"
            self.log_message.emit(f"[{self.task_name}] Task {state}")
            self.finished.emit(self.task_name, success)
        except Exception as exc:  # pragma: no cover - defensive worker boundary
            self.log_message.emit(f"[{self.task_name}] Subprocess failure: {exc}")
            self.finished.emit(self.task_name, False)
        finally:
            self._process = None


class SSHStatusWorker(CancellableWorker):
    log_message = pyqtSignal(str)
    finished = pyqtSignal(str, bool)
    status_ready = pyqtSignal(str)

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        mock_mode: bool,
        key_file: str = "",
        allow_unknown_host: bool = False,
    ) -> None:
        super().__init__()
        self.host = host
        self.username = username
        self.password = password
        self.mock_mode = mock_mode
        self.key_file = key_file
        self.allow_unknown_host = allow_unknown_host
        self.task_name = "Check SIEM Status"
        self._client: paramiko.SSHClient | None = None
        self._mock_process: subprocess.Popen[str] | None = None

    def cancel(self) -> None:
        super().cancel()
        mock_process = self._mock_process
        if mock_process is not None and mock_process.poll() is None:
            mock_process.terminate()
        client = self._client
        if client is not None:
            client.close()

    def _run_mock(self) -> bool:
        if self.cancelled:
            return False
        command = base_mock_command("ssh", self.host, self.username)
        try:
            # The mock command uses a fixed local executable and arguments.
            process = subprocess.Popen(  # nosec B603
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self._mock_process = process
            if self.cancelled:
                process.terminate()
        except Exception as exc:
            self.log_message.emit(f"[{self.task_name}] Mock SSH launch failed: {exc}")
            self.status_ready.emit("Mock launch failed")
            return False

        try:
            if process.stdout is not None:
                for line in process.stdout:
                    clean_line = line.rstrip()
                    if clean_line:
                        self.log_message.emit(f"[{self.task_name}] {clean_line}")
                    if self.cancelled:
                        break

            return_code = process.wait()
            success = return_code == 0 and not self.cancelled
            self.status_ready.emit("Mock: active (running)" if success else "Mock: unavailable")
            return success
        finally:
            self._mock_process = None

    @pyqtSlot()
    def run(self) -> None:
        if self.cancelled:
            self.finished.emit(self.task_name, False)
            return
        if self.mock_mode:
            self.log_message.emit(f"[{self.task_name}] Mock mode enabled for host {self.host}")
            success = self._run_mock()
            self.finished.emit(self.task_name, success)
            return

        self.log_message.emit(f"[{self.task_name}] Connecting to {self.host} over SSH")
        client = paramiko.SSHClient()
        self._client = client
        client.load_system_host_keys()
        client.set_missing_host_key_policy(
            paramiko.WarningPolicy() if self.allow_unknown_host else paramiko.RejectPolicy()
        )

        try:
            client.connect(
                hostname=self.host,
                username=self.username,
                password=self.password or None,
                key_filename=self.key_file or None,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                look_for_keys=True,
                allow_agent=True,
            )
            if self.cancelled:
                self.status_ready.emit("Check cancelled")
                self.finished.emit(self.task_name, False)
                return
            self.log_message.emit(f"[{self.task_name}] SSH connection established")
            # The command is a fixed constant, not user input.
            _, stdout, stderr = client.exec_command(  # nosec B601
                "systemctl is-active wazuh-manager && systemctl status wazuh-manager --no-pager --lines=20",
                get_pty=True,
                timeout=10,
            )

            status_line = "Status output received"
            for stream in (stdout, stderr):
                while True:
                    if self.cancelled:
                        self.status_ready.emit("Check cancelled")
                        self.finished.emit(self.task_name, False)
                        return
                    line = stream.readline()
                    if not line:
                        break
                    clean_line = normalize_text(line).rstrip()
                    if clean_line:
                        normalized_line = clean_line.strip().lower()
                        if normalized_line in {"active", "inactive", "failed", "activating", "deactivating"}:
                            status_line = f"Service state: {normalized_line}"
                        elif normalized_line.startswith("active:"):
                            status_line = clean_line
                        self.log_message.emit(f"[{self.task_name}] {clean_line}")

            exit_status = stdout.channel.recv_exit_status()
            success = exit_status == 0
            self.status_ready.emit(status_line)
            self.finished.emit(self.task_name, success)
        except paramiko.BadHostKeyException as exc:
            self.log_message.emit(f"[{self.task_name}] SSH host key mismatch: {exc}")
            self.status_ready.emit("SSH host key mismatch")
            self.finished.emit(self.task_name, False)
        except paramiko.AuthenticationException:
            self.log_message.emit(f"[{self.task_name}] Authentication failed for {self.username}@{self.host}")
            self.status_ready.emit("Authentication failed")
            self.finished.emit(self.task_name, False)
        except paramiko.ssh_exception.NoValidConnectionsError as exc:
            self.log_message.emit(f"[{self.task_name}] Unable to connect to SSH: {exc}")
            self.status_ready.emit("SSH connection failed")
            self.finished.emit(self.task_name, False)
        except (paramiko.SSHException, OSError) as exc:
            state = "Check cancelled" if self.cancelled else "SSH connection failed"
            self.log_message.emit(f"[{self.task_name}] SSH error: {exc}")
            self.status_ready.emit(state)
            self.finished.emit(self.task_name, False)
        except Exception as exc:  # pragma: no cover - defensive worker boundary
            self.log_message.emit(f"[{self.task_name}] Unexpected SSH failure: {exc}")
            self.status_ready.emit("SSH check failed")
            self.finished.emit(self.task_name, False)
        finally:
            client.close()
            self._client = None


class WazuhOverviewWorker(CancellableWorker):
    log_message = pyqtSignal(str)
    finished = pyqtSignal(str, bool)
    overview_ready = pyqtSignal(object)

    def __init__(self, settings: ConnectionSettings) -> None:
        super().__init__()
        self.settings = settings
        self.task_name = "Refresh Wazuh Overview"

    @pyqtSlot()
    def run(self) -> None:
        if self.cancelled:
            self.finished.emit(self.task_name, False)
            return
        self.log_message.emit(f"[{self.task_name}] Connecting to {self.settings.base_url}")
        try:
            overview = WazuhApiClient(self.settings).fetch_overview()
        except WazuhClientError as exc:
            self.log_message.emit(f"[{self.task_name}] {exc}")
            self.finished.emit(self.task_name, False)
            return
        except Exception as exc:  # pragma: no cover - defensive worker boundary
            self.log_message.emit(f"[{self.task_name}] Unexpected API failure: {exc}")
            self.finished.emit(self.task_name, False)
            return

        if self.cancelled:
            self.log_message.emit(f"[{self.task_name}] Refresh cancelled.")
            self.finished.emit(self.task_name, False)
            return

        agent_connection = overview.get("agent_connection", {})
        manager_daemons = overview.get("manager_daemons", {})
        self.log_message.emit(
            f"[{self.task_name}] API {overview.get('api_version', 'unknown')} | "
            f"{summarize_manager_daemons(manager_daemons)}"
        )
        self.log_message.emit(f"[{self.task_name}] Agent connectivity: {format_count_map(agent_connection)}")
        for agent in overview.get("agents", [])[:5]:
            agent_name = agent.get("name", "unknown-agent")
            agent_state = agent.get("status", "unknown")
            agent_ip = agent.get("ip", "n/a")
            self.log_message.emit(f"[{self.task_name}] Agent {agent_name} ({agent_ip}) status={agent_state}")

        self.overview_ready.emit(overview)
        self.finished.emit(self.task_name, True)


class RecentAlertsWorker(CancellableWorker):
    log_message = pyqtSignal(str)
    finished = pyqtSignal(str, bool)
    alerts_ready = pyqtSignal(object)

    def __init__(
        self,
        settings: ConnectionSettings,
        limit: int = 20,
        index_pattern: str = DEFAULT_ALERT_INDEX,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.limit = limit
        self.index_pattern = index_pattern
        self.task_name = "Load Recent Alerts"

    @pyqtSlot()
    def run(self) -> None:
        if self.cancelled:
            self.finished.emit(self.task_name, False)
            return
        self.log_message.emit(f"[{self.task_name}] Querying indexer at {self.settings.base_url}")
        client = WazuhIndexerClient(self.settings)
        try:
            cluster_health = client.fetch_cluster_health()
            alerts = client.fetch_recent_alerts(limit=self.limit, index_pattern=self.index_pattern)
        except WazuhClientError as exc:
            self.log_message.emit(f"[{self.task_name}] {exc}")
            self.finished.emit(self.task_name, False)
            return
        except Exception as exc:  # pragma: no cover - defensive worker boundary
            self.log_message.emit(f"[{self.task_name}] Unexpected indexer failure: {exc}")
            self.finished.emit(self.task_name, False)
            return

        if self.cancelled:
            self.log_message.emit(f"[{self.task_name}] Query cancelled.")
            self.finished.emit(self.task_name, False)
            return

        critical_alerts = [alert for alert in alerts if int(alert.get("severity", 0) or 0) >= 12]
        self.log_message.emit(
            f"[{self.task_name}] Cluster status={cluster_health.get('status', 'unknown')} | "
            f"nodes={cluster_health.get('number_of_nodes', '?')} | alerts={len(alerts)}"
        )
        if critical_alerts:
            self.log_message.emit(f"[{self.task_name}] High-severity alerts in current batch: {len(critical_alerts)}")

        self.alerts_ready.emit(
            {
                "cluster_health": cluster_health,
                "alerts": alerts,
                "critical_count": len(critical_alerts),
            }
        )
        self.finished.emit(self.task_name, True)


class SIEMCommanderWindow(QMainWindow):
    DASHBOARD_LINKS = [
        DashboardLink("Wazuh", "Security visibility and alert triage", "https://{host}"),
        DashboardLink("Kibana", "Elastic dashboards and log search", "https://{host}:5601"),
        DashboardLink("Grafana", "Infrastructure and telemetry panels", "https://{host}:3000"),
        DashboardLink("Proxmox", "Hypervisor management console", "https://{host}:8006"),
    ]

    def __init__(
        self,
        settings: QSettings | None = None,
        credential_store: CredentialStore | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle("SIEM-Commander")
        self.resize(1360, 860)

        self._threads: list[QThread] = []
        self._workers: list[QObject] = []
        self._worker_task_keys: dict[QObject, str] = {}
        self._worker_controls: dict[QObject, tuple[QWidget, ...]] = {}
        self._active_task_keys: set[str] = set()
        self._closing = False
        self._loading_settings = False
        self.active_jobs = 0
        self.default_mock_mode = False
        self.settings = settings or QSettings(SETTINGS_ORGANIZATION, SETTINGS_APPLICATION)
        self.credential_store = credential_store
        self._credential_store_error = ""
        if self.credential_store is None:
            try:
                self.credential_store = CredentialStore()
            except RuntimeError as exc:
                self._credential_store_error = str(exc)

        self._build_ui()
        if self.credential_store is None:
            self.remember_credentials_checkbox.setEnabled(False)
            self.remember_credentials_checkbox.setToolTip(self._credential_store_error)
        self._load_settings()
        self._apply_styles()
        self._sync_status_cards()
        self.append_log("SIEM-Commander initialized.")
        if self._credential_store_error:
            self.append_log(f"[Credentials] {self._credential_store_error}")

    def _build_ui(self) -> None:
        central = QWidget()
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(20, 20, 20, 20)
        root_layout.setSpacing(16)

        header = self._build_header()
        body = QHBoxLayout()
        body.setSpacing(16)

        sidebar = self._build_sidebar()
        content = self._build_content()

        body.addWidget(sidebar, 0)
        body.addWidget(content, 1)

        console_panel = self._build_console()

        root_layout.addWidget(header)
        root_layout.addLayout(body, 1)
        root_layout.addWidget(console_panel, 0)

        self.setCentralWidget(central)

    def _build_header(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("headerPanel")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(12)

        title_column = QVBoxLayout()
        title_column.setSpacing(4)

        title = QLabel("SIEM-Commander")
        title.setObjectName("titleLabel")
        subtitle = QLabel("Wazuh analyst console with live telemetry, dashboard launchers, and lab drill helpers.")
        subtitle.setObjectName("subtitleLabel")

        title_column.addWidget(title)
        title_column.addWidget(subtitle)

        self.mode_badge = QLabel("DEMO MODE" if self.default_mock_mode else "LIVE CONNECTIONS")
        self.mode_badge.setObjectName("modeBadge")
        self.mode_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.mode_badge.setMinimumWidth(160)

        layout.addLayout(title_column, 1)
        layout.addWidget(self.mode_badge, 0)
        return frame

    def _build_sidebar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("sidebar")
        frame.setFixedWidth(240)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 20, 18, 20)
        layout.setSpacing(10)

        section = QLabel("Navigation")
        section.setObjectName("sectionLabel")
        layout.addWidget(section)

        self.nav_buttons: list[QPushButton] = []
        for index, label in enumerate(["Lab Status", "Security Operations", "Dashboard Links"]):
            button = QPushButton(label)
            button.setCheckable(True)
            button.clicked.connect(partial(self._switch_page, index))
            layout.addWidget(button)
            self.nav_buttons.append(button)

        layout.addStretch()
        self.nav_buttons[0].setChecked(True)
        return frame

    def _build_content(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._scrollable_page(self._build_lab_status_page()))
        self.stack.addWidget(self._scrollable_page(self._build_attack_page()))
        self.stack.addWidget(self._scrollable_page(self._build_dashboard_page()))

        layout.addWidget(self.stack)
        return container

    def _scrollable_page(self, page: QWidget) -> QScrollArea:
        scroll_area = QScrollArea()
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setWidget(page)
        return scroll_area

    def _build_lab_status_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        stats_grid = QGridLayout()
        stats_grid.setHorizontalSpacing(12)
        stats_grid.setVerticalSpacing(12)

        self.platform_card = StatCard("Platform", platform.system())
        self.mode_card = StatCard("Connection Mode", "Demo" if self.default_mock_mode else "Live")
        self.active_tasks_card = StatCard("Active Jobs", "0")
        self.wazuh_card = StatCard("Manager Service", "No checks run yet")
        self.indexer_card = StatCard("Indexer Health", "No data")
        self.agent_summary_card = StatCard("Agent Summary", "No data")
        self.api_version_card = StatCard("Wazuh API", "Not connected")

        cards = [
            self.platform_card,
            self.mode_card,
            self.active_tasks_card,
            self.wazuh_card,
            self.indexer_card,
            self.agent_summary_card,
            self.api_version_card,
        ]
        for index, card in enumerate(cards):
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
            stats_grid.addWidget(card, index // 3, index % 3)

        layout.addLayout(stats_grid)
        layout.addWidget(self._build_ssh_panel())
        layout.addWidget(self._build_live_data_panel())
        layout.addStretch()
        return page

    def _build_ssh_panel(self) -> QGroupBox:
        panel = QGroupBox("Manager Service Check")
        panel.setObjectName("panelGroup")
        layout = QGridLayout(panel)
        layout.setContentsMargins(18, 22, 18, 18)
        layout.setHorizontalSpacing(14)
        layout.setVerticalSpacing(12)

        self.vm_ip_input = QLineEdit("192.168.56.10")
        self.vm_ip_input.setPlaceholderText("192.168.56.10")
        self.vm_ip_input.textChanged.connect(self._sync_dashboard_host)

        self.username_input = QLineEdit("socadmin")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Optional when using SSH keys or an SSH agent")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssh_key_file_input = QLineEdit()
        self.ssh_key_file_input.setPlaceholderText("Optional private key path")
        ssh_key_browse_button = QPushButton("Browse")
        ssh_key_browse_button.clicked.connect(self._choose_ssh_key_file)

        self.mock_mode_checkbox = QCheckBox("Enable Mock Mode")
        self.mock_mode_checkbox.setChecked(self.default_mock_mode)
        self.mock_mode_checkbox.toggled.connect(self._handle_mock_mode_toggled)
        self.allow_unknown_ssh_host_checkbox = QCheckBox(
            "Allow unknown SSH host keys (insecure; use only for initial lab setup)"
        )
        self.allow_unknown_ssh_host_checkbox.setChecked(False)

        self.check_siem_button = QPushButton("Check SIEM Status")
        self.check_siem_button.clicked.connect(self.start_ssh_status_check)

        note = QLabel(
            "This verifies the `wazuh-manager` service over SSH. Demo mode replays deterministic output instead of "
            "opening a real connection."
        )
        note.setObjectName("supportLabel")
        note.setWordWrap(True)

        layout.addWidget(QLabel("VM IP"), 0, 0)
        layout.addWidget(self.vm_ip_input, 0, 1)
        layout.addWidget(QLabel("Username"), 1, 0)
        layout.addWidget(self.username_input, 1, 1)
        layout.addWidget(QLabel("Password"), 2, 0)
        layout.addWidget(self.password_input, 2, 1)
        layout.addWidget(QLabel("SSH Key"), 3, 0)
        key_row = QHBoxLayout()
        key_row.addWidget(self.ssh_key_file_input, 1)
        key_row.addWidget(ssh_key_browse_button)
        layout.addLayout(key_row, 3, 1)
        layout.addWidget(self.mock_mode_checkbox, 4, 0, 1, 2)
        layout.addWidget(self.allow_unknown_ssh_host_checkbox, 5, 0, 1, 2)
        layout.addWidget(self.check_siem_button, 6, 0, 1, 2)
        layout.addWidget(note, 7, 0, 1, 2)

        return panel

    def _build_live_data_panel(self) -> QGroupBox:
        panel = QGroupBox("Live Wazuh Data Sources")
        panel.setObjectName("panelGroup")
        layout = QGridLayout(panel)
        layout.setContentsMargins(18, 22, 18, 18)
        layout.setHorizontalSpacing(14)
        layout.setVerticalSpacing(12)

        self.wazuh_api_url_input = QLineEdit(f"https://{self.vm_ip_input.text().strip()}:55000")
        self.wazuh_api_url_input.setPlaceholderText("https://<manager-host>:55000")
        self.wazuh_api_user_input = QLineEdit()
        self.wazuh_api_user_input.setPlaceholderText("Wazuh API username")
        self.wazuh_api_password_input = QLineEdit()
        self.wazuh_api_password_input.setPlaceholderText("Wazuh API password")
        self.wazuh_api_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.indexer_url_input = QLineEdit(f"https://{self.vm_ip_input.text().strip()}:9200")
        self.indexer_url_input.setPlaceholderText("https://<indexer-host>:9200")
        self.indexer_user_input = QLineEdit()
        self.indexer_user_input.setPlaceholderText("Indexer username")
        self.indexer_password_input = QLineEdit()
        self.indexer_password_input.setPlaceholderText("Indexer password")
        self.indexer_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.allow_self_signed_checkbox = QCheckBox("Allow self-signed TLS certificates")
        self.allow_self_signed_checkbox.setChecked(False)
        self.ca_bundle_input = QLineEdit()
        self.ca_bundle_input.setPlaceholderText("Optional CA certificate bundle")
        ca_browse_button = QPushButton("Browse")
        ca_browse_button.clicked.connect(self._choose_ca_bundle)

        self.alert_index_input = QLineEdit(DEFAULT_ALERT_INDEX)
        self.alert_index_input.setPlaceholderText(DEFAULT_ALERT_INDEX)
        self.alert_limit_input = QSpinBox()
        self.alert_limit_input.setRange(1, 200)
        self.alert_limit_input.setValue(50)

        self.remember_credentials_checkbox = QCheckBox("Remember credentials securely in the OS keyring")
        self.remember_credentials_checkbox.setChecked(False)
        self.remember_credentials_checkbox.toggled.connect(self._handle_remember_credentials_toggled)

        self.refresh_overview_button = QPushButton("Refresh Wazuh Overview")
        self.refresh_overview_button.clicked.connect(self.start_live_overview_refresh)
        self.load_alerts_button = QPushButton("Load Recent Alerts")
        self.load_alerts_button.clicked.connect(self.start_recent_alerts_refresh)

        note = QLabel(
            "Use the Wazuh server API for manager and agent health, and the Wazuh indexer for recent alerts. "
            "These live connections are what make the project portfolio-ready."
        )
        note.setObjectName("supportLabel")
        note.setWordWrap(True)

        layout.addWidget(QLabel("Wazuh API URL"), 0, 0)
        layout.addWidget(self.wazuh_api_url_input, 0, 1)
        layout.addWidget(QLabel("API User"), 1, 0)
        layout.addWidget(self.wazuh_api_user_input, 1, 1)
        layout.addWidget(QLabel("API Password"), 2, 0)
        layout.addWidget(self.wazuh_api_password_input, 2, 1)
        layout.addWidget(QLabel("Indexer URL"), 0, 2)
        layout.addWidget(self.indexer_url_input, 0, 3)
        layout.addWidget(QLabel("Indexer User"), 1, 2)
        layout.addWidget(self.indexer_user_input, 1, 3)
        layout.addWidget(QLabel("Indexer Password"), 2, 2)
        layout.addWidget(self.indexer_password_input, 2, 3)
        layout.addWidget(QLabel("Alert Index"), 3, 0)
        layout.addWidget(self.alert_index_input, 3, 1)
        layout.addWidget(QLabel("Alert Limit"), 3, 2)
        layout.addWidget(self.alert_limit_input, 3, 3)
        layout.addWidget(QLabel("CA Bundle"), 4, 0)
        ca_row = QHBoxLayout()
        ca_row.addWidget(self.ca_bundle_input, 1)
        ca_row.addWidget(ca_browse_button)
        layout.addLayout(ca_row, 4, 1, 1, 3)
        layout.addWidget(self.allow_self_signed_checkbox, 5, 0, 1, 2)
        layout.addWidget(self.remember_credentials_checkbox, 5, 2, 1, 2)
        layout.addWidget(self.refresh_overview_button, 6, 2)
        layout.addWidget(self.load_alerts_button, 6, 3)
        layout.addWidget(note, 7, 0, 1, 4)

        return panel

    def _build_attack_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        layout.addWidget(self._build_alerts_panel())
        layout.addWidget(self._build_lab_drill_panel())
        layout.addStretch()
        return page

    def _build_alerts_panel(self) -> QGroupBox:
        panel = QGroupBox("Recent Alerts")
        panel.setObjectName("panelGroup")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(18, 22, 18, 18)
        panel_layout.setSpacing(12)

        note = QLabel(
            "This view queries the Wazuh indexer for the newest alerts. Configure the live credentials on the Lab "
            "Status page, then refresh here or from the connection panel."
        )
        note.setObjectName("supportLabel")
        note.setWordWrap(True)

        action_row = QHBoxLayout()
        action_row.setSpacing(12)
        self.alert_status_label = QLabel("No live alerts loaded yet.")
        self.alert_status_label.setObjectName("supportLabel")
        self.refresh_alerts_button = QPushButton("Refresh Alerts")
        self.refresh_alerts_button.clicked.connect(self.start_recent_alerts_refresh)
        self.export_alerts_button = QPushButton("Export CSV")
        self.export_alerts_button.setEnabled(False)
        self.export_alerts_button.clicked.connect(self.export_alerts_csv)
        action_row.addWidget(self.alert_status_label, 1)
        action_row.addWidget(self.export_alerts_button, 0)
        action_row.addWidget(self.refresh_alerts_button, 0)

        self.alerts_table = QTableWidget(0, 7)
        self.alerts_table.setObjectName("alertsTable")
        self.alerts_table.setHorizontalHeaderLabels(
            ["Timestamp", "Severity", "Rule", "Agent", "Manager", "Source IP", "Location"]
        )
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alerts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.alerts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        panel_layout.addWidget(note)
        panel_layout.addLayout(action_row)
        panel_layout.addWidget(self.alerts_table)
        return panel

    def _build_lab_drill_panel(self) -> QGroupBox:
        panel = QGroupBox("Lab Drill Simulations")
        panel.setObjectName("panelGroup")
        panel_layout = QGridLayout(panel)
        panel_layout.setContentsMargins(18, 22, 18, 18)
        panel_layout.setHorizontalSpacing(14)
        panel_layout.setVerticalSpacing(14)

        self.target_ip_input = QLineEdit("192.168.56.20")
        self.target_ip_input.setPlaceholderText("Enter target IP")

        note = QLabel(
            "These remain optional SOC drills for demos and detection validation. They do not launch real offensive "
            "activity against a target."
        )
        note.setObjectName("supportLabel")
        note.setWordWrap(True)

        self.nmap_button = QPushButton("Nmap Stealth Scan")
        self.nmap_button.clicked.connect(partial(self.start_attack_task, "nmap", "Nmap Stealth Scan"))

        self.ssh_drill_button = QPushButton("SSH Brute Force")
        self.ssh_drill_button.clicked.connect(partial(self.start_attack_task, "ssh_bruteforce", "SSH Brute Force"))

        self.icmp_button = QPushButton("ICMP Flood")
        self.icmp_button.clicked.connect(partial(self.start_attack_task, "icmp_flood", "ICMP Flood"))

        panel_layout.addWidget(QLabel("Target IP"), 0, 0)
        panel_layout.addWidget(self.target_ip_input, 0, 1, 1, 2)
        panel_layout.addWidget(self.nmap_button, 1, 0)
        panel_layout.addWidget(self.ssh_drill_button, 1, 1)
        panel_layout.addWidget(self.icmp_button, 1, 2)
        panel_layout.addWidget(note, 2, 0, 1, 3)

        return panel

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        top_panel = QGroupBox("Dashboard Links")
        top_panel.setObjectName("panelGroup")
        top_layout = QVBoxLayout(top_panel)
        top_layout.setContentsMargins(18, 22, 18, 18)
        top_layout.setSpacing(14)

        host_row = QHBoxLayout()
        host_row.setSpacing(12)
        host_row.addWidget(QLabel("Dashboard Host"))
        self.dashboard_host_input = QLineEdit("192.168.56.10")
        self.dashboard_host_input.setPlaceholderText("Use VM IP or hostname")
        host_row.addWidget(self.dashboard_host_input, 1)

        cards = QGridLayout()
        cards.setHorizontalSpacing(14)
        cards.setVerticalSpacing(14)

        for index, link in enumerate(self.DASHBOARD_LINKS):
            row = index // 2
            column = index % 2
            cards.addWidget(self._build_dashboard_card(link), row, column)

        top_layout.addLayout(host_row)
        top_layout.addLayout(cards)
        layout.addWidget(top_panel)
        layout.addStretch()
        return page

    def _build_dashboard_card(self, link: DashboardLink) -> QFrame:
        card = QFrame()
        card.setObjectName("dashboardCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)

        title = QLabel(link.title)
        title.setObjectName("cardTitle")
        description = QLabel(link.description)
        description.setObjectName("supportLabel")
        description.setWordWrap(True)

        button = QPushButton(f"Open {link.title}")
        button.clicked.connect(partial(self.open_dashboard_link, link))

        layout.addWidget(title)
        layout.addWidget(description)
        layout.addStretch()
        layout.addWidget(button)
        return card

    def _build_console(self) -> QGroupBox:
        panel = QGroupBox("Live Console")
        panel.setObjectName("panelGroup")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(18, 22, 18, 18)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(1200)
        self.console.setMinimumHeight(130)
        self.console.setMaximumHeight(220)
        console_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        console_font.setPointSize(11)
        self.console.setFont(console_font)
        layout.addWidget(self.console)
        return panel

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            f"""
            QWidget {{
                background-color: {BACKGROUND};
                color: {TEXT};
                font-family: "Avenir Next", "Futura", "Segoe UI", sans-serif;
                font-size: 14px;
            }}
            QMainWindow {{
                background-color: {BACKGROUND};
            }}
            QLabel {{
                background-color: transparent;
            }}
            QLabel#titleLabel {{
                font-size: 30px;
                font-weight: 700;
                letter-spacing: 1px;
                color: {TEXT};
            }}
            QLabel#subtitleLabel {{
                color: {MUTED};
                font-size: 14px;
            }}
            QLabel#sectionLabel {{
                color: {MUTED};
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: 1px;
            }}
            QLabel#cardTitle {{
                color: {MUTED};
                font-size: 13px;
                font-weight: 600;
            }}
            QLabel#cardValue {{
                color: {TEXT};
                font-size: 20px;
                font-weight: 700;
            }}
            QLabel#supportLabel {{
                color: {MUTED};
                font-size: 13px;
                line-height: 1.4;
            }}
            QLabel#modeBadge {{
                background: rgba(23, 114, 69, 0.10);
                border: 1px solid rgba(23, 114, 69, 0.35);
                border-radius: 16px;
                color: {ACCENT_ALT};
                font-size: 12px;
                font-weight: 700;
                padding: 8px 14px;
            }}
            QFrame#headerPanel, QFrame#sidebar, QGroupBox#panelGroup, QFrame#statCard, QFrame#dashboardCard {{
                background-color: {SURFACE};
                border: 1px solid #dce5de;
                border-radius: 18px;
            }}
            QFrame#statCard {{
                min-height: 112px;
            }}
            QGroupBox#panelGroup {{
                margin-top: 8px;
                padding-top: 8px;
                font-weight: 700;
                color: {TEXT};
            }}
            QGroupBox#panelGroup::title {{
                subcontrol-origin: margin;
                left: 14px;
                background-color: {SURFACE};
                padding: 0 8px;
            }}
            QPushButton {{
                background-color: #ffffff;
                border: 1px solid rgba(23, 114, 69, 0.45);
                border-radius: 14px;
                color: {ACCENT_ALT};
                font-weight: 600;
                padding: 12px 16px;
            }}
            QPushButton:hover {{
                background-color: rgba(23, 114, 69, 0.08);
                border-color: {ACCENT};
            }}
            QPushButton:pressed {{
                background-color: rgba(23, 114, 69, 0.16);
            }}
            QPushButton:checked {{
                background-color: {ACCENT};
                border-color: {ACCENT};
                color: #ffffff;
            }}
            QLineEdit, QPlainTextEdit, QTableWidget, QSpinBox {{
                background-color: {PANEL};
                border: 1px solid #cfd9d1;
                border-radius: 12px;
                padding: 10px 12px;
                color: {TEXT};
                selection-background-color: {ACCENT};
                selection-color: #ffffff;
            }}
            QLineEdit:focus, QPlainTextEdit:focus, QTableWidget:focus, QSpinBox:focus {{
                border-color: {ACCENT};
            }}
            QHeaderView::section {{
                background-color: {SURFACE};
                color: {MUTED};
                border: none;
                border-bottom: 1px solid #dce5de;
                padding: 10px;
                font-weight: 600;
            }}
            QTableWidget {{
                alternate-background-color: #eef4ef;
                gridline-color: #e3eae4;
            }}
            QCheckBox {{
                background-color: transparent;
                color: {TEXT};
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 6px;
                border: 1px solid rgba(23, 114, 69, 0.55);
                background: #ffffff;
            }}
            QCheckBox::indicator:checked {{
                background: {ACCENT};
                border-color: {ACCENT};
            }}
            """
        )

    def _switch_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for button_index, button in enumerate(self.nav_buttons):
            button.setChecked(button_index == index)

    def _handle_mock_mode_toggled(self, enabled: bool) -> None:
        self.mode_badge.setText("DEMO MODE" if enabled else "LIVE CONNECTIONS")
        self.mode_card.set_value("Demo" if enabled else "Live")
        state = "enabled" if enabled else "disabled"
        self.append_log(f"Mock mode {state}.")

    def _sync_status_cards(self) -> None:
        self.platform_card.set_value(platform.system())
        self.mode_card.set_value("Demo" if self.mock_mode_checkbox.isChecked() else "Live")
        self.active_tasks_card.set_value(str(self.active_jobs))

    def _sync_dashboard_host(self, value: str) -> None:
        if not self.dashboard_host_input.text().strip():
            self.dashboard_host_input.setText(value)

    def _choose_ssh_key_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Select SSH Private Key")
        if filename:
            self.ssh_key_file_input.setText(filename)

    def _choose_ca_bundle(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select CA Certificate Bundle",
            "",
            "Certificates (*.pem *.crt *.cer);;All Files (*)",
        )
        if filename:
            self.ca_bundle_input.setText(filename)

    def _load_settings(self) -> None:
        self._loading_settings = True
        try:
            self.vm_ip_input.setText(str(self.settings.value("connections/manager_host", self.vm_ip_input.text())))
            self.username_input.setText(
                str(self.settings.value("connections/ssh_username", self.username_input.text()))
            )
            self.ssh_key_file_input.setText(str(self.settings.value("connections/ssh_key_file", "")))
            self.mock_mode_checkbox.setChecked(
                self.settings.value("connections/mock_mode", self.default_mock_mode, type=bool)
            )
            self.allow_unknown_ssh_host_checkbox.setChecked(
                self.settings.value("connections/allow_unknown_ssh_host", False, type=bool)
            )
            self.wazuh_api_url_input.setText(
                str(self.settings.value("connections/api_url", self.wazuh_api_url_input.text()))
            )
            self.wazuh_api_user_input.setText(str(self.settings.value("connections/api_username", "")))
            self.indexer_url_input.setText(
                str(self.settings.value("connections/indexer_url", self.indexer_url_input.text()))
            )
            self.indexer_user_input.setText(str(self.settings.value("connections/indexer_username", "")))
            self.ca_bundle_input.setText(str(self.settings.value("connections/ca_bundle", "")))
            self.allow_self_signed_checkbox.setChecked(
                self.settings.value("connections/allow_self_signed", False, type=bool)
            )
            self.alert_index_input.setText(str(self.settings.value("alerts/index_pattern", DEFAULT_ALERT_INDEX)))
            self.alert_limit_input.setValue(self.settings.value("alerts/limit", 50, type=int))
            self.target_ip_input.setText(str(self.settings.value("drills/target", self.target_ip_input.text())))
            self.dashboard_host_input.setText(str(self.settings.value("dashboards/host", self.vm_ip_input.text())))
            remember_credentials = self.settings.value(
                "credentials/remember",
                False,
                type=bool,
            )
            self.remember_credentials_checkbox.setChecked(
                bool(remember_credentials and self.credential_store is not None)
            )
        finally:
            self._loading_settings = False

        if self.remember_credentials_checkbox.isChecked():
            self._load_credentials()

    def _save_settings(self) -> None:
        self.settings.setValue("connections/manager_host", self.vm_ip_input.text().strip())
        self.settings.setValue("connections/ssh_username", self.username_input.text().strip())
        self.settings.setValue("connections/ssh_key_file", self.ssh_key_file_input.text().strip())
        self.settings.setValue("connections/mock_mode", self.mock_mode_checkbox.isChecked())
        self.settings.setValue(
            "connections/allow_unknown_ssh_host",
            self.allow_unknown_ssh_host_checkbox.isChecked(),
        )
        self.settings.setValue("connections/api_url", self.current_wazuh_api_url())
        self.settings.setValue("connections/api_username", self.wazuh_api_user_input.text().strip())
        self.settings.setValue("connections/indexer_url", self.current_indexer_url())
        self.settings.setValue("connections/indexer_username", self.indexer_user_input.text().strip())
        self.settings.setValue("connections/ca_bundle", self.ca_bundle_input.text().strip())
        self.settings.setValue(
            "connections/allow_self_signed",
            self.allow_self_signed_checkbox.isChecked(),
        )
        self.settings.setValue("alerts/index_pattern", self.alert_index_input.text().strip())
        self.settings.setValue("alerts/limit", self.alert_limit_input.value())
        self.settings.setValue("drills/target", self.target_ip_input.text().strip())
        self.settings.setValue("dashboards/host", self.dashboard_host_input.text().strip())
        self.settings.setValue(
            "credentials/remember",
            self.remember_credentials_checkbox.isChecked(),
        )
        self.settings.sync()
        if self.remember_credentials_checkbox.isChecked():
            self._save_credentials()

    def _load_credentials(self) -> None:
        if self.credential_store is None:
            return
        fields = {
            "ssh": (self.username_input, self.password_input),
            "wazuh-api": (self.wazuh_api_user_input, self.wazuh_api_password_input),
            "wazuh-indexer": (self.indexer_user_input, self.indexer_password_input),
        }
        try:
            for name, (username_input, password_input) in fields.items():
                credential = self.credential_store.load(name)
                if credential is not None:
                    username_input.setText(credential.username)
                    password_input.setText(credential.password)
        except RuntimeError as exc:
            self.append_log(f"[Credentials] {exc}")

    def _save_credentials(self) -> None:
        if self.credential_store is None:
            return
        credentials = {
            "ssh": (self.username_input.text().strip(), self.password_input.text()),
            "wazuh-api": (
                self.wazuh_api_user_input.text().strip(),
                self.wazuh_api_password_input.text(),
            ),
            "wazuh-indexer": (
                self.indexer_user_input.text().strip(),
                self.indexer_password_input.text(),
            ),
        }
        try:
            for name, (username, password) in credentials.items():
                if username and password:
                    self.credential_store.save(name, username, password)
        except RuntimeError as exc:
            self.append_log(f"[Credentials] {exc}")

    def _handle_remember_credentials_toggled(self, enabled: bool) -> None:
        if self._loading_settings:
            return
        if enabled:
            if self.credential_store is None:
                self.remember_credentials_checkbox.setChecked(False)
                self.append_log("[Credentials] No secure OS keyring backend is available.")
                return
            self._save_credentials()
            self.append_log("[Credentials] Secure credential storage enabled.")
            return

        if self.credential_store is not None:
            try:
                for name in ("ssh", "wazuh-api", "wazuh-indexer"):
                    self.credential_store.delete(name)
            except RuntimeError as exc:
                self.append_log(f"[Credentials] {exc}")
        self.append_log("[Credentials] Stored credentials removed from the OS keyring.")

    def current_dashboard_host(self) -> str:
        return self.dashboard_host_input.text().strip() or self.vm_ip_input.text().strip() or "127.0.0.1"

    def current_wazuh_api_url(self) -> str:
        configured = ensure_https_url(self.wazuh_api_url_input.text())
        if configured:
            return configured
        host = self.vm_ip_input.text().strip()
        return f"https://{host}:55000" if host else ""

    def current_indexer_url(self) -> str:
        configured = ensure_https_url(self.indexer_url_input.text())
        if configured:
            return configured
        host = self.vm_ip_input.text().strip()
        return f"https://{host}:9200" if host else ""

    def build_wazuh_api_settings(self) -> ConnectionSettings | None:
        base_url = self.current_wazuh_api_url()
        username = self.wazuh_api_user_input.text().strip()
        password = self.wazuh_api_password_input.text()
        if not base_url or not username or not password:
            self.append_log("[Refresh Wazuh Overview] API URL, username, and password are required.")
            return None
        validation_error = validate_service_url(base_url)
        if validation_error:
            self.append_log(f"[Refresh Wazuh Overview] {validation_error}")
            return None
        ca_bundle = self.ca_bundle_input.text().strip()
        if ca_bundle and not Path(ca_bundle).expanduser().is_file():
            self.append_log("[Refresh Wazuh Overview] The selected CA certificate bundle does not exist.")
            return None
        if base_url.startswith("http://"):
            self.append_log("[Refresh Wazuh Overview] Warning: credentials will be sent over unencrypted HTTP.")
        return ConnectionSettings(
            base_url=base_url,
            username=username,
            password=password,
            verify_tls=not self.allow_self_signed_checkbox.isChecked(),
            ca_bundle=ca_bundle,
        )

    def build_indexer_settings(self) -> ConnectionSettings | None:
        base_url = self.current_indexer_url()
        username = self.indexer_user_input.text().strip()
        password = self.indexer_password_input.text()
        if not base_url or not username or not password:
            self.append_log("[Load Recent Alerts] Indexer URL, username, and password are required.")
            return None
        validation_error = validate_service_url(base_url)
        if validation_error:
            self.append_log(f"[Load Recent Alerts] {validation_error}")
            return None
        ca_bundle = self.ca_bundle_input.text().strip()
        if ca_bundle and not Path(ca_bundle).expanduser().is_file():
            self.append_log("[Load Recent Alerts] The selected CA certificate bundle does not exist.")
            return None
        if base_url.startswith("http://"):
            self.append_log("[Load Recent Alerts] Warning: credentials will be sent over unencrypted HTTP.")
        return ConnectionSettings(
            base_url=base_url,
            username=username,
            password=password,
            verify_tls=not self.allow_self_signed_checkbox.isChecked(),
            ca_bundle=ca_bundle,
        )

    def append_log(self, message: str) -> None:
        timestamp = QTime.currentTime().toString("HH:mm:ss")
        self.console.appendPlainText(f"{timestamp} | {message}")
        cursor = self.console.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.console.setTextCursor(cursor)

    def _start_worker(
        self,
        worker: QObject,
        finish_callback,
        *,
        task_key: str,
        controls: tuple[QWidget, ...] = (),
    ) -> bool:
        if task_key in self._active_task_keys:
            self.append_log(f"[Jobs] {task_key} is already running.")
            return False

        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        if hasattr(worker, "log_message"):
            worker.log_message.connect(self.append_log)
        worker.finished.connect(partial(finish_callback, worker))
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(partial(self._finalize_worker, thread, worker))
        thread.finished.connect(thread.deleteLater)

        self._threads.append(thread)
        self._workers.append(worker)
        self._worker_task_keys[worker] = task_key
        self._worker_controls[worker] = controls
        self._active_task_keys.add(task_key)
        for control in controls:
            control.setEnabled(False)
        self.active_jobs += 1
        self._sync_status_cards()
        thread.start()
        return True

    def _finalize_worker(self, thread: QThread, worker: QObject) -> None:
        if worker in self._workers:
            self._workers.remove(worker)
        if thread in self._threads:
            self._threads.remove(thread)
        task_key = self._worker_task_keys.pop(worker, "")
        if task_key:
            self._active_task_keys.discard(task_key)
        for control in self._worker_controls.pop(worker, ()):
            control.setEnabled(True)
        self.active_jobs = max(0, self.active_jobs - 1)
        self._sync_status_cards()
        if self._closing and not self._threads:
            QTimer.singleShot(0, self.close)

    def start_attack_task(self, action: str, label: str) -> None:
        target = self.target_ip_input.text().strip()
        validation_error = validate_host(target)
        if validation_error:
            self.append_log(f"[Lab Drill] {validation_error}")
            return

        self.append_log(f"[Lab Drill] Scheduling {label} for {target}")
        worker = ProcessWorker(label, build_attack_command(action, target))
        controls = (self.nmap_button, self.ssh_drill_button, self.icmp_button)
        self._start_worker(
            worker,
            self._on_process_finished,
            task_key="lab-drill",
            controls=controls,
        )

    def start_ssh_status_check(self) -> None:
        host = self.vm_ip_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        mock_mode = self.mock_mode_checkbox.isChecked()
        key_file = self.ssh_key_file_input.text().strip()

        host_error = validate_host(host)
        if host_error:
            self.append_log(f"[Check SIEM Status] {host_error}")
            return
        if not username:
            self.append_log("[Check SIEM Status] SSH username is required.")
            return
        if key_file and not Path(key_file).expanduser().is_file():
            self.append_log("[Check SIEM Status] The selected SSH private key does not exist.")
            return

        self.append_log(f"[Check SIEM Status] Scheduling status check for {host}")
        worker = SSHStatusWorker(
            host,
            username,
            password,
            mock_mode,
            key_file=str(Path(key_file).expanduser()) if key_file else "",
            allow_unknown_host=self.allow_unknown_ssh_host_checkbox.isChecked(),
        )
        worker.status_ready.connect(self.wazuh_card.set_value)
        self._save_settings()
        self._start_worker(
            worker,
            self._on_process_finished,
            task_key="ssh-status",
            controls=(self.check_siem_button,),
        )

    def start_live_overview_refresh(self) -> None:
        settings = self.build_wazuh_api_settings()
        if settings is None:
            return

        self.append_log(f"[Refresh Wazuh Overview] Scheduling refresh for {settings.base_url}")
        worker = WazuhOverviewWorker(settings)
        worker.overview_ready.connect(self._apply_wazuh_overview)
        self._save_settings()
        self._start_worker(
            worker,
            self._on_process_finished,
            task_key="wazuh-overview",
            controls=(self.refresh_overview_button,),
        )

    def start_recent_alerts_refresh(self) -> None:
        settings = self.build_indexer_settings()
        if settings is None:
            return
        index_pattern = self.alert_index_input.text().strip()
        if not index_pattern:
            self.append_log("[Load Recent Alerts] Alert index pattern is required.")
            return

        self.append_log(f"[Load Recent Alerts] Scheduling query for {settings.base_url}")
        worker = RecentAlertsWorker(
            settings,
            limit=self.alert_limit_input.value(),
            index_pattern=index_pattern,
        )
        worker.alerts_ready.connect(self._apply_recent_alerts)
        self._save_settings()
        self._start_worker(
            worker,
            self._on_process_finished,
            task_key="recent-alerts",
            controls=(self.load_alerts_button, self.refresh_alerts_button),
        )

    def _apply_wazuh_overview(self, overview: object) -> None:
        if not isinstance(overview, dict):
            return

        api_version = normalize_text(overview.get("api_version", "Unknown"))
        manager_daemons = overview.get("manager_daemons", {})
        agent_connection = overview.get("agent_connection", {})
        agents = overview.get("agents", [])

        self.api_version_card.set_value(api_version)
        self.agent_summary_card.set_value(format_count_map(agent_connection))
        self.wazuh_card.set_value(summarize_manager_daemons(manager_daemons))

        if agents:
            lead_agent = agents[0]
            agent_name = normalize_text(lead_agent.get("name", "unknown-agent"))
            agent_state = normalize_text(lead_agent.get("status", "unknown"))
            self.append_log(f"[Refresh Wazuh Overview] Lead agent snapshot: {agent_name} status={agent_state}")

    def _apply_recent_alerts(self, payload: object) -> None:
        if not isinstance(payload, dict):
            return

        cluster_health = payload.get("cluster_health", {})
        alerts = payload.get("alerts", [])
        critical_count = int(payload.get("critical_count", 0))

        if isinstance(cluster_health, dict):
            status = normalize_text(cluster_health.get("status", "unknown"))
            nodes = normalize_text(cluster_health.get("number_of_nodes", "?"))
            self.indexer_card.set_value(f"{status} | nodes: {nodes}")
            self.alert_status_label.setText(
                f"Cluster {status} | Loaded {len(alerts)} alerts | High severity: {critical_count}"
            )

        self.alerts_table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                continue
            rule_label = normalize_text(alert.get("rule_description", "Unknown rule"))
            rule_id = normalize_text(alert.get("rule_id", ""))
            if rule_id:
                rule_label = f"{rule_id} - {rule_label}"
            self.alerts_table.setItem(row, 0, table_item(alert.get("timestamp", "")))
            self.alerts_table.setItem(row, 1, table_item(alert.get("severity", "")))
            self.alerts_table.setItem(row, 2, table_item(rule_label))
            self.alerts_table.setItem(row, 3, table_item(alert.get("agent_name", "")))
            self.alerts_table.setItem(row, 4, table_item(alert.get("manager_name", "")))
            self.alerts_table.setItem(row, 5, table_item(alert.get("source_ip", "")))
            self.alerts_table.setItem(row, 6, table_item(alert.get("location", "")))
        self.export_alerts_button.setEnabled(bool(alerts))

    def export_alerts_csv(self) -> None:
        if self.alerts_table.rowCount() == 0:
            self.append_log("[Alerts Export] There are no alerts to export.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Alerts",
            "siem-commander-alerts.csv",
            "CSV Files (*.csv)",
        )
        if not filename:
            return
        if not filename.lower().endswith(".csv"):
            filename = f"{filename}.csv"

        headers = [
            self.alerts_table.horizontalHeaderItem(column).text() for column in range(self.alerts_table.columnCount())
        ]
        try:
            with open(filename, "w", newline="", encoding="utf-8") as output_file:
                writer = csv.writer(output_file)
                writer.writerow(headers)
                for row in range(self.alerts_table.rowCount()):
                    writer.writerow(
                        self.alerts_table.item(row, column).text()
                        if self.alerts_table.item(row, column) is not None
                        else ""
                        for column in range(self.alerts_table.columnCount())
                    )
        except OSError as exc:
            self.append_log(f"[Alerts Export] Unable to write {filename}: {exc}")
            return

        self.append_log(f"[Alerts Export] Exported {self.alerts_table.rowCount()} alerts to {filename}")

    def _on_process_finished(self, worker: QObject, task_name: str, success: bool) -> None:
        result = "success" if success else "failure"
        self.append_log(f"[{task_name}] Finished with {result}.")

    def open_dashboard_link(self, link: DashboardLink) -> None:
        host = self.current_dashboard_host()
        validation_error = validate_host(host)
        if validation_error:
            self.append_log(f"[Dashboard Links] {validation_error}")
            return
        url = link.template.format(host=url_host(host))
        opened = QDesktopServices.openUrl(QUrl(url))
        if opened:
            self.append_log(f"[Dashboard Links] Opened {link.title}: {url}")
        else:
            self.append_log(f"[Dashboard Links] Unable to open {link.title}: {url}")

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._save_settings()
        if self._threads:
            event.ignore()
            if not self._closing:
                self._closing = True
                self.append_log("[Shutdown] Cancelling active jobs before closing.")
                self.centralWidget().setEnabled(False)
                for worker in list(self._workers):
                    cancel = getattr(worker, "cancel", None)
                    if callable(cancel):
                        cancel()
                for thread in list(self._threads):
                    thread.requestInterruption()
            return
        super().closeEvent(event)


def run() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("SIEM-Commander")
    app_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont)
    app_font.setPointSize(11)
    app.setFont(app_font)
    window = SIEMCommanderWindow()
    window.show()
    raise SystemExit(app.exec())
