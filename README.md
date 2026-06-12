# SIEM-Commander

SIEM-Commander is a production-oriented PyQt6 desktop operations console for an
existing Wazuh deployment. It gives a SOC analyst one place to verify manager
health, review agent connectivity, query recent alerts, check the manager
service over SSH, and open related dashboards.

It is a client for Wazuh, not a replacement SIEM.

## Capabilities

- Authenticates to the Wazuh server API with JWT
- Retrieves API version, manager daemon status, agent counts, and agent details
- Queries Wazuh indexer cluster health and recent `wazuh-alerts-*` documents
- Exports the current alert table to CSV
- Checks `wazuh-manager` through SSH with password, private-key, or SSH-agent authentication
- Opens Wazuh, Kibana, Grafana, and Proxmox dashboards
- Runs network and subprocess work outside the UI thread
- Cancels active work safely during application shutdown
- Stores non-secret configuration between runs
- Optionally stores credentials in the operating system keyring
- Provides deterministic, non-offensive drill simulations for demos

## Security Defaults

- TLS certificate verification is enabled.
- Unknown SSH host keys are rejected.
- Passwords are never written to `QSettings` or repository files.
- HTTP requests have timeouts and bounded response sizes.
- Alert index patterns are validated before use.
- Duplicate copies of the same background job are blocked.

Use `Allow self-signed TLS certificates` and `Allow unknown SSH host keys` only
for controlled labs. For a real deployment, install trusted certificates or
provide the deployment CA bundle and verify the SSH host fingerprint.

## Requirements

- Python 3.10 or newer
- A reachable Wazuh server API, normally on TCP `55000`
- A reachable Wazuh indexer API, normally on TCP `9200`
- Optional SSH access to the manager, normally on TCP `22`
- API and indexer accounts with only the permissions required for read access

The current client follows the Wazuh 4.x server API and indexer interfaces.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

On Linux, secure credential persistence also requires a working Secret Service
or another backend supported by Python `keyring`. The application continues to
work without credential persistence if no keyring backend is available.

## Run

From the repository:

```bash
python3 main.py
```

After installation:

```bash
siem-commander
```

## Production Configuration

### 1. Accounts

Create dedicated accounts instead of using Wazuh administrative credentials.

- The Wazuh API account needs permission to authenticate and read `/`,
  `/manager/status`, `/agents/summary/status`, and `/agents`.
- The indexer account needs cluster-health access and read/search access to the
  configured alert index, normally `wazuh-alerts-*`.
- The SSH account needs permission to run `systemctl is-active wazuh-manager`
  and read the service status.

### 2. TLS

Keep certificate verification enabled. If the deployment uses a private CA,
select its PEM certificate or CA bundle in `CA Bundle`.

The same CA bundle is currently used for the Wazuh API and indexer connections.

### 3. SSH

Prefer an SSH key or agent over a password. Add and verify the manager host key
in the user's `~/.ssh/known_hosts` before using the strict default mode.

The unknown-host option allows a first connection but does not establish trust
for future sessions. Verify and install the host key before production use.

### 4. Application Fields

In `Lab Status`, configure:

- Manager hostname or IP
- SSH username and optional password/private key
- Wazuh API URL and credentials
- Wazuh indexer URL and credentials
- Alert index pattern and result limit
- Optional CA certificate bundle

Non-secret settings persist automatically. Enable OS-keyring storage only on a
trusted workstation.

## Live Validation Checklist

Before relying on the console operationally, validate the same paths from the
analyst workstation:

```bash
curl --user api-user --cacert /path/to/ca.pem \
  -X POST "https://manager.example:55000/security/user/authenticate?raw=true"

curl --user indexer-user --cacert /path/to/ca.pem \
  "https://indexer.example:9200/_cluster/health"

ssh soc-reader@manager.example "systemctl is-active wazuh-manager"
```

Then verify in SIEM-Commander:

1. `Refresh Wazuh Overview` shows the expected API version and agent counts.
2. `Load Recent Alerts` returns events from the expected index and time order.
3. `Check SIEM Status` reports the same state as the direct SSH command.
4. Closing the application during an active task exits without an orphan process.
5. CSV export opens correctly in the intended analysis tool.

Never place passwords directly in shell commands or commit them to the repository.

## Development

Install development tools and run all checks:

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
QT_QPA_PLATFORM=offscreen pytest
```

GitHub Actions runs linting, tests, and package builds on Python 3.10 and 3.12.

## Current Scope

SIEM-Commander is an operational read-only console. It does not yet provide:

- Multiple named connection profiles
- Continuous alert streaming or scheduled refresh
- Alert acknowledgement and case-management workflows
- Wazuh active-response execution
- Role or account provisioning

Those actions should not be added until authorization, audit logging, and
approval workflows are designed for the target organization.

## Architecture and Design

### Architecture

![SIEM-Commander Architecture](docs/diagrams/siem-commander-architecture.png)

### System Design

![SIEM-Commander System Design](docs/diagrams/siem-commander-system-design.png)

### Flowchart

![SIEM-Commander Flowchart](docs/diagrams/siem-commander-flowchart.png)

## References

- [Wazuh server API authentication](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)
- [Wazuh server API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html)
- [Wazuh index definitions](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)

## License

MIT
