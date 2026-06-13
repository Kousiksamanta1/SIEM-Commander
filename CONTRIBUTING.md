# Contributing

Thanks for helping improve SIEM-Commander.

## Project Boundaries

SIEM-Commander is a read-only operations console for existing Wazuh
deployments. Changes must preserve secure defaults and must not add active
response, credential provisioning, or destructive actions without an explicit
authorization and audit design.

Never commit credentials, certificates, private keys, host details, alert
documents, or screenshots containing sensitive infrastructure data.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the checks used by CI:

```bash
ruff check .
ruff format --check .
QT_QPA_PLATFORM=offscreen pytest
```

## Pull Requests

- Keep the change focused and explain its analyst workflow.
- Add tests for API, storage, validation, or UI behavior changes.
- Preserve TLS verification, strict SSH host checking, bounded responses, and
  timeout behavior.
- Update documentation when configuration or visible behavior changes.

By contributing, you agree that your contribution is licensed under the MIT
License.

