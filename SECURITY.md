# Security Policy

## Reporting a Vulnerability

Do not open a public issue for a vulnerability that could expose credentials or
connected infrastructure. Contact the repository owner privately with:

- The affected version or commit
- Reproduction steps
- The expected impact
- Any suggested remediation

## Deployment Guidance

- Keep TLS verification enabled and provide a trusted CA bundle when required.
- Keep strict SSH host-key checking enabled.
- Use a dedicated read-only Wazuh API and indexer account.
- Do not place credentials in URLs, source files, screenshots, or issue reports.
- Rotate credentials immediately if they may have been exposed.
