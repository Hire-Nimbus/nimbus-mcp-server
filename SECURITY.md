# Security

Please do not report security vulnerabilities in public issues. Use a private
GitHub security advisory for this repository, or contact the repository
maintainer through the private channel configured by the operator.

This project is an integration layer. Operators are responsible for endpoint
authentication, tenant isolation, secret storage and rotation, network policy,
data retention, privacy notices, and incident response for their deployment.
Do not include credentials, customer data, or live endpoint responses in bug
reports.

Before publishing a build, run:

    python3 scripts/audit_public_release.py
