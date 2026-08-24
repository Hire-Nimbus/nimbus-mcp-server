# Public release checklist

This checklist is a publication gate for the self-hosted distribution. It
must be completed against the exact commit intended for release.

## Repository boundary

- [ ] python3 scripts/audit_public_release.py passes.
- [ ] git ls-files contains no .env, local config, generated archive, customer
      data, credential, or private deployment artifact.
- [ ] A full-history credential scan has been run. If historical secrets are
      found, publish from a fresh sanitized history and revoke the secrets.
- [ ] The public repository contains no private endpoint, first-party API
      default, customer data, or credential. The documented public hosted MCP
      fallback is the only intentional first-party endpoint.
- [ ] LICENSE, README.md, SECURITY.md, and operator data-ownership disclosures
      are present.

## Runtime and deployment

- [ ] python -m compileall -q src tests passes.
- [ ] pytest -q passes using mocked/local integrations only.
- [ ] ruff check src tests passes.
- [ ] sam validate --template-file template.yaml --lint passes.
- [ ] docker build -t home-services-mcp . succeeds and runs as a non-root
      Uvicorn container.
- [ ] Dockerfile.lambda is used only by SAM/Lambda packaging.
- [ ] Production OAuth and idempotency deployments set
      AUTH_STATE_TABLE_NAME and REQUIRE_DURABLE_STATE=true.
- [ ] OAuth discovery publishes a public `jwks_uri`, and dynamic registration
      returns unique client ids when enabled.
- [ ] Operators have configured least-privilege state-table access,
      encryption, backups, TTL, and retention.

## Integration and side effects

- [ ] Every required operator endpoint is explicitly configured.
- [ ] The default hosted relay is documented, and operators can override it
      with UPSTREAM_MCP_URL for a self-hosted upstream.
- [ ] Inbound authorization is not forwarded to an upstream relay.
- [ ] Booking/rebooking previews require explicit confirmation.
- [ ] Confirmed writes use a client-generated idempotency_key and the operator
      booking API honors it.
- [ ] Ambiguous writes are not automatically retried.
- [ ] Partial notification failures are returned as partial outcomes.

## Marketplace package

- [ ] The public repository stays configurable and supports fully self-hosted
      deployment; its hosted relay fallback is disclosed separately.
- [ ] The first-party marketplace package lives in the private runtime
      repository and contains the intentionally selected hosted MCP URL.
- [ ] Cursor Agent Plugin and existing Codex/OpenAI plugin manifests are
      validated separately.
- [ ] Marketplace submission is performed only after the public repository is
      available at the submitted GitHub URL.
