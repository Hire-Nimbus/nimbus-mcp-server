# Home Services MCP Server

An open-source, self-hostable Model Context Protocol server for home-service
discovery, provider profiles and reviews, homeowner identity, booking
requests, and booking follow-up. The server supplies the workflow and MCP
interface; each operator supplies the APIs, data, credentials, branding, and
deployment environment.

This repository contains no customer data, provider data, API keys, or private
production endpoints. It includes one documented public hosted MCP fallback
for convenience; operators can replace it with their own endpoint and
credentials for a fully self-hosted deployment.

## What is included

- Streamable HTTP MCP transport at `/mcp` (the root endpoint is also mapped for
  clients that require it).
- OAuth 2.0 authorization-code flow with PKCE, when OAuth credentials are
  configured.
- Provider search, details, reviews, homeowner profile, booking, previous-job,
  booking-status, and rebooking workflows.
- Optional category-specific find/book tool aliases.
- Input validation, PII-aware logging, outbound host allowlisting, rate
  limiting, and circuit-breaker behavior.
- Local ASGI development, a generic Docker image, and AWS SAM/Lambda
  deployment configuration.

The public MCP contract is intentionally stable. Operators can replace the
backends without changing the client-facing tool names or workflow semantics.

## Quick start

```bash
python3.10 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# The default setup uses the hosted MCP relay. For self-hosting, edit .env
# with your own upstream MCP endpoint, API URLs, and credentials.
uvicorn src.main:app --reload --port 8000
```

The server is then available at `http://localhost:8000/mcp`.

Before opening a release or marketplace review, run the checks in
docs/RELEASE_CHECKLIST.md, including:

    python3 scripts/audit_public_release.py

For a container build:

```bash
docker build -t home-services-mcp .
docker run --env-file .env -p 8000:8080 home-services-mcp
```

For AWS SAM, provide deployment-specific values through parameter overrides
or your secret manager. Do not place secrets in `template.yaml`, `samconfig`
files, container layers, or source control.

## Configuration

Start with [.env.example](.env.example). Empty optional endpoint variables
disable the related capability. The upstream MCP relay is the exception: it
defaults to the documented public hosted service and can be overridden.

Core operator-owned endpoints:

| Variable | Purpose |
| --- | --- |
| `PROVIDERS_API` | Provider search endpoint |
| `COORDS_RESOLVE_API` | Text/coordinate location resolver |
| `ZIP_RESOLVE_API` | Postal-code location resolver |
| `GEOCODING_API` / `GEOCODING_API_KEY` | Optional address enrichment integration |
| `REVIEWS_API` | Provider profile and review endpoint |
| `BOOKING_API` | Booking/request creation endpoint |
| `SERVICE_REQUESTS_URL` | Booking history/status endpoint |
| `SERVICE_REQUESTS_METADATA_URL` | Optional endpoint for notification metadata |
| `PROFILE_LOOKUP_API` | Optional phone/profile lookup endpoint |
| `AUTH_WEBHOOK_URL` | Optional OTP send/verify endpoint |
| `HOMEOWNER_PROFILE_API` | Optional profile-by-token endpoint |
| `CANCEL_BOOKING_API` | Optional authenticated, ownership-enforcing cancellation endpoint |

Optional integrations include notification endpoints, operator persistence,
monitoring webhooks, OAuth, and the OpenAI app verification challenge. All
URLs and secrets must be supplied by the operator.

### OAuth interoperability

When OAuth is enabled, access and refresh tokens use separate ES256 signing
keys; the access-token public verification key
is exposed through the metadata `jwks_uri`. Set
`OAUTH_ALLOWED_REDIRECT_URIS` to the exact hosted or claimed-scheme callbacks
your clients use. Native clients may register HTTP loopback callbacks on
`localhost`, `127.0.0.1`, or `[::1]` with any explicit port; these do not need
to be enumerated because native apps commonly bind an ephemeral port. Other
custom schemes (including arbitrary `cursor://` or `vscode://` callbacks) are
rejected unless their complete URI is explicitly configured, since dynamic
registration alone does not prove ownership of a private scheme. Enable
`OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED` to let public PKCE clients obtain
unique persisted client ids from `/oauth/register`; the legacy configured
client id and unregistered PKCE clients remain supported.

Use at least 32 cryptographically random bytes for `OAUTH_CLIENT_SECRET`. The
server derives domain-separated ES256 keys from that secret so stateless
instances publish and verify the same access-token key without reusing it for
refresh-token signatures. OAuth tokens carry an opaque homeowner session id;
profile PII and upstream bearer credentials remain in the server-side state
store.

### Upstream MCP relay

By default, the server relays requests from `/upstream/mcp` to
`https://mcp.hirenimbus.com/mcp`. Set `UPSTREAM_MCP_URL` to use an
operator-controlled MCP service instead. If the selected upstream requires
authentication, set `UPSTREAM_MCP_AUTH_TOKEN`; no token is bundled, and
inbound client authorization is never forwarded automatically.

Review the selected upstream's data handling, retention, terms, and access
policy before sending user requests to it. For a fully self-hosted deployment,
replace the default upstream and configure the operator-owned business APIs.

## Security and data ownership

The server is a programmable integration layer, not a data processor with a
built-in tenant. Operators are responsible for:

- API authorization, tenant isolation, data retention, backups, and deletion;
- secret storage, rotation, least-privilege scopes, and production network
  policy;
- privacy notices, terms, support contacts, regional/legal requirements, and
  any third-party processing disclosures;
- confirming that configured APIs do not return more personal information than
  the MCP client needs.

The default development configuration leaves external business APIs empty.
Production deployments should fail closed when a required capability is not
configured, use durable shared state for OAuth and idempotency, and keep
monitoring disabled unless its endpoint is explicitly configured. Set
AUTH_STATE_TABLE_NAME to a shared DynamoDB table and
REQUIRE_DURABLE_STATE=true for multi-instance OAuth or booking workloads.
Without those settings, the development fallback is process-local and does
not provide cross-instance replay protection.

Confirmed booking calls accept an optional client-generated
idempotency_key. Clients should reuse that key after a timeout. The
configured booking API should also honor the same field; the server never
retries an ambiguous booking request automatically.

## Testing

Install the development dependencies and run:

```bash
pytest -q
ruff check .
```

Tests must use mocks or local fixtures for external integrations. They must
not call a live operator endpoint.

## Marketplace package

The server and portable workflow skills are independent of any hosted
deployment. A first-party distribution can add a separate marketplace
manifest that points to its own hosted MCP URL and branded app, without
putting those values in this repository.

The portable home-service workflow is available at
[`skills/home-service-concierge/SKILL.md`](skills/home-service-concierge/SKILL.md).
Its app handoff uses the operator-configured `APP_LINK` value.

## License

Licensed under the [Apache License 2.0](LICENSE). Product names, trademarks,
private services, and operator integrations are not included as defaults by
this codebase. The documented public hosted MCP fallback is an intentional
exception and does not include credentials or customer data.
