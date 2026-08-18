# Nimbus MCP Distribution Context

This context defines the language used to make the private Nimbus MCP behavior reproducible as a safe, self-configured public distribution.

## Language

**Behavioral source of truth**:
The `nimbus-mcp` repository is the authoritative reference for the currently implemented Nimbus MCP runtime behavior and tool surface.
_Avoid_: README-only feature lists, planned functionality, or the public repository's current implementation.

**Parity scope**:
Every behavior implemented by the behavioral source of truth is in scope for the public distribution; features documented only as planned are not part of parity until implemented there.
_Avoid_: Documentation parity, aspirational parity.

**Public boundary**:
The set of source files, documentation, examples, tests, deployment metadata, and runtime defaults that may be distributed without revealing private Nimbus infrastructure, data, credentials, or deployment identity.
_Avoid_: Public-facing code only.

**Operator-owned integration**:
An external API, data store, notification service, identity provider, or other dependency supplied and administered by the person or organization running the public distribution.
_Avoid_: Built-in Nimbus integration, shared backend.

**Unconfigured capability**:
A supported MCP behavior whose operator-owned integration is absent or incomplete; it remains unavailable and must report a clear configuration error rather than silently contacting a private fallback.
_Avoid_: Anonymous fallback, undocumented remote service, best-effort private default.

**Integration contract**:
The documented request, response, authentication, error, and ownership boundary between an MCP capability and an operator-owned external service.
_Avoid_: Private API assumption, implicit backend schema.

**Integration adapter**:
A boundary component that translates MCP capability behavior to and from an integration contract, keeping the core behavior independent of a particular API vendor, database, or notification provider.
_Avoid_: Direct Supabase dependency, hardcoded service client.

**Upstream MCP relay**:
An adapter that connects the public server to another MCP server and exposes that remote capability through the documented public hosted default or an explicitly configured upstream URL and credential.
_Avoid_: REST endpoint substitution, undisclosed proxying, automatic inbound-token forwarding.

**Operator identity adapter**:
The configured boundary that verifies an MCP user's identity and loads the operator-owned profile needed by protected capabilities.
_Avoid_: Built-in phone provider, private auth webhook, shared identity database.

**Protected capability**:
An MCP behavior that requires an authenticated operator identity and may use the associated operator-owned profile or delegated access context.
_Avoid_: Authenticated endpoint, private-only tool.

**Durable operator state**:
State required for correctness across processes, instances, or restarts, stored in infrastructure owned and configured by the operator.
_Avoid_: Process-local production state, bundled application database.

**Development state**:
An in-memory implementation intended only for local development and tests, where restart loss and single-process behavior are acceptable.
_Avoid_: Production session store, durable state.

**Open-source distribution**:
The independently usable code and documentation published under the project's approved open-source license, with operator-supplied integrations and without private Nimbus infrastructure, data, or credentials. A documented public hosted MCP fallback may be included for convenience.
_Avoid_: Public mirror of the private deployment, source-available demo, undisclosed data routing.

**Supported deployment target**:
A runtime and deployment path that the project documents, tests, and treats as part of its compatibility promise: local ASGI, generic Docker, and AWS SAM/Lambda for this distribution.
_Avoid_: Unverified platform, private deployment recipe.

**Release gate**:
An automated or reproducible verification required before a milestone is committed, covering behavior, supported builds, code quality, dependency risk, and absence of private data or credentials.
_Avoid_: Manual confidence, live private-service smoke test.

**Configurable presentation**:
Operator-controlled display metadata such as the MCP name, descriptions, markets, brand links, provider URLs, app links, and support contact that does not change the underlying home-services capability behavior.
_Avoid_: Hardcoded product copy, private branding default.

**Side-effecting capability**:
An MCP behavior that can create, modify, notify about, schedule, approve, or otherwise cause a real-world or durable state change.
_Avoid_: Write endpoint, potentially destructive tool.

**Confirmation gate**:
The explicit user approval required immediately before a side-effecting capability submits an irreversible or externally visible operation.
_Avoid_: Implied intent, preview submission.

**Marketplace package**:
A first-party distributable wrapper containing plugin metadata, skills, and an explicitly selected remote MCP endpoint for publication through an agent marketplace; it is separate from the server's generic configuration and branding.
_Avoid_: Undocumented server default, open-source runtime credentials.

**Portable skill**:
Vendor-neutral workflow guidance that can ship with the open-source distribution and teach compatible agent clients how to use the MCP tool surface safely.
_Avoid_: Private product prompt, marketplace-only branding.

**Hosted handoff**:
A user-visible link or instruction that directs a homeowner from an MCP workflow to the operator's application, support channel, or provider page after a capability completes.
_Avoid_: Hardcoded app promotion, implicit remote-data redirect.

**Disclosure package**:
The privacy, terms, data-flow, security-contact, and operator guidance needed to explain and govern how a distribution handles user and integration data.
_Avoid_: Hidden data handling, marketplace form only.

**Credential exposure**:
Any secret, bearer token, private key, service-role credential, or credential-like default present in source, artifacts, configuration, logs, or reachable repository history; it is treated as compromised until revoked or proven inert.
_Avoid_: Harmless secret, test token by assumption.

**Sanitized public history**:
A newly published repository history containing only audited source, documentation, tests, and release artifacts, with all known credential-bearing or private deployment history excluded.
_Avoid_: Latest-commit cleanup, rewritten-history guarantee.

**Public MCP contract**:
The versioned set of tool names, input and result schemas, annotations, prompts, resources, authentication expectations, and side-effect semantics exposed to MCP clients.
_Avoid_: Internal implementation detail, documentation-only feature list.
