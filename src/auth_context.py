from __future__ import annotations

from typing import Any, Dict, Optional
import contextvars

# Per-request storage for the connected homeowner profile, populated from JWT claims
current_ho_profile: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "current_ho_profile",
    default=None,
)

# Whether the current request carries a valid OAuth or static operator token.
# A profile may be absent even when authentication succeeded.
current_is_authenticated: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "current_is_authenticated",
    default=False,
)

# Opaque operator identity/session reference for request-scoped enrichment.
current_ho_session_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_ho_session_id",
    default=None,
)

# Per-request HTTP metadata (IP, country, user-agent) for MCP monitor events.
current_request_meta: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "current_request_meta",
    default=None,
)

# Authenticated actor id (JWT sub or static token id) for per-user rate limiting.
current_actor_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_actor_id",
    default=None,
)
