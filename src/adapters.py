"""Operator-owned integration seams.

The MCP workflow depends on HTTP APIs, but the workflow should not know how
an operator hosts them. This adapter is the default implementation and is
also the seam used by tests and alternate deployments to replace outbound
transport without changing tool behavior.
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from src.security import ValidationError, external_request


class OperatorRequestAdapter(Protocol):
    async def request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        allowed_hosts: set[str],
        endpoint_name: str,
        rate_limit: int,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform one operator-owned outbound request."""


class HttpOperatorRequestAdapter:
    """Secure HTTP adapter for operator APIs and third-party integrations."""

    async def request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        allowed_hosts: set[str],
        endpoint_name: str,
        rate_limit: int,
        **kwargs: Any,
    ) -> httpx.Response:
        if not url.strip():
            raise ValidationError(
                f"Integration is not configured for {endpoint_name}",
                error_code="INTEGRATION_NOT_CONFIGURED",
            )
        return await external_request(
            client,
            method,
            url,
            allowed_hosts=allowed_hosts,
            endpoint_name=endpoint_name,
            rate_limit=rate_limit,
            **kwargs,
        )


_operator_request_adapter: OperatorRequestAdapter = HttpOperatorRequestAdapter()


def set_operator_request_adapter(adapter: OperatorRequestAdapter) -> None:
    """Replace the outbound adapter for tests or an alternate deployment."""

    global _operator_request_adapter
    _operator_request_adapter = adapter


async def operator_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    allowed_hosts: set[str],
    endpoint_name: str,
    rate_limit: int,
    **kwargs: Any,
) -> httpx.Response:
    """Route an outbound call through the configured operator adapter."""

    return await _operator_request_adapter.request(
        client,
        method,
        url,
        allowed_hosts=allowed_hosts,
        endpoint_name=endpoint_name,
        rate_limit=rate_limit,
        **kwargs,
    )
