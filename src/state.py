"""Small state-store abstraction for multi-instance deployments.

The public distribution does not own a database. Operators can configure a
DynamoDB table for shared state, while local development uses an in-memory
store. Values are JSON-like dictionaries and every write carries an expiry so
the table can use DynamoDB TTL without a cleanup worker.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from typing import Any, Protocol

logger = logging.getLogger("nimbus-mcp.state")


class StateStoreError(RuntimeError):
    """Raised when a configured state backend cannot be used."""


class StateStore(Protocol):
    """Async operations required by auth and side-effect workflows."""

    @property
    def durable(self) -> bool:
        ...

    async def get(self, key: str) -> dict[str, Any] | None:
        ...

    async def put(self, key: str, value: dict[str, Any], expires_at: int) -> None:
        ...

    async def put_if_absent(self, key: str, value: dict[str, Any], expires_at: int) -> bool:
        ...

    async def delete(self, key: str) -> None:
        ...

    async def consume(self, key: str) -> dict[str, Any] | None:
        ...


class InMemoryStateStore:
    """Process-local fallback intended for development and single-process tests."""

    durable = False

    def __init__(self) -> None:
        self._items: dict[str, tuple[dict[str, Any], int]] = {}
        self._lock = threading.RLock()

    def _get_live(self, key: str) -> dict[str, Any] | None:
        now = int(time.time())
        with self._lock:
            entry = self._items.get(key)
            if not entry:
                return None
            value, expires_at = entry
            if expires_at <= now:
                self._items.pop(key, None)
                return None
            return dict(value)

    async def get(self, key: str) -> dict[str, Any] | None:
        return self._get_live(key)

    async def put(self, key: str, value: dict[str, Any], expires_at: int) -> None:
        with self._lock:
            self._items[key] = (dict(value), int(expires_at))

    async def put_if_absent(self, key: str, value: dict[str, Any], expires_at: int) -> bool:
        now = int(time.time())
        with self._lock:
            existing = self._items.get(key)
            if existing and existing[1] > now:
                return False
            self._items[key] = (dict(value), int(expires_at))
            return True

    async def delete(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)

    async def consume(self, key: str) -> dict[str, Any] | None:
        now = int(time.time())
        with self._lock:
            existing = self._items.pop(key, None)
            if not existing or existing[1] <= now:
                return None
            return dict(existing[0])


class DynamoDbStateStore:
    """DynamoDB implementation using conditional writes and atomic consume."""

    durable = True

    def __init__(self, table_name: str) -> None:
        if not table_name:
            raise StateStoreError("DynamoDB state table name is empty")
        try:
            import boto3

            self._table = boto3.resource("dynamodb").Table(table_name)
        except Exception as exc:  # pragma: no cover - depends on deployment runtime
            raise StateStoreError("DynamoDB state backend is unavailable") from exc

    @staticmethod
    def _item(key: str, value: dict[str, Any], expires_at: int) -> dict[str, Any]:
        try:
            serialized = json.dumps(value, separators=(",", ":"), default=str)
        except (TypeError, ValueError) as exc:
            raise StateStoreError("State value must be JSON serializable") from exc
        return {
            "state_key": key,
            "state_value": serialized,
            "expires_at": int(expires_at),
        }

    @staticmethod
    def _value(item: dict[str, Any] | None) -> dict[str, Any] | None:
        if not item:
            return None
        try:
            decoded = json.loads(str(item.get("state_value") or "{}"))
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed state item")
            return None
        return decoded if isinstance(decoded, dict) else None

    async def get(self, key: str) -> dict[str, Any] | None:
        response = await asyncio.to_thread(
            self._table.get_item,
            Key={"state_key": key},
            ConsistentRead=True,
        )
        item = response.get("Item") or {}
        if int(item.get("expires_at", 0) or 0) <= int(time.time()):
            await self.delete(key)
            return None
        return self._value(item)

    async def put(self, key: str, value: dict[str, Any], expires_at: int) -> None:
        item = self._item(key, value, expires_at)
        await asyncio.to_thread(self._table.put_item, Item=item)

    async def put_if_absent(self, key: str, value: dict[str, Any], expires_at: int) -> bool:
        item = self._item(key, value, expires_at)
        try:
            await asyncio.to_thread(
                self._table.put_item,
                Item=item,
                ConditionExpression="attribute_not_exists(state_key) OR expires_at <= :now",
                ExpressionAttributeValues={":now": int(time.time())},
            )
            return True
        except Exception as exc:  # pragma: no cover - depends on boto3 response types
            response = getattr(exc, "response", {}) or {}
            error = response.get("Error", {}) if isinstance(response, dict) else {}
            if error.get("Code") == "ConditionalCheckFailedException":
                return False
            raise StateStoreError("State conditional write failed") from exc

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._table.delete_item, Key={"state_key": key})

    async def consume(self, key: str) -> dict[str, Any] | None:
        response = await asyncio.to_thread(
            self._table.delete_item,
            Key={"state_key": key},
            ReturnValues="ALL_OLD",
        )
        item = response.get("Attributes") or {}
        if int(item.get("expires_at", 0) or 0) <= int(time.time()):
            return None
        return self._value(item)


def build_state_store(table_name: str) -> StateStore:
    """Build the configured store; empty table names intentionally stay local."""

    if table_name:
        return DynamoDbStateStore(table_name)
    return InMemoryStateStore()
