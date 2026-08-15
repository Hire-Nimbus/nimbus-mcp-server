"""Security helpers: PII redaction, input validation, rate limits, circuit breakers."""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import httpx

from src.auth_context import current_actor_id

logger = logging.getLogger("nimbus-mcp.security")

# -------- PII redaction --------

_SENSITIVE_KEYS = frozenset({
    "phone", "ho_phone", "phone_number", "customer_phone", "business_phone", "contact_phone",
    "name", "ho_name", "given_name", "family_name", "reviewer_name", "customer_name",
    "address", "ho_address", "formattedAddress", "address1", "address2",
    "address_payload", "address_input", "location_raw", "resolved_location",
    "token", "access_token", "ho_token", "authorization",
})

_SCRIPT_PATTERN = re.compile(
    r"(<\s*script|javascript\s*:|on\w+\s*=|data\s*:\s*text/html)",
    re.IGNORECASE,
)

_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
_PHONE_PATTERN = re.compile(r"^\+?[0-9]{7,15}$")
_ZIP_PATTERN = re.compile(r"^\d{5}(?:-\d{4})?$")
_ADDRESS1_PATTERN = re.compile(r"^[A-Za-z0-9 .,#\-'/]{1,120}$")
_CITY_REGION_PATTERN = re.compile(r"^[A-Za-z .'\-]{1,80}$")
_POSTAL_PATTERN = re.compile(r"^[A-Za-z0-9 \-]{3,12}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def mask_phone(phone: str) -> str:
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    if len(digits) >= 4:
        return f"***{digits[-4:]}"
    return "***"


def mask_name(name: str) -> str:
    text = (name or "").strip()
    if not text:
        return "***"
    if len(text) <= 2:
        return "*"
    return f"{text[0]}***"


def mask_address(addr: Any) -> str:
    if not isinstance(addr, dict):
        return "[redacted]"
    city = str(addr.get("city") or "").strip()
    region = str(addr.get("region") or addr.get("state") or "").strip()
    postal = str(addr.get("postalCode") or addr.get("zip") or "").strip()
    parts = [p for p in (city, region, postal[:3] + "***" if len(postal) > 3 else postal) if p]
    return ", ".join(parts) if parts else "[redacted]"


def redact_for_log(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return "[truncated]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            lower = str(key).lower()
            if lower in _SENSITIVE_KEYS or "phone" in lower or "address" in lower or "token" in lower:
                if "phone" in lower and item:
                    out[key] = mask_phone(str(item))
                elif lower in ("name", "ho_name", "given_name", "family_name", "customer_name", "reviewer_name"):
                    out[key] = mask_name(str(item))
                elif "address" in lower or lower in ("address1", "address2", "formattedaddress"):
                    out[key] = mask_address(item if isinstance(item, dict) else {"formattedAddress": str(item)})
                else:
                    out[key] = "[redacted]"
            else:
                out[key] = redact_for_log(item, depth=depth + 1)
        return out
    if isinstance(value, list):
        return [redact_for_log(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, str) and len(value) > 200:
        return value[:197] + "..."
    return value


class PIIRedactingFilter(logging.Filter):
    """Best-effort redaction of phone-like digit sequences in log records."""

    _PHONE_IN_TEXT = re.compile(r"(\+?\d[\d\s().-]{6,}\d)")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = self._PHONE_IN_TEXT.sub(lambda m: mask_phone(m.group(1)), record.msg)
            if record.args:
                record.args = tuple(
                    self._PHONE_IN_TEXT.sub(lambda m: mask_phone(m.group(1)), str(a))
                    if isinstance(a, str) and any(ch.isdigit() for ch in a)
                    else a
                    for a in record.args
                )
        except Exception:
            pass
        return True


# -------- Input validation --------

NAME_MAX_LEN = 100
JOB_DESC_MAX_LEN = 2000
LOCATION_TEXT_MAX_LEN = 120


class ValidationError(Exception):
    def __init__(self, message: str, *, error_code: str = "VALIDATION_ERROR"):
        super().__init__(message)
        self.error_code = error_code


def sanitize_text(value: str, *, max_len: int) -> str:
    cleaned = _CONTROL_CHARS.sub("", (value or "").strip())
    if len(cleaned) > max_len:
        raise ValidationError(f"Value exceeds maximum length of {max_len}")
    return cleaned


def sanitize_job_description(value: str) -> str:
    cleaned = sanitize_text(value, max_len=JOB_DESC_MAX_LEN)
    if _SCRIPT_PATTERN.search(cleaned):
        raise ValidationError("job_description contains disallowed content", error_code="INVALID_INPUT")
    return cleaned


def validate_slug(slug: str) -> str:
    cleaned = sanitize_text(slug, max_len=80).lower()
    if not _SLUG_PATTERN.fullmatch(cleaned):
        raise ValidationError("serviceProviderSlug is invalid", error_code="VALIDATION_ERROR")
    return cleaned


def validate_person_name(name: str) -> str:
    cleaned = sanitize_text(name, max_len=NAME_MAX_LEN)
    if len(cleaned) < 2:
        raise ValidationError("name is required", error_code="VALIDATION_ERROR")
    if not re.fullmatch(r"[\w .,'\-]+", cleaned, flags=re.UNICODE):
        raise ValidationError("name contains invalid characters", error_code="VALIDATION_ERROR")
    return cleaned


def validate_phone_normalized(phone: str) -> str:
    cleaned = sanitize_text(phone, max_len=20)
    if not _PHONE_PATTERN.fullmatch(cleaned):
        raise ValidationError("phone is invalid", error_code="INVALID_PHONE")
    return cleaned


def validate_address_fields(raw: dict[str, Any] | None) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValidationError("address must be an object", error_code="VALIDATION_ERROR")

    allowed_keys = {
        "formattedAddress", "postalCode", "address1", "address2",
        "city", "region", "country",
        "street", "street_address", "line1", "address_line_1",
        "state", "province", "state_code",
        "zip", "zipCode", "zip_code", "postal_code", "postal",
        "unit", "apt", "suite", "line2", "address_line_2",
    }
    extra = set(raw.keys()) - allowed_keys
    if extra:
        raise ValidationError("address contains unsupported fields", error_code="VALIDATION_ERROR")

    addr1 = sanitize_text(str(raw.get("address1") or raw.get("street") or raw.get("line1") or ""), max_len=120)
    city = sanitize_text(str(raw.get("city") or ""), max_len=80)
    region = sanitize_text(str(raw.get("region") or raw.get("state") or ""), max_len=20).upper()
    postal = sanitize_text(
        str(raw.get("postalCode") or raw.get("zip") or raw.get("postal_code") or ""),
        max_len=12,
    )
    addr2 = sanitize_text(str(raw.get("address2") or raw.get("unit") or ""), max_len=60)
    country = sanitize_text(str(raw.get("country") or "US"), max_len=2).upper()

    has_structured = any([addr1, city, region, postal, addr2])
    if not has_structured:
        return {}

    if not addr1 or not city or not region or not postal:
        raise ValidationError(
            "address requires address1, city, region, and postalCode",
            error_code="VALIDATION_ERROR",
        )
    if not _ADDRESS1_PATTERN.fullmatch(addr1):
        raise ValidationError("address1 contains invalid characters", error_code="VALIDATION_ERROR")
    if not _CITY_REGION_PATTERN.fullmatch(city):
        raise ValidationError("city is invalid", error_code="VALIDATION_ERROR")
    if not re.fullmatch(r"[A-Z]{2}", region):
        raise ValidationError("region must be a 2-letter state code", error_code="VALIDATION_ERROR")
    if not _POSTAL_PATTERN.fullmatch(postal):
        raise ValidationError("postalCode is invalid", error_code="VALIDATION_ERROR")

    return {
        "address1": addr1,
        "address2": addr2 or None,
        "city": city,
        "region": region,
        "postalCode": postal,
        "country": country or "US",
    }


def validate_location_input(location: dict[str, Any]) -> dict[str, Any]:
    if not location:
        raise ValidationError("location is empty", error_code="INVALID_LOCATION")

    if "lat" in location and ("lng" in location or "lon" in location):
        try:
            lat = float(location["lat"])
            lng = float(location.get("lng", location.get("lon")))
        except (TypeError, ValueError) as exc:
            raise ValidationError("invalid coordinates", error_code="INVALID_LOCATION") from exc
        if not (-90 <= lat <= 90 and -180 <= lng <= 180):
            raise ValidationError("coordinates out of range", error_code="INVALID_LOCATION")
        return {"lat": lat, "lng": lng}

    if "zip" in location:
        zip_code = sanitize_text(str(location["zip"]), max_len=10)
        if not _ZIP_PATTERN.fullmatch(zip_code):
            raise ValidationError("zip is invalid", error_code="INVALID_LOCATION")
        return {"zip": zip_code[:5]}

    if "text" in location:
        text = sanitize_text(str(location["text"]), max_len=LOCATION_TEXT_MAX_LEN)
        if not text:
            raise ValidationError("location text is empty", error_code="INVALID_LOCATION")
        if not re.fullmatch(r"[\w .,'\-#]+", text, flags=re.UNICODE):
            raise ValidationError("location text contains invalid characters", error_code="INVALID_LOCATION")
        return {"text": text}

    raise ValidationError("location must include coords, zip, or text", error_code="INVALID_LOCATION")


def validate_zip_resolve_response(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValidationError("invalid zip-resolve response", error_code="UPSTREAM_ERROR")
    out: dict[str, Any] = {}
    for key in ("city", "state", "canonical_city", "source"):
        val = data.get(key)
        if val is not None:
            out[key] = sanitize_text(str(val), max_len=120)
    return out


def validate_coords_resolve_response(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValidationError("invalid coords-resolve response", error_code="UPSTREAM_ERROR")
    lat = data.get("lat")
    lon = data.get("lon", data.get("lng"))
    if lat is None or lon is None:
        return {}
    try:
        lat_f = float(lat)
        lon_f = float(lon)
    except (TypeError, ValueError) as exc:
        raise ValidationError("invalid coords-resolve response", error_code="UPSTREAM_ERROR") from exc
    if not (-90 <= lat_f <= 90 and -180 <= lon_f <= 180):
        raise ValidationError("invalid coords-resolve response", error_code="UPSTREAM_ERROR")
    out: dict[str, Any] = {"lat": lat_f, "lon": lon_f}
    canonical = data.get("canonical_city")
    if canonical is not None:
        out["canonical_city"] = sanitize_text(str(canonical), max_len=120)
    source = data.get("source")
    if source is not None:
        out["source"] = sanitize_text(str(source), max_len=40)
    return out


# -------- URL allowlist --------


def build_allowed_hosts(configured_urls: list[str]) -> set[str]:
    hosts: set[str] = set()
    for url in configured_urls:
        if not url:
            continue
        parsed = urlparse(url.strip())
        hostname = (parsed.hostname or "").lower()
        if hostname:
            hosts.add(hostname)
    return hosts


def assert_allowed_url(url: str, allowed_hosts: set[str]) -> None:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValidationError("external URL is invalid", error_code="CONFIG_ERROR")
    if hostname in allowed_hosts:
        return
    logger.warning("Blocked request to disallowed host: %s", hostname)
    raise ValidationError("external API host is not allowed", error_code="CONFIG_ERROR")


# -------- Rate limiting --------

class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def is_limited(self, key: str, *, limit: int, window_seconds: int = 60) -> bool:
        if limit <= 0:
            return False
        now = time.time()
        window_start = now - window_seconds
        bucket = self._buckets[key]
        self._buckets[key] = [t for t in bucket if t > window_start]
        if len(self._buckets[key]) >= limit:
            return True
        self._buckets[key].append(now)
        return False


_tool_rate_limiter = SlidingWindowRateLimiter()
_http_rate_limiter = SlidingWindowRateLimiter()


def actor_rate_limit_key(endpoint: str) -> str:
    actor = current_actor_id.get() or "anonymous"
    return f"{actor}:{endpoint}"


def check_tool_rate_limit(endpoint: str, *, limit: int) -> None:
    key = actor_rate_limit_key(endpoint)
    if _tool_rate_limiter.is_limited(key, limit=limit):
        logger.warning("Tool rate limit exceeded for endpoint=%s actor=%s", endpoint, actor_rate_limit_key(""))
        raise ValidationError("Too many requests for this operation", error_code="RATE_LIMITED")


def check_http_rate_limit(key: str, *, limit: int) -> bool:
    return _http_rate_limiter.is_limited(key, limit=limit)


# -------- Circuit breaker --------

class CircuitBreaker:
    def __init__(self, *, failure_threshold: int = 5, open_seconds: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.open_seconds = open_seconds
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._opened_at: dict[str, float] = {}

    def _prune(self, key: str, now: float) -> None:
        window_start = now - 60
        self._failures[key] = [t for t in self._failures[key] if t > window_start]

    def before_call(self, key: str) -> None:
        now = time.time()
        opened = self._opened_at.get(key)
        if opened is not None:
            if now - opened < self.open_seconds:
                raise ValidationError("Upstream service temporarily unavailable", error_code="CIRCUIT_OPEN")
            self._opened_at.pop(key, None)
            self._failures[key] = []

    def record_success(self, key: str) -> None:
        self._failures.pop(key, None)
        self._opened_at.pop(key, None)

    def record_failure(self, key: str) -> None:
        now = time.time()
        self._prune(key, now)
        self._failures[key].append(now)
        if len(self._failures[key]) >= self.failure_threshold:
            self._opened_at[key] = now
            logger.warning("Circuit opened for upstream key=%s", key)


_circuit_breaker = CircuitBreaker()


def _upstream_key(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"


async def external_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    allowed_hosts: set[str],
    endpoint_name: str,
    rate_limit: int,
    **kwargs: Any,
) -> httpx.Response:
    assert_allowed_url(url, allowed_hosts)
    check_tool_rate_limit(endpoint_name, limit=rate_limit)

    upstream_key = _upstream_key(url)
    _circuit_breaker.before_call(upstream_key)
    try:
        response = await client.request(method, url, **kwargs)
        if response.status_code >= 500:
            _circuit_breaker.record_failure(upstream_key)
        else:
            _circuit_breaker.record_success(upstream_key)
        return response
    except httpx.HTTPError:
        _circuit_breaker.record_failure(upstream_key)
        raise


def install_pii_log_filter() -> None:
    filt = PIIRedactingFilter()
    for name in ("nimbus-mcp", "nimbus-mcp.tools", "nimbus-mcp.monitor", "nimbus-mcp.security"):
        logging.getLogger(name).addFilter(filt)
