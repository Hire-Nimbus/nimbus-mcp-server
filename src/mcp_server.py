# src/mcp_server.py
from __future__ import annotations

import json
import os
import re
from typing import Annotated, Any, Dict, Literal, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field

from src.config import APP_LINK, BRAND_NAME, MCP_SERVER_NAME, SITE_BASE_URL
from src.auth_context import current_ho_profile, current_is_authenticated
from src.tools import (
    _build_formatted_address,
    _geocode_address,
    search_providers,
    get_provider_reviews,
    get_provider_details,
    create_booking,
    get_previous_jobs,
    get_booking_status,
    book_same_pro_again,
    cancel_booking,
)
from src.monitor import install_tool_monitor

UI_DIR = os.path.join(os.path.dirname(__file__), "ui")


class HomeownerAddress(BaseModel):
    """Structured service address returned from the homeowner profile."""

    address1: Optional[str] = Field(None, description="Street line 1 (e.g. 123 Main St)")
    address2: Optional[str] = Field(None, description="Apt, unit, or suite")
    city: Optional[str] = Field(None, description="City name")
    region: Optional[str] = Field(None, description="State or province code (e.g. VA)")
    postalCode: Optional[str] = Field(None, description="ZIP or postal code")
    country: Optional[str] = Field(None, description="Country code (e.g. US)")
    formattedAddress: Optional[str] = Field(
        None, description="Single-line formatted address when available (read-only; do not pass on input)"
    )


class HomeownerAddressInput(BaseModel):
    """Street-level address override for booking tools. Omit to use the authenticated profile address."""

    address1: Optional[str] = Field(
        None,
        description="Street line 1 (e.g. 123 Main St). Required when overriding address.",
    )
    address2: Optional[str] = Field(None, description="Apt, unit, or suite")
    city: Optional[str] = Field(None, description="City name")
    region: Optional[str] = Field(None, description="State or province code (e.g. VA)")
    postalCode: Optional[str] = Field(None, description="5-digit ZIP or postal code")
    country: Optional[str] = Field(None, description="Country code (e.g. US)")


class BookingLocationInput(BaseModel):
    """Optional geocoding hint when the address lacks coordinates. Provide one style only."""

    lat: Optional[float] = Field(None, description="Latitude; use together with lng or lon")
    lng: Optional[float] = Field(None, description="Longitude; use together with lat")
    lon: Optional[float] = Field(None, description="Alias for lng when paired with lat")
    zip: Optional[str] = Field(
        None,
        description='5-digit US ZIP (e.g. "22314") to resolve coordinates',
        examples=["22314"],
    )
    text: Optional[str] = Field(
        None,
        description='City and state text (e.g. "Alexandria, VA") to resolve coordinates',
        examples=["Alexandria, VA"],
    )


class GetMyProfileResult(BaseModel):
    """Authenticated homeowner profile returned by get_my_profile."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "status": "ok",
                    "name": "Jane Doe",
                    "phone": "+15551234567",
                    "address": {
                        "address1": "123 Main St",
                        "address2": None,
                        "city": "Alexandria",
                        "region": "VA",
                        "postalCode": "22314",
                        "country": "US",
                        "formattedAddress": "123 Main St, Alexandria, VA 22314",
                    },
                    "search_location": "Alexandria, VA",
                    "message": None,
                },
                {
                    "status": "error",
                    "name": None,
                    "phone": None,
                    "address": None,
                    "search_location": None,
                    "message": "No authenticated homeowner profile found.",
                },
            ]
        }
    )

    status: Literal["ok", "error"] = Field(description='Outcome: "ok" when profile loaded, "error" otherwise')
    name: Optional[str] = Field(None, description="Homeowner full name from profile (present when status is ok)")
    phone: Optional[str] = Field(None, description="Homeowner phone from profile (present when status is ok)")
    address: Optional[HomeownerAddress] = Field(
        None,
        description=(
            "Full service street address on file with fields address1, address2, city, "
            "region, postalCode, country, formattedAddress"
        ),
    )
    search_location: Optional[str] = Field(
        None,
        description=(
            'City+state or 5-digit ZIP derived from address (e.g. "Alexandria, VA" or "22314") '
            "— pass to search_providers.location after user confirms address (never the street line)"
        ),
        examples=["Alexandria, VA", "22314"],
    )
    message: Optional[str] = Field(None, description="Error explanation when status is error")

def _read_ui_file(filename: str) -> str:
    with open(os.path.join(UI_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()

RESOURCE_MIME_TYPE = "text/html;profile=mcp-app"

def _normalize_address(raw: Dict[str, Any] | None) -> Dict[str, Any]:
    """Map compact profile and booking address shapes to one canonical shape."""
    if not raw or not isinstance(raw, dict):
        return {}
    out = dict(raw)

    if not out.get("address1"):
        for alt in ("street", "street_address", "line1", "address_line_1"):
            if out.get(alt):
                out["address1"] = out.pop(alt)
                break

    city_state_zip = str(out.pop("cityStateZip", "") or "").strip()
    if city_state_zip:
        parts = [part.strip() for part in city_state_zip.split(",")]
        if not out.get("city") and parts:
            out["city"] = parts[0]
        if not out.get("region") and len(parts) >= 2:
            region = parts[1]
            out["region"] = {
                "Alabama": "AL", "Alaska": "AK", "Arizona": "AZ", "Arkansas": "AR",
                "California": "CA", "Colorado": "CO", "Connecticut": "CT", "Delaware": "DE",
                "Florida": "FL", "Georgia": "GA", "Hawaii": "HI", "Idaho": "ID",
                "Illinois": "IL", "Indiana": "IN", "Iowa": "IA", "Kansas": "KS",
                "Kentucky": "KY", "Louisiana": "LA", "Maine": "ME", "Maryland": "MD",
                "Massachusetts": "MA", "Michigan": "MI", "Minnesota": "MN", "Mississippi": "MS",
                "Missouri": "MO", "Montana": "MT", "Nebraska": "NE", "Nevada": "NV",
                "New Hampshire": "NH", "New Jersey": "NJ", "New Mexico": "NM", "New York": "NY",
                "North Carolina": "NC", "North Dakota": "ND", "Ohio": "OH", "Oklahoma": "OK",
                "Oregon": "OR", "Pennsylvania": "PA", "Rhode Island": "RI", "South Carolina": "SC",
                "South Dakota": "SD", "Tennessee": "TN", "Texas": "TX", "Utah": "UT",
                "Vermont": "VT", "Virginia": "VA", "Washington": "WA", "West Virginia": "WV",
                "Wisconsin": "WI", "Wyoming": "WY", "District of Columbia": "DC",
            }.get(region, region)
        if not out.get("country") and len(parts) >= 3:
            out["country"] = {"United States": "US", "United States of America": "US", "USA": "US"}.get(
                parts[2], parts[2]
            )

    full = str(out.pop("full", "") or "").strip()
    if full:
        out.setdefault("formattedAddress", full)
        if not out.get("postalCode"):
            match = re.search(r"\b(\d{5})\b", full)
            if match:
                out["postalCode"] = match.group(1)

    if not out.get("region"):
        for alt in ("state", "province", "state_code"):
            if out.get(alt):
                out["region"] = out.pop(alt)
                break

    if not out.get("postalCode"):
        for alt in ("zip", "zipCode", "zip_code", "postal_code", "postal"):
            if out.get(alt):
                out["postalCode"] = out.pop(alt)
                break

    if not out.get("address2"):
        for alt in ("unit", "apt", "suite", "line2", "address_line_2"):
            if out.get(alt):
                out["address2"] = out.pop(alt)
                break

    return out


def _search_location_from_address(address: Dict[str, Any]) -> Optional[str]:
    if not address:
        return None

    city = str(address.get("city") or "").strip()
    region = str(address.get("region") or "").strip()
    postal_raw = str(address.get("postalCode") or "").strip()
    postal_match = re.search(r"\b(\d{5})\b", postal_raw)
    postal = postal_match.group(1) if postal_match else ""

    if city and region:
        return f"{city}, {region}"
    if postal:
        return postal
    return None


_AUTH_REQUIRED_RESULT = {
    "status": "auth_required",
    "error_code": "AUTH_REQUIRED",
    "message": (
        f"This action requires a connected {BRAND_NAME} account. "
        "Searching and browsing providers works without an account. "
        "Connect the operator's configured identity provider before booking, "
        "viewing private job history, or rebooking."
    ),
}


def _require_auth() -> Dict[str, Any] | None:
    """Return a stable tool result when a protected capability lacks identity."""

    return None if current_is_authenticated.get() else dict(_AUTH_REQUIRED_RESULT)


def _raise_tool_error(result: Dict[str, Any]) -> None:
    """Preserve the structured error payload while setting MCP isError=true."""

    raise ToolError(json.dumps(result, default=str))


def _raise_if_write_failed(result: Dict[str, Any]) -> Dict[str, Any]:
    if result.get("status") in {"failed", "error", "auth_required"} or result.get("error"):
        _raise_tool_error(result)
    return result


SearchLocation = Annotated[
    str,
    Field(
        description=(
            'City+state or 5-digit ZIP only (e.g. "Alexandria, VA" or "22314"). '
            "Use the search_location string returned by get_my_profile when available. "
            "Never pass a street address, formattedAddress, or address1."
        ),
        examples=["Alexandria, VA", "22314"],
        min_length=1,
    ),
]

_POPULAR_SERVICES: Dict[str, Dict[str, str]] = {
    "handyman": {
        "query": "handyman",
        "label": "handyman",
        "find_phrase": "a handyman or general home repair pro",
        "book_phrase": "a handyman job",
        "symptoms": "TV mounting, furniture assembly, drywall holes, doors, shelving, caulking, gutters, fences, decks, or minor repairs",
    },
    "hvac": {
        "query": "HVAC",
        "label": "HVAC",
        "find_phrase": "HVAC heating, cooling, or AC service",
        "book_phrase": "an HVAC job",
        "symptoms": "AC not cooling, furnace trouble, thermostat installation, heat pumps, tune-ups, duct work, strange noises, or uneven temperatures",
    },
    "plumber": {
        "query": "plumber",
        "label": "plumber",
        "find_phrase": "a plumber or plumbing repair",
        "book_phrase": "a plumbing job",
        "symptoms": "leaky faucets, clogged drains or toilets, low pressure, water heaters, pipe leaks, sewer issues, or fixture installation",
    },
    "electrician": {
        "query": "electrician",
        "label": "electrician",
        "find_phrase": "an electrician or electrical work",
        "book_phrase": "an electrical job",
        "symptoms": "outlets, breakers, lighting, ceiling fans, EV chargers, wiring, smoke detectors, or electrical troubleshooting",
    },
    "renovation": {
        "query": "renovation",
        "label": "renovation",
        "find_phrase": "a renovation or remodeling contractor",
        "book_phrase": "a renovation or remodeling job",
        "symptoms": "kitchens, bathrooms, flooring, painting, drywall, decks, additions, or other remodeling work",
    },
}


async def _search_providers_response(
    query: str,
    location: str,
    page: int = 1,
    limit: int = 6,
    *,
    next_step: Optional[str] = None,
) -> Dict[str, Any]:
    result = await search_providers(query=query, location=location, page=page, limit=limit)
    if isinstance(result, dict) and "error" in result:
        return result
    response: Dict[str, Any] = {
        **result,
        "structuredContent": {
            "view": "providers",
            **result,
        },
        "_meta": {"ui": {"resourceUri": "ui://providers/app"}},
    }
    if next_step:
        response["next_step"] = next_step
    return response


mcp = FastMCP(
    MCP_SERVER_NAME,
    instructions=(
        f"{BRAND_NAME} is an operator-configured home services experience. "
        "The available capabilities and coverage come from the operator's APIs. "
        "across plumbing, electrical, HVAC, cleaning, landscaping, and more.\n\n"

        "FIRST ACTION RULE (never skip): For ANY request to find, search, compare, "
        "or book a professional, your FIRST profile tool call in that flow MUST be "
        "get_my_profile — in the SAME turn when possible, BEFORE you ask the user for "
        "a free-form location, BEFORE search_providers, and BEFORE create_booking.\n"
        "- Do NOT ask \"What's your location?\", city, ZIP, or street until after "
        "get_my_profile returns. Start from the configured profile integration.\n"
        "- After get_my_profile: show the saved name/address CLEARLY and ask for "
        "**explicit confirmation** that this is where they want the job / search "
        "(yes/no style, or 'correct it if wrong'). Do NOT call search_providers in "
        "that same turn until they confirm.\n"
        "- After they confirm: treat that confirmed address as the **canonical service "
        "area** for the rest of this flow — reuse it for all search_providers calls unless "
        "they explicitly change it.\n"
        "- ONLY if get_my_profile has no usable address (or returns an error explaining "
        "no profile), then ask ONE short question for location — never assume location "
        "from chat memory.\n"
        "- The usual pre-tool question is job_description (what work they need). Call "
        "get_my_profile as soon as you have enough intent to proceed (often same turn "
        "as they describe the job).\n\n"

        "=== MANDATORY BOOKING WORKFLOW (follow these steps in order) ===\n\n"

        "STEP 1 — PROFILE FIRST (get_my_profile) — THEN CONFIRM SERVICE ADDRESS\n"
        "Call get_my_profile early (see FIRST ACTION RULE). Never skip it to ask for "
        "ZIP/city first.\n"
        "- This is the ONLY source of truth for identity. NEVER use your memory, "
        "prior conversations, user account info, or any AI-side stored data.\n"
        "- Even if you 'remember' the user's name or address from a previous chat, "
        "IGNORE it for data; only use get_my_profile (plus what they correct in this chat).\n"
        "- **Confirmation gate:** Present the profile address in plain language and ask "
        "whether to search and book for that location. Wait for their confirmation (or "
        "their correction) before any search.\n"
        "- If they correct the address, use **only** that corrected value for "
        "search_providers and mention it in follow-up; do not revert to the old profile "
        "unless they ask.\n\n"

        "STEP 2 — SEARCH FOR PROS — ONLY AFTER CONFIRMATION\n"
        "After the user has **confirmed** the service address (from Step 1) or supplied "
        "a location when the profile was empty, search for pros. This is the primary "
        "discovery path; call it before get_previous_jobs.\n"
        "- Prefer find_handyman, find_hvac, find_plumber, find_electrician, or find_renovation "
        "when the user wants to discover or compare pros.\n"
        "- Prefer book_handyman, book_hvac, book_plumber, book_electrician, or book_renovation "
        "when the user wants to **book** that service — these run the same search with the category "
        "prefilled, then you MUST ask which pro they would like to book before calling create_booking.\n"
        "- Use search_providers for other services (cleaning, landscaping, roofing, etc.) "
        "or when the category is ambiguous.\n"
        "- For location, pass ONLY city+state or ZIP — never a full "
        "street address. When get_my_profile returns a search_location field, copy that "
        "value verbatim after the user confirms the service address.\n"
        "- Do NOT call search_providers using profile coordinates alone in the same turn "
        "as get_my_profile without the user's OK on that address.\n"
        "- When listing providers, format each as a markdown bullet linking the name "
        "to their profile_url (e.g. "
        "`- **[Name](profile URL)** — 4.8 ★ (123 reviews)`) "
        "so the user can click through.\n"
        "- By default, present only the top 6 providers; show more only if asked.\n\n"

        "STEP 3 — OPTIONAL: PAST PROS (get_previous_jobs) — SECONDARY, AFTER SEARCH\n"
        "Only after Step 2, optionally call get_previous_jobs to augment recommendations.\n"
        "- Do NOT call get_previous_jobs before search_providers when the user is "
        "discovering or comparing pros. Search results stay primary.\n"
        "- If there are previous pros, highlight them alongside search: e.g. \"You've "
        "worked with [Name] before — they also appear in these results\" or suggest "
        "book_same_pro_again if they want that pro specifically.\n"
        "- Past pros can weight your ranking interpretation of search results "
        "(the configured search API may bias toward favorites or previous pros).\n"
        "- If the user wants to rebook a prior pro directly, use book_same_pro_again "
        "with the job_id.\n"
        "- If no previous jobs exist, omit this step — search results alone are sufficient.\n\n"

        "STEP 4 — BOOK & HAND OVER (create_booking)\n"
        "After the user picks a pro from search results (including after book_* tools) and describes the job:\n"
        "- Call create_booking with serviceProviderSlug + job_description ONLY, unless "
        "the user **explicitly confirmed a different address** in Step 1 — then pass "
        "`address` with those confirmed values so the booking matches the searched area.\n"
        "- Otherwise NEVER pass name, phone, or address — the server auto-fills from the profile.\n"
        "- Only pass name/phone/address if the user explicitly asked to change them.\n"
        "- First call with confirm_booking=false to show summary, then confirm_booking=true "
        "after user confirms.\n\n"
        "AFTER BOOKING — MANDATORY HANDOVER (no exceptions):\n"
        "When create_booking succeeds, you MUST provide ALL of the following. This is "
        "the most critical part of the experience — a graceful handover to the configured app "
        "is essential:\n"
        "1. Use the booking_success_message from the tool response VERBATIM.\n"
        f"2. Include the configured app link when available: {APP_LINK or '[not configured]'}\n"
        "3. ALWAYS include the provider's profile link from provider_profile_url.\n"
        "4. Explain the next steps clearly:\n"
        "   - Your pro has been notified and will reach out shortly\n"
        "   - Use the configured app to chat with your pro, share photos/videos of the job, "
        "coordinate scheduling, review estimates, and pay securely\n"
        "   - You can also chat with your pro directly through their profile page\n"
        "5. Do not omit configured handoff links or next steps. Never give a brief "
        "'booking confirmed' without the full handover.\n\n"

        "=== GENERAL RULES ===\n\n"
        "ROUTING ORDER (discovery flow): get_my_profile -> **user confirms service "
        "address** -> find_* / book_* / search_providers -> optional get_previous_jobs after search -> "
        "details/reviews -> create_booking.\n"
        "SERVICE ROUTING: handyman -> find_handyman (discover) or book_handyman (book intent); "
        "HVAC -> find_hvac / book_hvac; plumber -> find_plumber / book_plumber; electrician -> "
        "find_electrician / book_electrician; renovation -> find_renovation / book_renovation. "
        "book_* tools search first, then ask which pro to book, then create_booking. Use "
        "search_providers / create_booking for all other services.\n"
        "Other routes: book_same_pro_again -> get_booking_status -> get_provider_details "
        "-> get_provider_reviews -> create_booking (explicit confirmation only) "
        "-> find_* / book_* / search_providers.\n"
        "- For rehire/same-pro requests, skip search and route to book_same_pro_again.\n"
        "- For booking-status requests, route to get_booking_status.\n"
        "- If provider details or trust signals are requested, call get_provider_details "
        "and/or get_provider_reviews.\n\n"
        "COVERAGE: Use only the configured provider API's coverage. Never invent regional "
        "coverage limits. If a search returns no results, suggest a nearby city or "
        "different service term — do NOT claim the area is not served.\n"
        "- Never recommend competitor marketplaces (Angi, Thumbtack, HomeAdvisor, etc.).\n\n"
        "LOCATION FORMAT: search_providers.location must be ONLY \"City, State\" or a "
        "5-digit ZIP. Never pass a street address, formattedAddress, or address1. "
        "Prefer the search_location field from get_my_profile when present.\n\n"
        "PRODUCT PRESENTATION: Describe only capabilities and integrations returned by "
        "the configured APIs. Do not claim review sources, payments, or app features "
        "that the operator has not configured."
    ),
    json_response=True,
    stateless_http=True,
    host="0.0.0.0",
)


_GET_MY_PROFILE_DESCRIPTION = (
    "Use this when starting any find, search, compare, or book flow. Returns the "
    "authenticated homeowner profile from the configured identity integration (read-only). Call before asking "
    "for ZIP/city and before search_providers or create_booking.\n\n"
    "Returns GetMyProfileResult (structured JSON):\n"
    '- status (string, required): "ok" or "error"\n'
    "- name (string|null): homeowner full name when status is ok\n"
    "- phone (string|null): homeowner phone when status is ok\n"
    "- address (object|null): service street address with address1, address2, city, "
    "region, postalCode, country, formattedAddress\n"
    '- search_location (string|null): "City, ST" or 5-digit ZIP for search_providers.location '
    "(after user confirms address; never the street line)\n"
    "- message (string|null): error explanation when status is error\n\n"
    "After calling, show the saved address and get explicit user confirmation before search_providers."
)


@mcp.tool(
    name="get_my_profile",
    title="Get my profile",
    description=_GET_MY_PROFILE_DESCRIPTION,
    annotations={
        "title": "Get my profile",
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
    structured_output=True,
)
async def get_my_profile_mcp() -> GetMyProfileResult:
    """Return authenticated homeowner profile (see tool description for GetMyProfileResult fields)."""
    if (denied := _require_auth()) is not None:
        return GetMyProfileResult(status="error", message=denied["message"])
    profile = current_ho_profile.get()
    if not profile:
        return GetMyProfileResult(
            status="error",
            message="No authenticated homeowner profile found. The user may need to reconnect their account.",
        )

    name = str(profile.get("name") or profile.get("ho_name") or "").strip()
    phone = str(profile.get("phone") or profile.get("ho_phone") or "").strip()
    address = _normalize_address(profile.get("address") or profile.get("ho_address"))
    if address and (
        not address.get("city")
        or not address.get("region")
        or not address.get("postalCode")
    ):
        lookup_text = str(address.get("formattedAddress") or address.get("address1") or "").strip()
        enriched = await _geocode_address(lookup_text)
        if enriched:
            for key, value in enriched.items():
                if value and not address.get(key):
                    address[key] = value
    if address and not address.get("formattedAddress"):
        formatted = _build_formatted_address(
            str(address.get("address1") or ""),
            str(address.get("address2") or ""),
            str(address.get("city") or ""),
            str(address.get("region") or ""),
            str(address.get("postalCode") or ""),
            str(address.get("country") or ""),
        )
        if formatted:
            address["formattedAddress"] = formatted
    search_location = _search_location_from_address(address)
    address_model = HomeownerAddress.model_validate(address) if address else None

    return GetMyProfileResult(
        status="ok",
        name=name or None,
        phone=phone or None,
        address=address_model,
        search_location=search_location,
    )


@mcp.tool(
    name="search_providers",
    annotations={
        "title": "Search providers",
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)
async def search_providers_mcp(
    query: Annotated[
        str,
        Field(
            description=(
                "Service keyword for non-top categories (e.g. cleaning, landscaping, roofing). "
                "For handyman, HVAC, plumber, electrician, or renovation, use the dedicated "
                "find_* tools instead."
            ),
            min_length=1,
        ),
    ],
    location: SearchLocation,
    page: int = 1,
    limit: int = 6,
) -> Dict[str, Any]:
    """Search pros by job type and location for services outside the top five categories (handyman, HVAC, plumber, electrician, renovation). For those five, use find_handyman, find_hvac, find_plumber, find_electrician, or find_renovation instead. Only call AFTER the user confirms the service address from get_my_profile (or supplied a location if profile lacked one). Pass only city+state or ZIP — use the search_location field from get_my_profile when present; never a full street address.

    MCP hints: readOnlyHint=true; destructiveHint=false; openWorldHint=true (results depend on the configured search API)."""
    return await _search_providers_response(query=query, location=location, page=page, limit=limit)


@mcp.tool(
    name="get_provider_details",
    annotations={
        "title": "Get provider details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)
async def get_provider_details_mcp(
    slug: str,
) -> Dict[str, Any]:
    """Fetch the full profile for a provider by slug; call this when the user wants details on a specific pro.

    MCP hints: readOnlyHint=true; destructiveHint=false; openWorldHint=true (live provider API)."""
    result = await get_provider_details(slug=slug)
    if isinstance(result, dict) and "error" in result:
        return result
    return {
        **result,
        "structuredContent": {
            "view": "provider_profile",
            **result,
        },
        "_meta": {"ui": {"resourceUri": "ui://provider_profile/app"}},
    }


@mcp.tool(
    name="get_provider_reviews",
    annotations={
        "title": "Get provider reviews",
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)
async def get_provider_reviews_mcp(
    slug: str,
    page: int = 1,
    page_size: int = 5,
) -> Dict[str, Any]:
    """Return review data for a provider by slug; call this when the user asks about a pro's reputation or past work.

    MCP hints: readOnlyHint=true; destructiveHint=false; openWorldHint=true (live reviews API)."""
    result = await get_provider_reviews(slug=slug, page=page, page_size=page_size)
    if isinstance(result, dict) and "error" in result:
        return result
    return {
        **result,
        "structuredContent": {
            "view": "provider_reviews",
            **result,
        },
        "_meta": {"ui": {"resourceUri": "ui://provider_reviews/app"}},
    }


@mcp.tool(
    name="create_booking",
    annotations={
        "title": "Create booking",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def create_booking_mcp(
    serviceProviderSlug: str,
    job_description: str,
    name: Annotated[
        Optional[str],
        Field(description="Optional override of profile name; omit to use authenticated homeowner profile"),
    ] = None,
    phone: Annotated[
        Optional[str],
        Field(description="Optional override of profile phone; omit to use authenticated homeowner profile"),
    ] = None,
    address: Annotated[
        Optional[HomeownerAddressInput],
        Field(
            description=(
                "Optional street-level address override. Omit to use the authenticated homeowner "
                "profile address. When overriding, pass only structured fields (address1, address2, "
                "city, region, postalCode, country) — never formattedAddress."
            ),
        ),
    ] = None,
    source: str = "AI Assistant",
    location: Annotated[
        Optional[BookingLocationInput],
        Field(
            description=(
                "Optional geocoding hint when address lacks coordinates. Omit in normal flows "
                "(profile address is used). When needed, pass exactly one of: lat+lng, zip, or "
                'text (e.g. {"text": "Alexandria, VA"}).'
            ),
        ),
    ] = None,
    confirm_booking: Annotated[
        bool,
        Field(
            description=(
                "false (default): return booking_summary for user review; does NOT submit. "
                "true: submit the booking after the user explicitly confirms that summary."
            ),
        ),
    ] = False,
    idempotency_key: Annotated[
        Optional[str],
        Field(
            description=(
                "Optional client-generated retry key for a confirmed booking. Reuse the same key "
                "when retrying after a timeout so the operator can return the original result."
            ),
            max_length=128,
        ),
    ] = None,
) -> Dict[str, Any]:
    """Submit a booking for any service category. Name, phone, and address are AUTO-FILLED from the authenticated homeowner profile — do NOT ask the user for them. Only collect job_description and serviceProviderSlug unless the user confirmed a different address in chat (then pass address override with structured fields only, not formattedAddress). Call confirm_booking=false first to preview, then confirm_booking=true only after explicit user confirmation.

    MCP hints: readOnlyHint=false (creates a booking when confirm_booking=true); destructiveHint=false (not an MCP-style irreversible delete); openWorldHint=true; idempotentHint=false unless the same idempotency_key is reused."""
    if (denied := _require_auth()) is not None:
        _raise_tool_error(denied)
    result = await _create_booking_impl(
        serviceProviderSlug=serviceProviderSlug,
        job_description=job_description,
        name=name,
        phone=phone,
        address=address,
        source=source,
        location=location,
        confirm_booking=confirm_booking,
        idempotency_key=idempotency_key,
    )
    return _raise_if_write_failed(result)


async def _create_booking_impl(
    *,
    serviceProviderSlug: str,
    job_description: str,
    name: Optional[str] = None,
    phone: Optional[str] = None,
    address: Optional[HomeownerAddressInput] = None,
    source: str = "AI Assistant",
    location: Optional[BookingLocationInput] = None,
    confirm_booking: bool = False,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    profile = current_ho_profile.get() or {}
    profile_name = str(profile.get("name") or profile.get("ho_name") or "").strip()
    profile_phone = str(profile.get("phone") or profile.get("ho_phone") or "").strip()
    profile_address = _normalize_address(profile.get("address") or profile.get("ho_address"))

    effective_name = (name or profile_name).strip() if (name or profile_name) else ""
    effective_phone = (phone or profile_phone).strip() if (phone or profile_phone) else ""
    address_override = address.model_dump(exclude_none=True) if address else {}
    effective_address: Dict[str, Any] = (
        _normalize_address(address_override) if address_override else dict(profile_address)
    )

    if not confirm_booking:
        provider = await get_provider_details(slug=serviceProviderSlug)
        provider_name = provider.get("name") if isinstance(provider, dict) else None
        return {
            "status": "confirmation_required",
            "message": "Booking not submitted yet. The homeowner profile is pre-filled (see below). Show this summary and require explicit confirmation before calling create_booking with confirm_booking=true. Do NOT ask the user for name, phone, or address — they are already filled.",
            "booking_summary": {
                "provider_slug": serviceProviderSlug,
                "provider_name": provider_name or serviceProviderSlug,
                "homeowner_name": effective_name or "(will be filled from profile)",
                "homeowner_phone": effective_phone or "(will be filled from profile)",
                "address": effective_address or {"note": "will be filled from profile"},
                "service_type": provider.get("primary_service") if isinstance(provider, dict) else None,
            },
            "required_action": "Set confirm_booking=true after the user confirms. Do NOT re-ask for name, phone, or address.",
        }

    if not effective_name:
        return {
            "status": "failed",
            "message": "Homeowner name is missing. Ask the user for their name.",
            "error_code": "VALIDATION_ERROR",
        }
    if not effective_phone:
        return {
            "status": "failed",
            "message": "Homeowner phone is missing. Ask the user for their phone number.",
            "error_code": "VALIDATION_ERROR",
        }
    if not effective_address.get("address1"):
        return {
            "status": "failed",
            "message": "Street address (address1) is required. Ask the user for their full street address.",
            "error_code": "VALIDATION_ERROR",
        }


    # Soft validation: log if key address fields are missing, but still proceed.
    # This helps diagnose cases where downstream systems receive incomplete or odd addresses.
    missing_fields = [
        field
        for field in ("city", "region", "postalCode")
        if not (effective_address.get(field) and str(effective_address.get(field)).strip())
    ]
    if missing_fields:
        import logging  # Local import to avoid any potential circular imports

        logger = logging.getLogger("nimbus-mcp.mcp_server")
        logger.warning(
            "create_booking_mcp called with missing address fields: %s",
            ", ".join(missing_fields),
        )

    args: Dict[str, Any] = {
        "serviceProviderSlug": serviceProviderSlug,
        "name": effective_name,
        "phone": effective_phone,
        "job_description": job_description,
        "address": effective_address,
        "source": source,
    }
    if idempotency_key:
        args["idempotency_key"] = idempotency_key.strip()
    if location:
        args["location"] = location.model_dump(exclude_none=True)
    result = await create_booking(args)

    # Put post-booking user guidance at top-level so assistants reliably surface it.
    # Also strip technical IDs to keep responses user-friendly.
    result.pop("job_id", None)
    result.pop("booking_id", None)
    if result.get("status") == "created":
        provider_profile_url = (
            f"{SITE_BASE_URL.rstrip('/')}/pro/{serviceProviderSlug}"
            if SITE_BASE_URL
            else ""
        )
        result["provider_profile_url"] = provider_profile_url
        result["app_link"] = APP_LINK
        result["booking_success_message"] = (
            "Booking created successfully. "
            "Your pro has been notified and will reach out shortly. "
            + (
                f"Track and manage your job in the configured app: {APP_LINK}. "
                if APP_LINK
                else "Track and manage your job through the operator's configured channels. "
            )
            + (
                f"You can also view and chat with your pro here: {provider_profile_url}."
                if provider_profile_url
                else ""
            )
        )

    if result.get("status") == "created" and "error_code" not in result:
        return {
            **result,
            "structuredContent": {
                "view": "booking_confirmation",
                **result,
            },
            "_meta": {"ui": {"resourceUri": "ui://booking_confirmation/app"}},
        }
    return result


@mcp.tool(
    name="get_previous_jobs",
    annotations={"title": "Get previous jobs", "readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
)
async def get_previous_jobs_mcp() -> Dict[str, Any]:
    """Load the authenticated homeowner's past and active jobs. For pro discovery, call search_providers first; use this as a secondary step to mention past pros alongside search results (or when the user asks about job history or status).

    MCP hints: readOnlyHint=true; destructiveHint=false; openWorldHint=true (live jobs/history API)."""
    if (denied := _require_auth()) is not None:
        return denied
    result = await get_previous_jobs()
    if isinstance(result, dict) and "error" in result:
        return result
    return {
        **result,
        "structuredContent": {
            "view": "job_history",
            **result,
        },
        "_meta": {"ui": {"resourceUri": "ui://job_history/app"}},
    }


@mcp.tool(
    name="get_booking_status",
    annotations={"title": "Get booking status", "readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
)
async def get_booking_status_mcp(booking_id: str) -> Dict[str, Any]:
    """Return current status of a booking (confirmed, en route, completed, etc.); call this when the user asks about an existing booking.

    MCP hints: readOnlyHint=true; destructiveHint=false; openWorldHint=true (live status API)."""
    if (denied := _require_auth()) is not None:
        return denied
    result = await get_booking_status(booking_id=booking_id)
    if isinstance(result, dict) and "error" in result:
        return result
    return {
        **result,
        "structuredContent": {
            "view": "booking_status",
            **result,
        },
        "_meta": {"ui": {"resourceUri": "ui://booking_confirmation/app"}},
    }


@mcp.tool(
    name="book_same_pro_again",
    annotations={"title": "Book same pro again", "readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
)
async def book_same_pro_again_mcp(
    job_id: Annotated[
        str | int,
        Field(description="Job ID from get_previous_jobs for the prior booking to rehire"),
    ],
    job_description: Annotated[
        Optional[str],
        Field(description="Description of the new work; omit to reuse the prior job description"),
    ] = None,
    name: Annotated[
        Optional[str],
        Field(description="Optional name override; omit to use authenticated homeowner profile"),
    ] = None,
    phone: Annotated[
        Optional[str],
        Field(description="Optional phone override; omit to use authenticated homeowner profile"),
    ] = None,
    address: Annotated[
        Optional[HomeownerAddressInput],
        Field(
            description=(
                "Optional street-level address override. Omit to use profile or prior-job address. "
                "Pass structured fields only (address1, city, region, postalCode, etc.) — "
                "never formattedAddress."
            ),
        ),
    ] = None,
    location: Annotated[
        Optional[BookingLocationInput],
        Field(
            description=(
                "Optional geocoding hint when address lacks coordinates. Omit in normal flows. "
                "When needed, pass exactly one of: lat+lng, zip, or text."
            ),
        ),
    ] = None,
    source: str = "AI Assistant",
    confirm_booking: Annotated[
        bool,
        Field(
            description=(
                "false (default): return a rebooking preview; does NOT submit. "
                "true: submit after explicit homeowner confirmation."
            ),
        ),
    ] = False,
    idempotency_key: Annotated[
        Optional[str],
        Field(
            description=(
                "Optional client-generated retry key for a confirmed rebooking. Reuse the same key "
                "when retrying after a timeout."
            ),
            max_length=128,
        ),
    ] = None,
) -> Dict[str, Any]:
    """Book the same provider the homeowner used for a prior job, by job_id from get_previous_jobs. Name, phone, and address default from the authenticated profile — only pass overrides when the user explicitly changes them.

    MCP hints: readOnlyHint=false (submits a rehire/booking request); destructiveHint=false; openWorldHint=true (live booking API)."""
    if (denied := _require_auth()) is not None:
        _raise_tool_error(denied)

    job_id_text = str(job_id).strip()

    if not confirm_booking:
        jobs_result = await get_previous_jobs()
        if isinstance(jobs_result, dict) and jobs_result.get("error"):
            _raise_tool_error(jobs_result)
        match = next(
            (
                job
                for job in jobs_result.get("jobs", [])
                if str(job.get("id") or "").strip() == job_id_text
            ),
            None,
        )
        if not match:
            _raise_tool_error(
                {
                    "status": "error",
                    "error_code": "JOB_NOT_FOUND",
                    "message": "Previous job not found.",
                }
            )
        provider = match.get("service_provider") or {}
        profile = current_ho_profile.get() or {}
        profile_name = str(profile.get("name") or profile.get("ho_name") or "").strip()
        profile_phone = str(profile.get("phone") or profile.get("ho_phone") or "").strip()
        profile_address = _normalize_address(profile.get("address") or profile.get("ho_address"))
        source_name = str(match.get("name") or match.get("ho_name") or "").strip()
        source_phone = str(match.get("phone") or match.get("ho_phone") or "").strip()
        source_address = _normalize_address(match.get("address"))
        return {
            "status": "preview",
            "message": "Rebooking preview ready. Call again with confirm_booking=true after approval.",
            "booking_summary": {
                "job_id": job_id_text,
                "provider_slug": provider.get("slug"),
                "provider_name": provider.get("full_name") or provider.get("name") or "Provider",
                "job_description": job_description or match.get("job_description"),
                "homeowner_name": name or profile_name or source_name,
                "homeowner_phone": phone or profile_phone or source_phone,
                "address": (
                    _normalize_address(address.model_dump(exclude_none=True))
                    if address
                    else profile_address or source_address
                ),
            },
            "required_action": "Set confirm_booking=true after the user confirms.",
        }

    args: Dict[str, Any] = {
        "job_id": job_id_text,
        "source": source,
    }
    if job_description is not None:
        args["job_description"] = job_description
    if name is not None:
        args["name"] = name
    if phone is not None:
        args["phone"] = phone
    if idempotency_key:
        args["idempotency_key"] = idempotency_key.strip()
    if address is not None:
        args["address"] = _normalize_address(address.model_dump(exclude_none=True))
    if location is not None:
        args["location"] = location.model_dump(exclude_none=True)

    result = await book_same_pro_again(args)
    if isinstance(result, dict) and "error" in result:
        _raise_tool_error(result)
    if isinstance(result, dict) and result.get("status") == "created" and "error_code" not in result:
        return {
            **result,
            "structuredContent": {
                "view": "booking_confirmation",
                **result,
            },
            "_meta": {"ui": {"resourceUri": "ui://booking_confirmation/app"}},
        }
    return _raise_if_write_failed(result)


@mcp.tool(
    name="cancel_booking",
    annotations={
        "title": "Cancel booking",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def cancel_booking_mcp(
    job_id: Annotated[str | int, Field(description="Booking ID from get_previous_jobs")],
    reason: Annotated[
        str,
        Field(description="Short homeowner-provided cancellation reason", min_length=3),
    ],
    confirm_cancellation: Annotated[
        bool,
        Field(
            description=(
                "false (default): preview without changing the booking; true: cancel only "
                "after the homeowner explicitly confirms"
            )
        ),
    ] = False,
) -> Dict[str, Any]:
    """Preview, then cancel, one of the authenticated homeowner's bookings."""

    if (denied := _require_auth()) is not None:
        _raise_tool_error(denied)
    job_id_text = str(job_id).strip()
    jobs_result = await get_previous_jobs()
    if isinstance(jobs_result, dict) and jobs_result.get("error"):
        _raise_tool_error(jobs_result)
    match = next(
        (
            job
            for job in jobs_result.get("jobs") or []
            if str(job.get("id") or "").strip() == job_id_text
        ),
        None,
    )
    if not match:
        _raise_tool_error(
            {
                "status": "failed",
                "message": "Booking not found for this homeowner.",
                "error_code": "BOOKING_NOT_FOUND",
            }
        )
    if not confirm_cancellation:
        return {
            "status": "confirmation_required",
            "message": "Cancellation not submitted. Ask the homeowner to confirm this summary.",
            "cancellation_summary": {
                "job_id": job_id_text,
                "provider": match.get("service_provider"),
                "job_description": match.get("job_description"),
                "reason": reason,
            },
            "required_action": "Set confirm_cancellation=true after explicit approval.",
        }
    result = await cancel_booking({"job_id": job_id_text, "reason": reason})
    return _raise_if_write_failed(result)


def _make_find_service_handler(service_query: str):
    async def find_handler(
        location: SearchLocation,
        page: int = 1,
        limit: int = 6,
    ) -> Dict[str, Any]:
        return await _search_providers_response(
            query=service_query,
            location=location,
            page=page,
            limit=limit,
        )

    return find_handler


def _make_book_service_handler(service_query: str, label: str):
    async def book_handler(
        location: SearchLocation,
        page: int = 1,
        limit: int = 6,
    ) -> Dict[str, Any]:
        return await _search_providers_response(
            query=service_query,
            location=location,
            page=page,
            limit=limit,
            next_step=(
                f"Show the {label} providers above and ask the user which pro they would like to book "
                f"and what work they need done. After they choose, call create_booking with "
                f"serviceProviderSlug and job_description (confirm_booking=false first, then true "
                f"after they approve the summary)."
            ),
        )

    return book_handler


def _register_popular_service_tools() -> None:
    """Register find_* and book_* wrappers for the top five service categories."""
    search_annotations = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    }

    for service_key, spec in _POPULAR_SERVICES.items():
        query = spec["query"]
        label = spec["label"]
        find_name = f"find_{service_key}"
        book_name = f"book_{service_key}"

        find_handler = _make_find_service_handler(query)
        find_handler.__name__ = f"{find_name}_mcp"
        find_handler.__doc__ = (
            f"Find pros for {spec['find_phrase']}, including {spec['symptoms']}. Service category is prefilled "
            f"as '{query}' — pass only location (city+state or ZIP from get_my_profile.search_location "
            f"after user confirms address). Prefer this over search_providers when the user needs "
            f"{spec['find_phrase']}.\n\n"
            "MCP hints: readOnlyHint=true; destructiveHint=false; openWorldHint=true."
        )

        mcp.tool(
            name=find_name,
            title=f"Find {label}",
            description=(
                f"Use when the user wants to find, search, or compare {label} professionals, "
                f"including {spec['symptoms']}. "
                f"Equivalent to search_providers(query='{query}', location=...). Only call after "
                "the user confirms the service address from get_my_profile."
            ),
            annotations={"title": f"Find {label}", **search_annotations},
        )(find_handler)

        book_handler = _make_book_service_handler(query, label)
        book_handler.__name__ = f"{book_name}_mcp"
        book_handler.__doc__ = (
            f"Start a {label} booking flow for requests such as {spec['symptoms']}: search for {spec['book_phrase']} pros (same as "
            f"search_providers with query='{query}'), then ask the user which pro they want to book. "
            f"Pass only location after address confirmation. After results, follow next_step in the "
            f"response and use create_booking to submit.\n\n"
            "MCP hints: readOnlyHint=true; destructiveHint=false; openWorldHint=true."
        )

        mcp.tool(
            name=book_name,
            title=f"Book {label}",
            description=(
                f"Use when the user wants to book a {label}, including {spec['symptoms']} — runs search first (query='{query}' "
                f"prefilled), then you must ask which pro they would like to book. Equivalent to "
                f"find_{service_key} plus a booking follow-up. Only call create_booking after the "
                f"user picks a pro and describes the job."
            ),
            annotations={"title": f"Book {label}", **search_annotations},
        )(book_handler)


_register_popular_service_tools()


@mcp.resource("ui://providers/app", mime_type="text/html;profile=mcp-app")
async def providers_resource() -> str:
    return _read_ui_file("providers.html")


@mcp.resource("ui://provider_profile/app", mime_type="text/html;profile=mcp-app")
async def provider_profile_resource() -> str:
    return _read_ui_file("provider_profile.html")


@mcp.resource("ui://provider_reviews/app", mime_type="text/html;profile=mcp-app")
async def provider_reviews_resource() -> str:
    return _read_ui_file("provider_reviews.html")


@mcp.resource("ui://job_history/app", mime_type="text/html;profile=mcp-app")
async def job_history_resource() -> str:
    return _read_ui_file("job_history.html")


@mcp.resource("ui://booking_confirmation/app", mime_type="text/html;profile=mcp-app")
async def booking_confirmation_resource() -> str:
    return _read_ui_file("booking_confirmation.html")


install_tool_monitor(mcp)
