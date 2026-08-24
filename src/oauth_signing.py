"""Asymmetric signing helpers for OAuth access tokens and public JWKS."""

from __future__ import annotations

import base64
import hashlib
import json
from functools import lru_cache
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
_SIGNING_CONTEXT = b"nimbus-mcp/access-token-signing/v1"

# OAUTH_CLIENT_SECRET is operator-managed and must be high entropy (at least
# 32 random bytes). HKDF domain separation keeps the ES256 key distinct from
# its client-authentication and refresh-token uses while remaining stable
# across stateless instances.


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@lru_cache(maxsize=8)
def _signing_material(
    oauth_secret: str,
) -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
    if not oauth_secret:
        raise RuntimeError("OAuth access-token signing requires OAUTH_CLIENT_SECRET")

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_SIGNING_CONTEXT,
    ).derive(oauth_secret.encode("utf-8"))
    private_value = (int.from_bytes(derived, "big") % (_P256_ORDER - 1)) + 1
    private_key = ec.derive_private_key(private_value, ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    x = _base64url(public_numbers.x.to_bytes(32, "big"))
    y = _base64url(public_numbers.y.to_bytes(32, "big"))
    thumbprint_input = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": x, "y": y},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    kid = _base64url(hashlib.sha256(thumbprint_input).digest())
    return private_key, {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
    }


def access_token_jwk(oauth_secret: str) -> dict[str, str]:
    """Return the public JWK for the configured access-token signing key."""

    _, jwk = _signing_material(oauth_secret)
    return dict(jwk)


def encode_access_token(claims: dict[str, Any], oauth_secret: str) -> str:
    """Sign an OAuth access token with ES256 and a stable public key id."""

    private_key, jwk = _signing_material(oauth_secret)
    return jwt.encode(
        claims,
        private_key,
        algorithm="ES256",
        headers={"kid": jwk["kid"], "typ": "JWT"},
    )


def decode_access_token(
    token: str,
    oauth_secret: str,
    *,
    audience: str,
) -> dict[str, Any]:
    """Verify an ES256 OAuth access token for the canonical MCP audience."""

    private_key, _ = _signing_material(oauth_secret)
    return jwt.decode(
        token,
        private_key.public_key(),
        algorithms=["ES256"],
        options={"require": ["exp", "sub"]},
        audience=audience,
    )
