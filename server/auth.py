"""
server/auth.py — JWT issuance, verification, revocation, and OIDC flow.

Passwords (local mode) are stored in plaintext in server.yml (chmod 600).
Tokens use HS256; revoked JTIs are kept in memory and flushed to disk.

OIDC flow (oidc-manual / oidc-auto):
  1. oidc_authorization_url()  → build redirect URL with state+nonce
  2. oidc_exchange_code()      → exchange code for id_token, extract claims
  3. oidc_identity()           → normalised identity key from token claims
  4. oidc_display()            → raw display name from token claims
  5. oidc_authorize()          → check identity against whitelist/blocklist
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time as _time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple
from uuid import uuid4

import httpx
from jose import JWTError, jwt

from .config import OIDCConfig, ServerConfig, User

_revoked: set[str] = set()
_revoked_file: Path = Path("logs/revoked_tokens.json")

# ── OIDC state store (in-memory, short-lived) ─────────────────────────────────
# Maps state → {"nonce": str, "expires": float}
_oidc_states: dict[str, dict] = {}
_OIDC_STATE_TTL  = 300   # 5 minutes
_OIDC_MAX_STATES = 500   # cap to bound memory on unauthenticated /oidc/start spam

# ── OIDC discovery + JWKS cache ──────────────────────────────────────────────
_oidc_discovery:  Optional[dict] = None
_oidc_jwks_cache: Optional[dict] = None   # cached JWKS set {"keys": [...]}
_OIDC_JWKS_TTL   = 300                    # re-fetch after 5 minutes
_oidc_jwks_ts:    float          = 0.0    # monotonic timestamp of last fetch

# ── OIDC refresh token store (jti → refresh_token) ───────────────────────────
# Used to perform backchannel logout when the operator logs out.
_oidc_refresh_tokens: dict[str, str]   = {}
_oidc_refresh_exp:    dict[str, float] = {}   # jti → unix expiry for TTL pruning

# ── revoked token expiry index (for TTL pruning) ──────────────────────────────
# _revoked stays a set[str] (jti); this parallel dict holds the exp timestamp.
_revoked_exp: dict[str, float] = {}   # jti → unix expiry


# ── brute-force protection ────────────────────────────────────────────────────
_fail_counts:   dict[str, list[float]] = {}   # ip → list of failure timestamps
_lockout_ends:  dict[str, float]       = {}   # ip → monotonic time when lockout expires
_LOCKOUT_WINDOW = 300    # 5-minute sliding window
_LOCKOUT_THRESH = 5      # max failures before lockout
_LOCKOUT_DUR    = 60     # lockout duration in seconds


def check_rate_limit(client_ip: str) -> bool:
    """Return True if request is allowed, False if locked out."""
    now = _time.monotonic()
    # Hard lockout anchored at threshold-crossing time, not at last failure.
    if now < _lockout_ends.get(client_ip, 0.0):
        return False
    times = _fail_counts.get(client_ip, [])
    times = [t for t in times if now - t < _LOCKOUT_WINDOW]
    _fail_counts[client_ip] = times
    return True


def record_failure(client_ip: str) -> None:
    now   = _time.monotonic()
    times = _fail_counts.setdefault(client_ip, [])
    times.append(now)
    if len(times) >= _LOCKOUT_THRESH:
        # Re-arm lockout if the previous one has already expired — otherwise a
        # first lockout that elapsed naturally would leave _lockout_ends populated
        # with a stale timestamp, preventing any future lockout from being set.
        existing = _lockout_ends.get(client_ip, 0.0)
        if now >= existing:
            _lockout_ends[client_ip] = now + _LOCKOUT_DUR
        # Prune list so it doesn't grow unboundedly during active lockout.
        _fail_counts[client_ip] = times[-_LOCKOUT_THRESH:]


def record_success(client_ip: str) -> None:
    _fail_counts.pop(client_ip, None)
    _lockout_ends.pop(client_ip, None)


# ── init ──────────────────────────────────────────────────────────────────────

def init(log_dir: str) -> None:
    global _revoked_file
    _revoked_file = Path(log_dir) / "revoked_tokens.json"
    _load_revoked()


def _load_revoked() -> None:
    if not _revoked_file.exists():
        return
    raw = _revoked_file.read_text()
    data = json.loads(raw)   # raises on corrupt file — intentional: never silently drop revocations
    # MED-16: file format is now dict[jti, exp] so _revoked_exp is restored on restart.
    # Backwards-compat: accept old list[str] format and treat missing exp as inf.
    if isinstance(data, list):
        for jti in data:
            _revoked.add(jti)
            _revoked_exp[jti] = float("inf")
    else:
        for jti, exp in data.items():
            _revoked.add(jti)
            _revoked_exp[jti] = float(exp)


def _save_revoked() -> None:
    _revoked_file.parent.mkdir(parents=True, exist_ok=True)
    _revoked_file.write_text(json.dumps(_revoked_exp))


# ── local auth ────────────────────────────────────────────────────────────────

def authenticate(cfg: ServerConfig, username: str, password: str) -> Optional[User]:
    user = cfg.find_user(username)
    if user and user.password is not None and secrets.compare_digest(user.password, password):
        return user
    return None


# ── JWT ───────────────────────────────────────────────────────────────────────

def issue_token(cfg: ServerConfig, username: str, display: Optional[str] = None, oidc_refresh_token: str = "") -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=cfg.settings.jwt_expiry_hours)
    jti = str(uuid4())
    payload = {
        "sub":     username,
        "display": display or username,
        "jti":     jti,
        "iat":     now,
        "exp":     exp,
        "amr":     cfg.auth_mode,   # auth mode at issuance — validated on every request
    }
    if oidc_refresh_token:
        _oidc_refresh_tokens[jti] = oidc_refresh_token
        _oidc_refresh_exp[jti]    = exp.timestamp()
    return jwt.encode(payload, cfg.settings.jwt_secret, algorithm="HS256")


def _identity_still_valid(cfg: ServerConfig, identity: str, issued_amr: str) -> bool:
    """Check that the identity encoded in a JWT is still authorised under the
    current auth_mode.  Called on every request so a config change (e.g.
    switching from oidc-auto to local, or removing a user) takes effect
    immediately without requiring a server restart token flush.

    issued_amr is the auth_mode recorded in the JWT at issuance — if it no
    longer matches the current mode the token is rejected outright, preventing
    local tokens from being accepted under oidc-auto and vice versa."""
    if issued_amr != cfg.auth_mode:
        return False
    if cfg.auth_mode == "local":
        return cfg.find_user(identity) is not None
    if cfg.auth_mode == "oidc-manual":
        allowed = {i.lower().strip() for i in (cfg.oidc.allowed_identities if cfg.oidc else [])}
        return identity.lower().strip() in allowed
    if cfg.auth_mode == "oidc-auto":
        blocked = {i.lower().strip() for i in (cfg.oidc.blocked_identities if cfg.oidc else [])}
        return identity.lower().strip() not in blocked
    return False


def verify_token(cfg: ServerConfig, token: str) -> Optional[str]:
    """Return identity (sub) if valid and still authorised, None otherwise."""
    try:
        payload = jwt.decode(token, cfg.settings.jwt_secret, algorithms=["HS256"])
        if payload.get("jti", "") in _revoked:
            return None
        identity  = payload.get("sub")
        issued_amr = payload.get("amr", "")
        if not identity or not _identity_still_valid(cfg, identity, issued_amr):
            return None
        return identity
    except JWTError:
        return None


def verify_token_display(cfg: ServerConfig, token: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (identity, display_name) if valid and still authorised, (None, None) otherwise."""
    try:
        payload = jwt.decode(token, cfg.settings.jwt_secret, algorithms=["HS256"])
        if payload.get("jti", "") in _revoked:
            return None, None
        identity   = payload.get("sub")
        issued_amr = payload.get("amr", "")
        if not identity or not _identity_still_valid(cfg, identity, issued_amr):
            return None, None
        return identity, payload.get("display")
    except JWTError:
        return None, None


def revoke_token(cfg: ServerConfig, token: str) -> Optional[str]:
    """Revoke the token. Returns the associated OIDC refresh_token if any."""
    try:
        payload = jwt.decode(
            token, cfg.settings.jwt_secret, algorithms=["HS256"],
            options={"verify_exp": False},
        )
        jti = payload.get("jti")
        if jti:
            _revoked.add(jti)
            # Use inf if exp is absent — never prune a JTI with no known expiry.
            raw_exp = payload.get("exp")
            _revoked_exp[jti] = float(raw_exp) if raw_exp is not None else float("inf")
            _save_revoked()
            _oidc_refresh_exp.pop(jti, None)
            return _oidc_refresh_tokens.pop(jti, None)
    except JWTError:
        pass
    return None


def prune_auth_stores() -> None:
    """Remove expired entries from in-memory auth stores.

    Safe to call periodically (e.g. from a background task). A JTI in _revoked
    whose exp is in the past cannot be replayed anyway — dropping it is safe.
    """
    now      = _time.time()
    now_mono = _time.monotonic()

    expired_rev = [k for k, exp in _revoked_exp.items() if exp < now]
    for k in expired_rev:
        _revoked.discard(k)
        del _revoked_exp[k]

    expired_rt = [k for k, exp in _oidc_refresh_exp.items() if exp < now]
    for k in expired_rt:
        _oidc_refresh_tokens.pop(k, None)
        del _oidc_refresh_exp[k]

    # MED-22: purge IPs whose entire sliding window has expired
    stale_fc = [ip for ip, times in _fail_counts.items()
                if not any(now_mono - t < _LOCKOUT_WINDOW for t in times)]
    for ip in stale_fc:
        del _fail_counts[ip]

    stale_lo = [ip for ip, t in _lockout_ends.items() if now_mono >= t]
    for ip in stale_lo:
        del _lockout_ends[ip]


# ── OIDC ──────────────────────────────────────────────────────────────────────

def _oidc_discover(oidc: OIDCConfig) -> dict:
    """Fetch and cache the OIDC provider discovery document."""
    global _oidc_discovery
    if _oidc_discovery:
        return _oidc_discovery
    url = f"{oidc.provider_url}/.well-known/openid-configuration"
    try:
        r = httpx.get(url, timeout=10)
        r.raise_for_status()
        _oidc_discovery = r.json()
        return _oidc_discovery
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch OIDC discovery document from {url}: {exc}"
        ) from exc


def _oidc_jwks(oidc: OIDCConfig) -> dict:
    """Return the provider JWKS set as {"keys": [...]}, cached for _OIDC_JWKS_TTL seconds."""
    global _oidc_jwks_cache, _oidc_jwks_ts
    now = _time.monotonic()
    if _oidc_jwks_cache is not None and now - _oidc_jwks_ts < _OIDC_JWKS_TTL:
        return _oidc_jwks_cache
    disc = _oidc_discover(oidc)
    jwks_uri = disc.get("jwks_uri", "")
    if not jwks_uri:
        raise RuntimeError("OIDC discovery document missing 'jwks_uri'.")
    try:
        r = httpx.get(jwks_uri, timeout=10)
        r.raise_for_status()
        _oidc_jwks_cache = r.json()
        _oidc_jwks_ts    = now
        return _oidc_jwks_cache
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch JWKS from {jwks_uri}: {exc}") from exc


def _prune_states() -> None:
    now = _time.monotonic()
    expired = [k for k, v in _oidc_states.items() if v["expires"] < now]
    for k in expired:
        del _oidc_states[k]


def oidc_authorization_url(oidc: OIDCConfig, redirect_uri: str) -> Tuple[str, str]:
    """Build the provider authorization URL.

    Returns (url, state) where state must be stored and verified at callback.
    """
    disc  = _oidc_discover(oidc)
    auth_ep = disc.get("authorization_endpoint", "")
    if not auth_ep:
        raise RuntimeError("OIDC discovery document missing 'authorization_endpoint'.")

    _prune_states()
    if len(_oidc_states) >= _OIDC_MAX_STATES:
        raise RuntimeError("Too many pending OIDC login flows — wait for existing ones to expire and retry.")
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    _oidc_states[state] = {"nonce": nonce, "expires": _time.monotonic() + _OIDC_STATE_TTL}

    from urllib.parse import urlencode
    params = urlencode({
        "response_type": "code",
        "client_id":     oidc.client_id,
        "redirect_uri":  redirect_uri,
        "scope":         "openid email profile",
        "state":         state,
        "nonce":         nonce,
    })
    return f"{auth_ep}?{params}", state


def oidc_backchannel_logout(oidc: OIDCConfig, refresh_token: str = "") -> None:
    """Call the provider end_session endpoint server-side (no browser redirect).

    Uses refresh_token to identify the specific session to invalidate.
    Silently ignores failures — Stratum token is already revoked regardless.
    """
    try:
        disc = _oidc_discover(oidc)
        end_session_ep = disc.get("end_session_endpoint", "")
        if not end_session_ep:
            return
        data: dict = {"client_id": oidc.client_id, "client_secret": oidc.client_secret}
        if refresh_token:
            data["refresh_token"] = refresh_token
        httpx.post(end_session_ep, data=data, timeout=5)
    except Exception:
        pass


def oidc_exchange_code(oidc: OIDCConfig, code: str, state: str, redirect_uri: str) -> dict:
    """Exchange authorization code for claims dict.

    Validates state, exchanges code for tokens, returns the id_token claims.
    Raises ValueError with a user-facing message on any failure.
    """
    _prune_states()
    stored = _oidc_states.pop(state, None)
    if not stored:
        raise ValueError("Invalid or expired login session. Please try again.")
    if stored["expires"] < _time.monotonic():
        raise ValueError("Login session expired. Please try again.")

    disc     = _oidc_discover(oidc)
    token_ep = disc.get("token_endpoint", "")
    if not token_ep:
        raise ValueError("OIDC discovery document missing 'token_endpoint'.")

    try:
        r = httpx.post(token_ep, data={
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  redirect_uri,
            "client_id":     oidc.client_id,
            "client_secret": oidc.client_secret,
        }, timeout=15)
        r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise ValueError(
            f"Token exchange failed (HTTP {exc.response.status_code}). "
            "Check client_id, client_secret, and redirect_uri."
        ) from exc
    except Exception as exc:
        raise ValueError(f"Token exchange failed: {exc}") from exc

    tokens = r.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise ValueError("Provider did not return an id_token.")

    # Verify id_token signature using provider JWKS (RS256).
    # No fallback — a JWKS fetch failure is treated as an auth failure to prevent
    # network-level attacks from bypassing signature verification.
    try:
        jwks = _oidc_jwks(oidc)
        claims = jwt.decode(
            id_token,
            jwks,
            algorithms=["RS256"],
            audience=oidc.client_id,
            options={"verify_exp": True, "verify_aud": True, "verify_at_hash": False},
        )
    except RuntimeError as exc:
        raise ValueError(f"Cannot verify id_token: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"id_token signature verification failed: {exc}") from exc

    # MED-18: nonce verification is mandatory — no conditional skip
    stored_nonce = stored.get("nonce")
    if not stored_nonce or claims.get("nonce") != stored_nonce:
        raise ValueError("Nonce mismatch — possible replay attack.")

    # Also return the refresh_token so the caller can store it for backchannel logout
    claims["_refresh_token"] = tokens.get("refresh_token", "")
    return claims


def oidc_identity(oidc: OIDCConfig, claims: dict) -> str:
    """Extract and normalise the identity key from claims.

    Raises ValueError if the configured identity_claim is absent.
    """
    raw = claims.get(oidc.identity_claim)
    if not raw:
        raise ValueError(
            f"Provider did not return the '{oidc.identity_claim}' claim. "
            "Check the Keycloak realm configuration and token scopes."
        )
    return str(raw).lower().strip()


def oidc_display(oidc: OIDCConfig, claims: dict) -> str:
    """Extract the display name from claims. Falls back to identity_claim if absent."""
    raw = claims.get(oidc.display_claim)
    if raw:
        return str(raw)
    # Graceful fallback: use the raw (non-normalised) identity claim value
    return str(claims.get(oidc.identity_claim, ""))


def oidc_authorize(cfg: ServerConfig, identity: str) -> Tuple[bool, str]:
    """Check whether an identity is allowed to log in.

    Returns (allowed, reason). reason is non-empty only when denied.
    """
    oidc = cfg.oidc
    if not oidc:
        return False, "OIDC not configured."

    if cfg.auth_mode == "oidc-manual":
        allowed = [i.lower().strip() for i in oidc.allowed_identities]
        if identity not in allowed:
            return False, "Access denied: your account is not authorised."
        return True, ""

    if cfg.auth_mode == "oidc-auto":
        blocked = [i.lower().strip() for i in oidc.blocked_identities]
        if identity in blocked:
            return False, "Access denied: your account has been revoked."
        return True, ""

    return False, "Unexpected auth_mode."
