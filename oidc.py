"""Native OIDC (authorization code + PKCE) login for the FortiDoc admin UI.

Provider: authentik, per-provider issuer ``/application/o/fortidoc/``.
Enabled via env (all optional — with OIDC_ENABLED unset the app behaves
exactly as before, password login only):

  OIDC_ENABLED=1
  OIDC_CLIENT_ID=<authentik provider pkce client id>
  OIDC_CLIENT_SECRET=<unused for public PKCE clients, may be empty>
  OIDC_ISSUER=https://<your-oidc-provider>/application/o/fortidoc/
  OIDC_PUBLIC_BASE=https://<your-fortidoc-domain>   (redirect_uri host)
  OIDC_ADMIN_EMAILS=a@x.com,b@y.com   (allowlist; empty = any SSO user)

Design notes
------------
* Stateless: the OIDC ``state`` is a signed JSON blob (HMAC over
  SECRET_KEY) carrying the PKCE verifier + nonce + expiry. No shared state
  between gunicorn workers is needed, and a callback hitting any worker
  verifies it locally.
* Only stdlib (urllib) — no new dependencies in the image.
* The token/userinfo fetch functions are module-level seams so the e2e
  suite can monkey-patch them.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import redirect, request, session, url_for

STATE_TTL = 600  # seconds; code+challenge are single-use, keep it tight


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def enabled() -> bool:
    # All three required: without a client_id/issuer the SSO flow cannot work,
    # so the button stays hidden and login is password-only.
    return (
        _env("OIDC_ENABLED") == "1"
        and bool(_env("OIDC_CLIENT_ID"))
        and bool(_env("OIDC_ISSUER"))
    )


def client_id() -> str:
    return _env("OIDC_CLIENT_ID")


def client_secret() -> str:
    return _env("OIDC_CLIENT_SECRET")


def issuer() -> str:
    base = _env("OIDC_ISSUER")
    return base if base.endswith("/") else base + "/"


def public_base() -> str:
    return _env("OIDC_PUBLIC_BASE").rstrip("/")


def redirect_uri() -> str:
    return public_base() + "/oidc/callback"


def _admin_emails() -> set:
    raw = _env("OIDC_ADMIN_EMAILS")
    if not raw:
        return set()
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


def _key() -> bytes:
    # Same key as the Flask session — one server secret signs both.
    return (os.environ.get("SECRET_KEY") or "fallback-dev-key").encode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _make_state(nonce: str, code_verifier: str, next_url: str) -> str:
    payload = {"n": nonce, "v": code_verifier, "x": next_url, "t": int(time.time())}
    blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    mac = hmac.new(_key(), blob, hashlib.sha256).digest()
    return _b64url(blob) + "." + _b64url(mac)


def _parse_state(state: str):
    """Verify HMAC + freshness. Returns payload dict or None."""
    try:
        blob_b64, mac_b64 = state.split(".")
        blob = base64.urlsafe_b64decode(blob_b64 + "=" * (-len(blob_b64) % 4))
        mac = base64.urlsafe_b64decode(mac_b64 + "=" * (-len(mac_b64) % 4))
    except Exception:
        return None
    expect = hmac.new(_key(), blob, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect):
        return None
    try:
        payload = json.loads(blob)
    except Exception:
        return None
    if not isinstance(payload.get("t"), int) or time.time() - payload["t"] > STATE_TTL:
        return None
    return payload


def _pkce_pair():
    verifier = _b64url(os.urandom(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


# ── endpoint discovery ──────────────────────────────────────────────────────
# authentik serves authorize/token/userinfo on the GLOBAL /application/o/ path
# even for per_provider issuers (only issuer + jwks are per-provider). Read
# the real endpoints from the OIDC discovery document instead of guessing.
_disc_lock = __import__("threading").Lock()
_disc_cache = {}


def fetch_discovery(issuer_url):
    """GET <issuer>.well-known/openid-configuration (seam for e2e)."""
    url = issuer_url + ".well-known/openid-configuration"
    req = urllib.request.Request(url, headers={"User-Agent": "fortidoc-oidc/1"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def endpoints():
    """Resolve (authorize, token, userinfo) endpoints, cached per process.

    Sourced from the discovery document; falls back to authentik's global
    /application/o/ layout if discovery is unreachable (same values)."""
    with _disc_lock:
        ep = _disc_cache.get("endpoints")
        if ep:
            return ep
    host = issuer().split("/")[2]
    fallback = (
        f"https://{host}/application/o/authorize/",
        f"https://{host}/application/o/token/",
        f"https://{host}/application/o/userinfo/",
    )
    disc = fetch_discovery(issuer()) or {}
    ep = (
        disc.get("authorization_endpoint") or fallback[0],
        disc.get("token_endpoint") or fallback[1],
        disc.get("userinfo_endpoint") or fallback[2],
    )
    with _disc_lock:
        _disc_cache["endpoints"] = ep
    return ep


def _reset_endpoint_cache():
    with _disc_lock:
        _disc_cache.clear()


# ── fetch seams (monkey-patched by the e2e suite) ──────────────────────────

def fetch_token(token_endpoint: str, form: dict):
    """POST the authorization code exchange. Returns (response_dict, error).

    response_dict is the provider's full token response on success
    (access_token, id_token, ...) and {} on failure. error is None on success,
    else the provider's error string (or "token_exchange_failed").
    """
    body = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(
        token_endpoint, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode()), None
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode())
        except Exception:
            data = {}
        return {}, data.get("error", "token_exchange_failed")
    except Exception:
        return {}, "token_exchange_failed"


def fetch_userinfo(userinfo_endpoint: str, access_token: str):
    """GET userinfo. Returns dict or None on failure."""
    req = urllib.request.Request(
        userinfo_endpoint,
        headers={"Authorization": "***" + access_token},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def decode_id_token(id_token):
    """Decode the provider's id_token into a claims dict (best-effort).

    Accepts an already-decoded dict (tests) or a JWT string. The signature is
    NOT verified here (the token arrived over TLS from the provider in the same
    token response), but iss / aud / exp are validated against our configured
    issuer + client when present. A token that fails validation returns None so
    the caller can fall back to userinfo. Returns a claims dict (possibly
    without 'email') or None.
    """
    if id_token is None:
        return None
    if isinstance(id_token, dict):
        claims = id_token
    elif isinstance(id_token, str):
        parts = id_token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            claims = json.loads(base64.urlsafe_b64decode(payload).decode())
        except Exception:
            return None
        if not isinstance(claims, dict):
            return None
    else:
        return None

    iss = claims.get("iss")
    if iss and iss.rstrip("/") != issuer().rstrip("/"):
        return None
    aud = claims.get("aud")
    if aud:
        auds = aud if isinstance(aud, list) else [aud]
        if client_id() and client_id() not in auds:
            return None
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        return None
    return claims


# ── routes ──────────────────────────────────────────────────────────────────

def _next_arg(default="/admin"):
    nxt = urllib.parse.unquote(request.args.get("next", "") or "")
    # only allow same-app relative targets
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = default
    return nxt


def oidc_authorize():
    """Step 1: redirect to the provider's authorize endpoint (PKCE)."""
    if not enabled():
        return redirect(url_for("admin_page"))
    if session.get("admin"):
        return redirect(_next_arg())
    verifier, challenge = _pkce_pair()
    nonce = _b64url(os.urandom(12))
    session["oidc_nonce"] = nonce
    state = _make_state(nonce, verifier, _next_arg())
    params = urllib.parse.urlencode({
        "client_id": client_id(),
        "redirect_uri": redirect_uri(),
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return redirect(endpoints()[0] + "?" + params)


def oidc_callback():
    """Step 2: provider redirects back with ?code=&state=."""
    state = request.args.get("state", "") or ""
    code = request.args.get("code", "") or ""
    payload = _parse_state(state) if state else None
    if not payload or not code:
        return redirect(url_for("admin_page", error="SSO login failed: bad or expired state — try again."))
    nonce = session.pop("oidc_nonce", None)
    if nonce != payload.get("n"):
        return redirect(url_for("admin_page", error="SSO login failed: nonce mismatch — try again."))

    _, token_endpoint, userinfo_endpoint = endpoints()
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(),
        "client_id": client_id(),
        "code_verifier": payload["v"],
    }
    if client_secret():
        form["client_secret"] = client_secret()
    token_resp, err = fetch_token(token_endpoint, form)
    if err or not token_resp:
        return redirect(url_for("admin_page", error="SSO login failed: token exchange rejected."))
    access_token = token_resp.get("access_token")
    if not access_token:
        return redirect(url_for("admin_page", error="SSO login failed: token exchange rejected."))

    # Identity source 1 (primary): the id_token returned in the token response.
    # It's the canonical OIDC identity assertion and is always present when the
    # scope includes "openid" (we always request it). This avoids depending on a
    # second HTTP round-trip to /userinfo, which some provider configurations
    # reject even for a valid token (401) and would otherwise surface as a
    # "no email in identity" error.
    user = decode_id_token(token_resp.get("id_token"))

    # Identity source 2 (fallback): the userinfo endpoint, only reached when the
    # id_token was absent or carried no email.
    if not user or not user.get("email"):
        userinfo = fetch_userinfo(userinfo_endpoint, access_token)
        if userinfo and userinfo.get("email"):
            user = userinfo
        elif not user:
            user = {}

    if not user or not user.get("email"):
        return redirect(url_for("admin_page", error="SSO login failed: no email in identity — check the account."))

    email = user["email"].lower()
    allow = _admin_emails()
    if allow and email not in allow:
        return redirect(url_for("admin_page", error="SSO login failed: your account is not authorized for admin."))

    session.permanent = True
    session["admin"] = True
    session["admin_email"] = email
    session["admin_name"] = user.get("name") or email
    return redirect(url_for("admin_page", notice=f"Signed in via SSO as {email}."))


def oidc_logout():
    """Provider-side logout is best-effort; clear our session either way."""
    session.clear()
    next_url = _next_arg()
    return redirect(next_url)
