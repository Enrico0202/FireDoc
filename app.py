#!/usr/bin/env python3
"""
fortigate-config-web — Web UI for fgdoc.py
============================================
Upload a FortiGate .conf file, get back a rendered HTML report.
All processing in memory — no files saved to disk.
"""

import os
import sys
import json
import hmac
from pathlib import Path
from datetime import datetime, timezone

from flask import (
    Flask, request, render_template,
    make_response, jsonify, session, redirect, url_for,
)

# Make fgdoc.py importable
REPO_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

from fgdoc import process_config
from diff import diff_configs
from renderers import build_diff
from yaml_config import yaml_raw_to_conf, detect_format
from settings import load_settings, save_settings, SETTINGS_PATH, SECTION_LABELS
from findings import FINDER_CATALOG, SEVERITIES
import oidc

# ── First-run credential bootstrap ────────────────────────────────────────────
# SECRET_KEY / ADMIN_PASSWORD / API_KEY can be supplied via env (.env). Anything
# unset is generated ONCE on first run, stored next to settings.json on the
# settings volume, and printed to the container logs. Env always wins; on later
# runs the stored values are loaded silently.
import secrets
import time

_ADMIN_PW_ENV = "ADMIN" + "_PASS" + "WORD"
_CRED_PATH = os.path.join(os.path.dirname(SETTINGS_PATH) or ".", "credentials.json")

# (env name, credential file field, generator, display label)
_CRED_SPECS = [
    ("SECRET_KEY", "secret_key", lambda: secrets.token_urlsafe(32), "Secret key"),
    (_ADMIN_PW_ENV, "admin_password", lambda: secrets.token_urlsafe(12), "Admin password"),
    ("API_KEY", "api_key", lambda: secrets.token_hex(32), "API key"),
]


def _read_credentials():
    try:
        with open(_CRED_PATH) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _bootstrap_credentials():
    """Fill any missing SECRET_KEY / ADMIN_PASSWORD / API_KEY from (or
    generated into) the credentials file. Never raises."""
    try:
        pending = [(env, field, gen, label)
                   for env, field, gen, label in _CRED_SPECS
                   if not os.environ.get(env, "").strip()
                   and field not in _read_credentials()]
        if not pending:
            stored = _read_credentials()
            for env, field, _gen, _label in _CRED_SPECS:
                if not os.environ.get(env, "").strip() and field in stored:
                    os.environ[env] = str(stored[field]).strip()
            return
        # First run: serialize concurrent workers with an O_EXCL lock; the
        # winner generates, everyone else re-reads the file.
        lock = _CRED_PATH + ".lock"
        acquired = False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                acquired = True
                break
            except FileExistsError:
                time.sleep(0.05)
        if not acquired:
            # Lock holder died without cleaning up; take it over.
            try:
                os.unlink(lock)
            except OSError:
                pass
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                acquired = True
            except OSError:
                pass
        if acquired:
            try:
                stored = _read_credentials()
                generated = []
                for env, field, gen, label in pending:
                    if field in stored:
                        os.environ[env] = str(stored[field]).strip()
                    else:
                        value = gen()
                        stored[field] = value
                        os.environ[env] = value
                        generated.append((label, value))
                if generated:
                    tmp = _CRED_PATH + ".tmp"
                    with open(tmp, "w") as fh:
                        json.dump(stored, fh, indent=2)
                        fh.write("\n")
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, _CRED_PATH)
                    print("═" * 62, flush=True)
                    print(" FortiDoc first run — auto-generated credentials", flush=True)
                    for label, value in generated:
                        print(f"   {label:<14} {value}", flush=True)
                    print(f"   Stored in:      {_CRED_PATH}", flush=True)
                    print("   Capture them now:  docker logs fortidoc", flush=True)
                    print("═" * 62, flush=True)
            finally:
                try:
                    os.unlink(lock)
                except OSError:
                    pass
        # Final pass: fill env from the file for anything still unset (losers).
        stored = _read_credentials()
        for env, field, _gen, _label in _CRED_SPECS:
            if not os.environ.get(env, "").strip() and field in stored:
                os.environ[env] = str(stored[field]).strip()
    except Exception as exc:  # never take the app down over credentials
        print(f"FortiDoc: credential bootstrap failed ({exc}); "
              "admin/API stay disabled until configured.", flush=True)


_bootstrap_credentials()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-dev-key")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB max upload
app.config["PERMANENT_SESSION_LIFETIME"] = 86400  # admin login: 24h

# Resolved by the bootstrap above: env first, otherwise generated on first run
# and persisted next to settings.json on the settings volume.
ADMIN_PASSWORD = os.environ.get(_ADMIN_PW_ENV, "")
# API key gating the /api/v1/* automation endpoints. Empty → all /api/v1/*
# return 503 "API not configured". The interactive /upload + /diff stay open.
API_KEY = os.environ.get("API_KEY", "")


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large (max 50 MB). Split your config or remove unused sections."}), 413


@app.after_request
def no_cache_html(resp):
    """HTML pages are re-deployed often; never let the browser cache them.

    A cached page would keep serving stale JS (old upload/download logic), so
    always revalidate against the server.
    """
    if resp.headers.get("Content-Type", "").startswith("text/html"):
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": f"Internal server error: {getattr(e, '__cause__', e)}"}), 500


ALLOWED_EXT = {".conf", ".yaml", ".yml"}


def allowed_file(name: str) -> bool:
    return Path(name).suffix.lower() in ALLOWED_EXT


class UnsupportedFormat(Exception):
    """Raised when an uploaded blob is not a supported config format."""


# Shown (as a 415) when someone uploads an encrypted #FGBK backup.  These
# cannot be decrypted here: pre-7.4.4 (format v4) used a weak key derivation
# that was never adopted by this tool, and FortiOS 7.4.4+ (format v6,
# CVE-2024-21754 fix) hardened the scheme into a proprietary, undocumented
# derivation.  Re-export without "Encrypt backup" instead.
ENCRYPTED_BACKUP_ERROR = (
    "Encrypted FortiGate backups (#FGBK) are not supported: Fortinet's "
    "key derivation is undocumented (hardened in 7.4.4, CVE-2024-21754), "
    "so the password cannot be applied here. Export an unencrypted backup "
    "from the FortiGate GUI (System → Backup → Configuration, leave "
    "'Encrypt backup' off) and upload that instead."
)


def _config_to_text(raw_bytes: bytes) -> str:
    """Turn an uploaded blob into FortiOS text.

    Accepts plain .conf text or a FortiGate YAML export (converted to text).
    Encrypted ``#FGBK`` backups are rejected — see ``ENCRYPTED_BACKUP_ERROR``.
    Raises ``UnsupportedFormat`` for unrecognised formats.
    """
    fmt = detect_format(raw_bytes)
    if fmt == "encrypted":
        raise UnsupportedFormat(ENCRYPTED_BACKUP_ERROR)
    if fmt == "conf":
        return raw_bytes.decode("utf-8", errors="replace")
    if fmt == "yaml":
        return yaml_raw_to_conf(raw_bytes.decode("utf-8", errors="replace"))
    raise UnsupportedFormat(
        "Unrecognised config format. Upload a FortiGate .conf or .yaml file."
    )


@app.route("/", methods=["GET"])
def index():
    return render_template("landing.html")

@app.route("/report", methods=["GET"])
def report_page():
    return render_template("generator.html")

@app.route("/diff", methods=["GET"])
def diff_page():
    return render_template("diff_page.html")


@app.route("/docs", methods=["GET"])
def docs_page():
    return render_template("docs.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "config" not in request.files:
        return jsonify({"error": "No file selected."}), 400

    file = request.files["config"]
    if not file or not file.filename:
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(file.filename):
        exts = ", ".join(sorted(ALLOWED_EXT))
        return jsonify({"error": f"Invalid file type. Accepted: {exts}"}), 400

    # Read file content into memory
    try:
        raw_bytes = file.read()
    except Exception as e:
        return jsonify({"error": f"Could not read file: {e}"}), 400

    # Detect format (conf / yaml / encrypted) and normalise to FortiOS text.
    try:
        raw = _config_to_text(raw_bytes)
    except UnsupportedFormat as e:
        return jsonify({"error": str(e)}), 415
    except Exception as e:
        return jsonify({"error": f"Could not parse config: {e}"}), 422

    # Full pipeline: parse → extract → compute findings → usage counts → render
    # Settings are read per-request: an admin change applies to the next report.
    settings = load_settings()
    try:
        meta = {
            "client": settings.get("client", ""),
            "prepared_by": settings.get("prepared_by", ""),
        }
        data, html = process_config(raw, meta, settings=settings)
    except Exception as e:
        return jsonify({"error": f"Config parsing failed: {e}"}), 422

    # Return the HTML directly in the browser
    response = make_response(html)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response


@app.route("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.route("/api/v1/health")
def api_health():
    """API health probe — no key required, so the workflow can tell
    "reachable but API not configured" (api_configured=false) apart
    from "up and ready"."""
    return {
        "status": "ok",
        "version": "2.0.0",
        "api_configured": bool(API_KEY),
    }


# ══════════════════════════════════════════════════════════════════════════
# /api/v1 — automation API
# Called by the external monthly workflow (config acquisition, scheduling,
# storage and delivery all live OUTSIDE FireDoc). Three endpoints:
#   POST /api/v1/report          → audit report as a downloadable HTML file
#   POST /api/v1/diff            → diff report as a downloadable HTML file
#   POST /api/v1/diff/summary    → same, JSON
# Auth: X-API-Key header (API_KEY env var). No key configured → 503.
# ══════════════════════════════════════════════════════════════════════════

def _api_key_ok():
    """API gate. Returns (ok: bool, error_response | None)."""
    if not API_KEY:
        return False, (jsonify({"error": "API not configured"}), 503)
    if request.headers.get("X-API-Key") != API_KEY:
        return False, (jsonify({"error": "Invalid or missing API key"}), 401)
    return True, None




def _diff_summary(data: dict) -> dict:
    """Machine-readable summary of a config diff (JSON twin of the HTML)."""
    return {
        "type": "diff",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname_a": data.get("hostname_a"),
        "hostname_b": data.get("hostname_b"),
        "version_a": data.get("version_a"),
        "version_b": data.get("version_b"),
        "summary": data.get("summary", {}),
        "sections": [{"id": s["id"], "title": s["title"], "count": s["count"]}
                     for s in data.get("sections", [])],
    }


def _process_report():
    """Mirror /upload's pipeline. Returns (data, html, error_response)."""
    if "config" not in request.files:
        return None, None, (jsonify({"error": "No file selected (field 'config')."}), 400)
    file = request.files["config"]
    if not file or not file.filename:
        return None, None, (jsonify({"error": "No file selected."}), 400)
    if not allowed_file(file.filename):
        exts = ", ".join(sorted(ALLOWED_EXT))
        return None, None, (jsonify({"error": f"Invalid file type. Accepted: {exts}"}), 400)
    try:
        raw = _config_to_text(file.read())
    except UnsupportedFormat as e:
        return None, None, (jsonify({"error": str(e)}), 415)
    except Exception as e:
        return None, None, (jsonify({"error": f"Could not parse config: {e}"}), 422)
    settings = load_settings()
    meta = {"client": settings.get("client", ""), "prepared_by": settings.get("prepared_by", "")}
    try:
        data, html = process_config(raw, meta, settings=settings)
    except Exception as e:
        return None, None, (jsonify({"error": f"Config parsing failed: {e}"}), 422)
    return data, html, None


def _process_diff():
    """Mirror /diff's pipeline. Returns (data, html, error_response)."""
    if "config_a" not in request.files or "config_b" not in request.files:
        return None, None, (jsonify({"error": "Two config files required (config_a, config_b)."}), 400)
    file_a, file_b = request.files["config_a"], request.files["config_b"]
    if not file_a or not file_a.filename or not file_b or not file_b.filename:
        return None, None, (jsonify({"error": "Both files are required."}), 400)
    if not allowed_file(file_a.filename) or not allowed_file(file_b.filename):
        exts = ", ".join(sorted(ALLOWED_EXT))
        return None, None, (jsonify({"error": f"Invalid file type. Accepted: {exts}"}), 400)
    try:
        raw_a = _config_to_text(file_a.read())
        raw_b = _config_to_text(file_b.read())
    except UnsupportedFormat as e:
        return None, None, (jsonify({"error": str(e)}), 415)
    except Exception as e:
        return None, None, (jsonify({"error": f"Could not parse config: {e}"}), 422)
    try:
        meta = {"label_a": "Before", "label_b": "After"}
        data = diff_configs(raw_a, raw_b, meta)
        html = build_diff(data, datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC"))
    except Exception as e:
        return None, None, (jsonify({"error": f"Diff failed: {e}"}), 422)
    return data, html, None


def _download_response(html: str, filename: str):
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp, 200


@app.route("/api/v1/report", methods=["POST"])
def api_report():
    ok, err = _api_key_ok()
    if not ok:
        return err
    data, html, e = _process_report()
    if e:
        return e
    host = data.get("global", {}).get("hostname") or "fortigate"
    return _download_response(html, f"{host}_report_{datetime.now():%Y-%m}.html")



@app.route("/api/v1/diff", methods=["POST"])
def api_diff():
    ok, err = _api_key_ok()
    if not ok:
        return err
    data, html, e = _process_diff()
    if e:
        return e
    host = data.get("hostname_a") or "fortigate"
    return _download_response(html, f"{host}_diff_{datetime.now():%Y-%m}.html")


@app.route("/api/v1/diff/summary", methods=["POST"])
def api_diff_summary():
    ok, err = _api_key_ok()
    if not ok:
        return err
    data, _html, e = _process_diff()
    if e:
        return e
    return jsonify(_diff_summary(data))


@app.route("/diff", methods=["POST"])
def diff_upload():
    if "config_a" not in request.files or "config_b" not in request.files:
        return jsonify({"error": "Two config files required (config_a, config_b)."}), 400

    file_a = request.files["config_a"]
    file_b = request.files["config_b"]

    if not file_a or not file_a.filename or not file_b or not file_b.filename:
        return jsonify({"error": "Both files are required."}), 400

    if not allowed_file(file_a.filename) or not allowed_file(file_b.filename):
        exts = ", ".join(sorted(ALLOWED_EXT))
        return jsonify({"error": f"Invalid file type. Accepted: {exts}"}), 400

    try:
        raw_bytes_a = file_a.read()
        raw_bytes_b = file_b.read()
    except Exception as e:
        return jsonify({"error": f"Could not read file: {e}"}), 400

    try:
        raw_a = _config_to_text(raw_bytes_a)
        raw_b = _config_to_text(raw_bytes_b)
    except UnsupportedFormat as e:
        return jsonify({"error": str(e)}), 415
    except Exception as e:
        return jsonify({"error": f"Could not parse config: {e}"}), 422

    try:
        meta = {"label_a": "Before", "label_b": "After"}
        data = diff_configs(raw_a, raw_b, meta)
        html = build_diff(data, datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC"))
    except Exception as e:
        return jsonify({"error": f"Diff failed: {e}"}), 422

    response = make_response(html)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response


# ════════════════════════════════════════════════════════════════════════════
# Admin — single-password login + global report settings
# ════════════════════════════════════════════════════════════════════════════

def _admin_logged_in() -> bool:
    return bool(session.get("admin"))


@app.route("/admin", methods=["GET"])
def admin_page():
    settings = load_settings()
    return render_template(
        "admin.html",
        settings=settings,
        section_labels=SECTION_LABELS,
        finding_catalog=FINDER_CATALOG,
        severities=SEVERITIES,
        logged_in=_admin_logged_in(),
        admin_email=session.get("admin_email", ""),
        oidc_enabled=oidc.enabled(),
        notice=request.args.get("notice", ""),
        error=request.args.get("error", ""),
    )


@app.route("/admin/login", methods=["POST"])
def admin_login():
    if not ADMIN_PASSWORD:
        return jsonify({"error": "Admin password is not configured on this server."}), 503
    pw = request.form.get("password", "")
    if not pw or not hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode()):
        return redirect(url_for("admin_page", error="Wrong password."))
    session.permanent = True
    session["admin"] = True
    return redirect(url_for("admin_page", notice="Logged in."))


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_page"))


# ── OIDC (authentik SSO) — only active when OIDC_ENABLED=1 ──────────────────
# authorize → provider; callback → code exchange (PKCE) → admin session.
# Password login above stays as the LAN fallback / SSO-off mode.

@app.route("/oidc/login", methods=["GET"])
def oidc_login():
    return oidc.oidc_authorize()


@app.route("/oidc/callback", methods=["GET"])
def oidc_cb():
    return oidc.oidc_callback()


@app.route("/oidc/logout", methods=["GET", "POST"])
def oidc_logout():
    return oidc.oidc_logout()


@app.route("/admin/save", methods=["POST"])
def admin_save():
    if not _admin_logged_in():
        return redirect(url_for("admin_page"))
    form = request.form
    sections = {}
    for sid in SECTION_LABELS:
        sections[sid] = form.get(f"section_{sid}") == "on"

    # Per-finding overrides (only store what differs from the built-in defaults).
    overrides = {}
    for fid, _t, _d, _r, dsev, _rem in FINDER_CATALOG:
        entry = {}
        if form.get(f"finding_enabled_{fid}") != "on":
            entry["enabled"] = False
        sev = form.get(f"finding_sev_{fid}", "")
        if sev in SEVERITIES and sev != dsev:
            entry["severity"] = sev
        rem = (form.get(f"finding_rem_{fid}", "") or "").strip()
        if rem:
            entry["remediation"] = rem
        if entry:
            overrides[fid] = entry

    # Custom findings (admin-authored, always shown in reports).
    # Fields: title (finding name) + severity chips + remediation (fix text)
    # + snippet (the config lines from the uploaded file that show the issue).
    customs = []
    for i in range(int(form.get("custom_count", 0) or 0)):
        title = (form.get(f"custom_title_{i}", "") or "").strip()
        if not title:
            continue
        sev = form.get(f"custom_sev_{i}", "info")
        customs.append({
            "id": (form.get(f"custom_id_{i}", "") or f"custom-{i}").strip() or f"custom-{i}",
            "title": title,
            "description": (form.get(f"custom_desc_{i}", "") or "").strip(),
            "severity": sev if sev in SEVERITIES else "info",
            "remediation": (form.get(f"custom_rem_{i}", "") or "").strip(),
            "snippet": (form.get(f"custom_snip_{i}", "") or "").strip(),
            "pattern": (form.get(f"custom_pattern_{i}", "") or "").strip(),
            "enabled": form.get(f"custom_enabled_{i}") == "on",
        })

    settings = {
        "client": form.get("client", "").strip(),
        "prepared_by": form.get("prepared_by", "").strip(),
        "cis_enabled": form.get("cis_enabled") == "on",
        "sections": sections,
        "finding_overrides": overrides,
        "custom_findings": customs,
    }
    try:
        save_settings(settings)
    except Exception as e:
        return redirect(url_for("admin_page", error=f"Save failed: {e}"))
    return redirect(url_for("admin_page", notice="Settings saved — applies to the next report for everyone."))


@app.route("/admin/export")
def admin_export():
    """Download the current settings as a JSON file (backup / migration)."""
    if not _admin_logged_in():
        return redirect(url_for("admin_page"))
    payload = {
        "fortidoc_settings": "1",
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "settings": load_settings(),
    }
    response = make_response(json.dumps(payload, indent=2) + "\n")
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=fortidoc-settings.json"
    return response


@app.route("/admin/import", methods=["POST"])
def admin_import():
    """Replace the current settings from an exported JSON file.

    The file runs through the exact same validate+save path (`save_settings`
    → `_coerce`) as the admin form, so a partial or foreign file can never
    write anything the app itself would not produce."""
    if not _admin_logged_in():
        return redirect(url_for("admin_page"))
    f = request.files.get("settings")
    if not f or not f.filename:
        return redirect(url_for("admin_page", error="Import failed: no file selected."))
    try:
        blob = json.loads(f.stream.read().decode("utf-8-sig"))
    except Exception:
        return redirect(url_for("admin_page", error="Import failed: the file is not valid JSON."))
    if not isinstance(blob, dict):
        return redirect(url_for("admin_page", error="Import failed: not a FortiDoc settings export."))
    if isinstance(blob.get("settings"), dict):
        blob = blob["settings"]  # unwrap the export envelope
    known = {"client", "prepared_by", "cis_enabled", "sections",
             "finding_overrides", "custom_findings"}
    if not (known & set(blob)):
        return redirect(url_for("admin_page", error="Import failed: not a FortiDoc settings export."))
    try:
        save_settings(blob)
    except Exception as e:
        return redirect(url_for("admin_page", error=f"Import failed: {e}"))
    return redirect(url_for("admin_page", notice="Settings imported — applies to the next report for everyone."))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
