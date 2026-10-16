"""Persistent admin settings for the FortiDoc web app.

Settings live in ONE JSON file (SETTINGS_PATH env, default ./settings.json)
on a docker volume, so every gunicorn worker sees the same values and an
admin change applies to the next report for everyone — no restart needed.
Missing or corrupt file → built-in defaults, which equal the pre-admin
behaviour (everything on, no client/prepared_by).
"""
import json
import os

from findings import FINDER_CATALOG, SEVERITIES

SETTINGS_PATH = os.environ.get("SETTINGS_PATH", "settings.json")

# Canonical filterable sections: id → label, in report order.
# 'overview' is ALWAYS rendered; 'findings' follows the CIS toggle.
SECTION_LABELS = {
    "admins": "Administrators",
    "ha": "HA Cluster",
    "snmp": "SNMP",
    "interfaces": "Interfaces",
    "vlans": "VLAN Interfaces",
    "dhcp": "DHCP Servers",
    "routes": "Static Routes",
    "policy_routes": "Policy Routes",
    "layer3": "Layer 3 & SD-WAN",
    "addresses": "Address Objects",
    "groups": "Address Groups",
    "services": "Custom Services",
    "service_groups": "Service Groups",
    "zones": "Zones",
    "policies": "Firewall Policies",
    "nat": "NAT / VIPs",
    "shapers": "Traffic Shaping",
    "vpn": "S2S IPsec Tunnels",
    "vpn_ra": "IPsec Remote Access",
    "sslvpn": "SSL-VPN Remote Access",
    "certs": "Certificates",
}


def _defaults() -> dict:
    return {
        "client": "",
        "prepared_by": "",
        "cis_enabled": True,
        "sections": {sid: True for sid in SECTION_LABELS},
        # per-finding admin overrides: id → {enabled, severity, remediation}
        # (only stores what the admin actually changed — defaults = built-ins)
        "finding_overrides": {},
        # admin-authored findings, always shown in the report
        "custom_findings": [],
    }


def _coerce(stored: dict) -> dict:
    """Merge a decoded JSON blob onto defaults, dropping anything malformed."""
    settings = _defaults()
    if not isinstance(stored, dict):
        return settings
    for k in ("client", "prepared_by"):
        if isinstance(stored.get(k), str):
            settings[k] = stored[k]
    if isinstance(stored.get("cis_enabled"), bool):
        settings["cis_enabled"] = stored["cis_enabled"]
    sec = stored.get("sections")
    if isinstance(sec, dict):
        for sid in settings["sections"]:
            if isinstance(sec.get(sid), bool):
                settings["sections"][sid] = sec[sid]
    # Per-finding overrides: id → {enabled: bool, severity: str, remediation: str}
    ov = stored.get("finding_overrides")
    if isinstance(ov, dict):
        valid_ids = {fid for fid, _, _, _, _, _ in FINDER_CATALOG}
        for fid, entry in ov.items():
            if fid not in valid_ids or not isinstance(entry, dict):
                continue
            clean = {}
            if "enabled" in entry:
                clean["enabled"] = bool(entry["enabled"])
            if isinstance(entry.get("severity"), str) and entry["severity"] in SEVERITIES:
                clean["severity"] = entry["severity"]
            if isinstance(entry.get("remediation"), str):
                clean["remediation"] = entry["remediation"].strip()
            if clean:
                settings["finding_overrides"][fid] = clean
    # Custom findings: list of {id, title, description, severity, remediation}
    cf = stored.get("custom_findings")
    if isinstance(cf, list):
        for i, c in enumerate(cf):
            if not isinstance(c, dict):
                continue
            title = (c.get("title") or "").strip()
            if not title:
                continue
            settings["custom_findings"].append({
                "id": (c.get("id") or f"custom-{i}").strip() or f"custom-{i}",
                "title": title,
                "description": (c.get("description") or "").strip(),
                "severity": c.get("severity") if c.get("severity") in SEVERITIES else "info",
                "remediation": (c.get("remediation") or "").strip(),
                "snippet": (c.get("snippet") or "").strip(),
                "pattern": (c.get("pattern") or "").strip(),
                "enabled": c.get("enabled", True),
            })
    return settings


def load_settings() -> dict:
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            return _coerce(json.load(f))
    except FileNotFoundError:
        return _defaults()
    except Exception:
        # Corrupt/partial file: keep serving with defaults rather than 500.
        return _defaults()


def save_settings(settings: dict) -> None:
    """Validate onto defaults and write atomically (tmp + rename)."""
    clean = _coerce(settings)
    d = os.path.dirname(os.path.abspath(SETTINGS_PATH))
    os.makedirs(d, exist_ok=True)
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2)
        f.write("\n")
    os.replace(tmp, SETTINGS_PATH)
