"""
renderers.py — HTML rendering for all FortiDoc sections and the full report.
"""

import re
from pathlib import Path
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader

from utils import html_escape, anchor_id, js_name as _js_name
from extractors import mask_to_cidr_prefix, apply_netmask
from findings import finding_severity as _eff_sev


def _icon(sid: str) -> str:
    """Heroicons-style inline SVG (20x20, stroke:currentColor)."""
    I = {
        "overview": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>',
        "admins": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
        "ha": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
        "snmp": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
        "interfaces": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
        "vlans": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="2"/><path d="M7 12h10M12 7v10"/></svg>',
        "dhcp": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>',
        "routes": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="5" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><line x1="6.5" y1="6.5" x2="17.5" y2="17.5"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><line x1="17.5" y1="6.5" x2="6.5" y2="17.5"/></svg>',
        "policy_routes": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>',
        "layer3": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        "addresses": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>',
        "groups": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
        "services": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
        "service_groups": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
        "zones": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="12" y1="3" x2="12" y2="21"/><line x1="3" y1="12" x2="21" y2="12"/></svg>',
        "policies": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        "nat": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>',
        "shapers": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>',
        "vpn": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
        "vpn_ra": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
        "sslvpn": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
        "findings": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
        "certs": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
        "_system": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
        "_network": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>',
        "_routing": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        "_objects": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/></svg>',
        "_policies": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        "_vpn": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
        "_security": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
    }
    return I.get(sid, '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>')

# Jinja2 environment — templates live in the project root's templates/ dir
_TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)))

# Read static assets for standalone (self-contained HTML) mode
_STATIC_DIR = Path(__file__).parent / "static"
_REPORT_CSS = (_STATIC_DIR / "report.css").read_text(encoding="utf-8") if (_STATIC_DIR / "report.css").exists() else ""
_REPORT_JS = (_STATIC_DIR / "report.js").read_text(encoding="utf-8") if (_STATIC_DIR / "report.js").exists() else ""
_DIFF_CSS = (_STATIC_DIR / "diff_report.css").read_text(encoding="utf-8") if (_STATIC_DIR / "diff_report.css").exists() else ""

# Favicon inlined as a data URI — the generated report is a standalone file
# opened from disk, so an absolute /static path never resolves there.
def _favicon_link() -> str:
    try:
        svg = (_STATIC_DIR / "favicon.svg").read_text(encoding="utf-8")
        import base64
        href = "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")
        return f'<link rel="icon" type="image/svg+xml" href="{href}">'
    except Exception:
        return ""

# Short TOC chip labels for the magazine report (full titles stay in the section headers)
_TOC_SHORT = {
    "overview": "OVERVIEW",
    "findings": "FINDINGS",
    "system": "SYSTEM",
    "network": "NETWORK",
    "routing": "ROUTING",
    "polnat": "POLICIES",
    "vpn": "VPN",
    "objects": "OBJECTS",
    "admins": "ADMINS",
}

# Report app version chip (mirrors app.py health())
_APP_VER = "v2.0"

# Small standalone SVGs for the sidebar chrome (brand + search), same stroke
# style as the _icon() library above.
def _svg(paths: str) -> str:
    return ('<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            + paths + '</svg>')

# Flame glyph (matches static/favicon.svg) — brand mark for the sidebar.
_BRAND_ICON = _svg('<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>')
_SEARCH_ICON = _svg('<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>')

# Sidebar TOC rows reuse the report's existing icon library (sids from the
# rendered report panels mapped onto _icon() keys).
_NAV_ICON_KEYS = {
    "overview": "overview",
    "findings": "findings",
    "system": "_system",
    "network": "_network",
    "routing": "_routing",
    "polnat": "_policies",
    "vpn": "_vpn",
    "objects": "_objects",
    "admins": "admins",
}

def render_snmp(snmp: dict) -> str:
 if snmp.get("status") != "enable":
  return '<div class="empty-state">SNMP not enabled.</div>'
 parts = []
 # Summary
 rows = []
 rows.append(["Status", badge("enabled", "enabled")])
 if snmp.get("location"):
  rows.append(["Location", html_escape(snmp["location"])])
 if snmp.get("contact"):
  rows.append(["Contact", html_escape(snmp["contact"])])
 if snmp.get("description"):
  rows.append(["Description", html_escape(snmp["description"])])
 parts.append(table_html(["Setting", "Value"], rows))
 # Communities
 communities = snmp.get("communities", [])
 if communities:
  parts.append('<h3 class="sub-heading">SNMP Communities</h3>')
  for c in communities:
   c_parts = []
   # Query/Trap status
   q1 = badge("v1", "enabled") if c.get("query_v1") == "enable" else badge("v1", "disabled")
   tv1 = badge("v1", "enabled") if c.get("trap_v1") == "enable" else badge("v1", "disabled")
   tv2 = badge("v2c", "enabled") if c.get("trap_v2c") == "enable" else badge("v2c", "disabled")
   c_parts.append(f'<div style="display:flex;gap:8px;align-items:center"><span style="font-size:14px;font-weight:600">{html_escape(c["name"])}</span> {q1} {tv1} {tv2}</div>')
   # Hosts
   hosts = c.get("hosts", [])
   if hosts:
    host_items = "".join(
     f'<span style="font-size:11px;font-family:var(--mono);color:var(--muted);'
     f'display:inline-block;margin:2px 4px;padding:2px 8px;'
     f'background:var(--bg);border:1px solid var(--border);border-radius:4px">'
     f'{html_escape(h["ip"])} ({html_escape(h.get("host_type", "query"))})</span>'
     for h in hosts
    )
    c_parts.append(f'<div style="font-size:12px;margin-top:4px">{host_items}</div>')
   # Events
   events = c.get("events", [])
   if events:
    c_parts.append(f'<div style="font-size:10px;color:var(--dim);margin-top:4px">Events: {", ".join(html_escape(e) for e in events[:15])}{"..." if len(events) > 15 else ""}</div>')
   parts.append(f'<div style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:8px">{"".join(c_parts)}</div>')
 # SNMPv3 Users
 v3_users = snmp.get("users", [])
 if v3_users:
  parts.append('<h3 class="sub-heading">SNMPv3 Users</h3>')
  u_rows = []
  for u in v3_users:
   auth = f'{html_escape(u.get("auth_proto", "") or "—")} {"🔑" if u.get("auth_pwd_set") else ""}'.strip()
   priv = f'{html_escape(u.get("priv_proto", "") or "—")} {"🔑" if u.get("priv_pwd_set") else ""}'.strip()
   queries = badge("queries", "enabled") if u.get("queries") == "enable" else badge("no queries", "disabled")
   notify = ", ".join(html_escape(h) for h in u.get("notify_hosts", [])) or "—"
   u_rows.append([
    html_escape(u["name"]),
    html_escape(u.get("security_level", "") or "—"),
    auth or "—",
    priv or "—",
    queries,
    notify,
   ])
  parts.append(table_html(
   ["User", "Security Level", "Auth", "Privacy", "Queries", "Notify Hosts"],
   u_rows, "No SNMPv3 users defined."))
 return "".join(parts)



# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def html_escape(s: str) -> str:
 return (str(s)
   .replace("&", "&amp;")
   .replace("<", "&lt;")
   .replace(">", "&gt;")
   .replace('"', "&quot;"))


def anchor_id(name: str, prefix: str = "") -> str:
 """Create a safe HTML id from a FortiGate object name."""
 safe = re.sub(r'[^a-zA-Z0-9_-]', '_', str(name))
 return f"{prefix}{safe}"


def badge(text: str, kind: str = "default") -> str:
 cls_map = {
  "accept": "badge-accept", "deny": "badge-deny", "block": "badge-deny",
  "enabled": "badge-enabled", "disabled": "badge-disabled",
  "wan": "badge-wan", "lan": "badge-lan", "dmz": "badge-dmz",
  "high": "badge-high", "medium": "badge-medium",
  "info": "badge-info-sev", "psk": "badge-psk",
  "ipmask": "badge-ipmask", "iprange": "badge-iprange",
  "fqdn": "badge-fqdn", "geography": "badge-geo",
  "ikev2": "badge-ikev2", "nat": "badge-nat",
  "mfa": "badge-mfa", "default": "badge-default",
 }
 cls = cls_map.get(kind, "badge-default")
 return f'<span class="badge {cls}">{html_escape(text)}</span>'


def table_html(headers: list[str], rows: list[list[str]],
        empty_msg: str = "No entries") -> str:
 if not rows:
  return f'<div class="empty-state">{html_escape(empty_msg)}</div>'
 ths = "".join(f"<th>{html_escape(h)}</th>" for h in headers)
 trs = "".join(
  f"<tr>{''.join(f'<td>{cell}</td>' for cell in row)}</tr>"
  for row in rows
 )
 return (f'<div class="table-wrap"><table class="data-table">'
   f'<thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>')


def render_data_table(rows, headers, row_renderer, empty_msg="No entries"):
 """Render a data table using a per-row callable: row_renderer(item) -> <tr>…</tr>."""
 if not rows:
  return f'<div class="empty-state">{html_escape(empty_msg)}</div>'
 ths = "".join(f"<th>{html_escape(h)}</th>" for h in headers)
 return (f'<div class="table-wrap"><table class="data-table">'
   f'<thead><tr>{ths}</tr></thead><tbody>'
   f'{"".join(row_renderer(r) for r in rows)}</tbody></table></div>')


def section_html(id_: str, icon: str, title: str, count: int | None,
         content: str, collapsed: bool = False) -> str:
 caret = "▼" if not collapsed else "▶"
 count_html = (f'<span class="section-count">{count}</span>'
        if count is not None else "")
 state = ' data-collapsed="true"' if collapsed else ""
 return f"""
<section class="doc-section" id="{id_}"{state}>
 <div class="section-header" onclick="toggleSection(this)">
 <span class="section-icon">{icon}</span>
 <span class="section-title">{html_escape(title)}</span>
 {count_html}
 <span class="section-caret">{caret}</span>
 </div>
 <div class="section-body">{content}</div>
</section>"""


def render_overview(data: dict, meta: dict, findings_enabled: bool = True) -> str:
 g = data["global"]
 hostname = g.get("hostname", "Unknown")
 policies_on = sum(1 for p in data["policies"] if p["status"] == "enabled")
 high = sum(1 for f in data["findings"] if _eff_sev(f) == "high")
 medium = sum(1 for f in data["findings"] if _eff_sev(f) == "medium")

 sys_rows = []

 # Key metrics — compact stat cards inside system settings
 cards = [
  ("🔌", "Interfaces", str(len(data["interfaces"]))),
  ("🗺", "Static Routes", str(len(data["routes"]))),
  ("🛡", "Active Policies", f"{policies_on} / {len(data['policies'])}"),
  ("🔒", "VPN Tunnels", str(len(data["vpn"]))),
  ("👤", "Admins", str(len(data["admins"]))),
  ("📌", "Address Objects", str(len(data["addresses"]))),
 ]
 card_html = "".join(
  f'<div class="stat-card"><div class="stat-icon">{icon}</div>'
  f'<div class="stat-label">{html_escape(label)}</div>'
  f'<div class="stat-value">{html_escape(value)}</div></div>'
  for icon, label, value in cards
 )
 stat_grid = f'<div class="stat-grid" style="margin-bottom:1rem">{card_html}</div>'

 vi = data.get("version_info", {})
 if vi.get("serial"):
  label = "Model" if vi.get("model") else "Serial number"
  sys_rows.append([label, html_escape(vi["serial"])])
 if vi.get("model"):
  sys_rows.append(["Source note", "⚠️ Serial not found — showing device/hostname instead"])
 if vi.get("firmware"):
  fw = vi["firmware"]
  if vi.get("build"):
   fw += f" (build {vi['build']})"
  sys_rows.append(["Firmware version", html_escape(fw)])
 for k, label in [
  ("hostname", "Hostname"), ("timezone", "Timezone"),
  ("admintimeout", "Admin timeout"), ("admin-sport", "HTTPS port"),
  ("strong-crypto", "Strong crypto"),
 ]:
  v = g.get(k, "")
  if v:
   sys_rows.append([html_escape(label), html_escape(str(v))])

 dns = data["dns"]
 if dns.get("primary"):
  sys_rows.append(["DNS primary", html_escape(dns["primary"])])
 if dns.get("secondary"):
  sys_rows.append(["DNS secondary", html_escape(dns["secondary"])])

 ntp = data["ntp"]
 ntp_status = badge("enabled", "enabled") if ntp.get("sync") == "enable" else badge("disabled", "disabled")
 ntp_servers = ntp.get("servers", [])
 ntp_ifaces = ntp.get("ntp_interfaces", [])
 ntp_access_ifaces = ntp.get("ntp_access_interfaces", [])
 ntp_type = ntp.get("type", "")
 ntp_server_mode = ntp.get("server_mode", "disable")
 ntp_detail = ntp_status
 if ntp_type:
  ntp_detail += f'<br><span style="font-size:11px;color:var(--muted)">Source: {html_escape(ntp_type)}</span>'
 if ntp_servers:
  ntp_detail += f'<br><span style="font-size:11px;color:var(--muted)">NTP-Server: {" ".join(html_escape(s) for s in ntp_servers)}</span>'
 elif ntp.get("sync") == "enable":
  ntp_detail += f'<br><span style="font-size:11px;color:var(--dim)">(via {html_escape(ntp_type or "FortiGuard/DHCP")})</span>'
 if ntp_server_mode == "enable" and ntp_ifaces:
  ntp_detail += f'<br><span style="font-size:11px;color:var(--green)">NTP-Server on: {" ".join(_link_iface(i) for i in ntp_ifaces)}</span>'
 if ntp_access_ifaces:
  ntp_detail += f'<br><span style="font-size:11px;color:var(--muted)">NTP allowaccess: {" ".join(_link_iface(i) for i in ntp_access_ifaces)}</span>'
 if ntp.get("source_ip"):
  ntp_detail += f'<br><span style="font-size:11px;color:var(--muted)">Source-IP: {html_escape(ntp["source_ip"])}</span>'
 sys_rows.append(["NTP sync", ntp_detail])

 sl = data["syslog"]
 sys_rows.append(["Syslog",
  badge("enabled", "enabled")
  if sl.get("status") == "enable"
  else badge("disabled", "disabled")])
 if sl.get("server"):
  sys_rows.append(["Syslog server",
   f"{html_escape(sl['server'])}:{html_escape(sl.get('port','514'))}"])
 ha = data.get("ha", {})
 ha_mode = ha.get("mode", "standalone")
 ha_labels = {"a-p": "Active-Passive", "a-a": "Active-Active", "standalone": "Standalone"}
 if ha_mode != "standalone":
  ha_display = ha_labels.get(ha_mode, ha_mode)
  if ha.get("group_name"):
   ha_display += f' <span style="font-size:11px;color:var(--muted)">({html_escape(ha["group_name"])})</span>'
  sys_rows.append(["HA cluster", ha_display])
 else:
  sys_rows.append(["HA cluster", "Standalone"])

 sys_table = table_html(["Setting", "Value"], sys_rows,
         "No system global data")

 if findings_enabled:
     findings_block = (f'<div class="findings-summary">'
      f'<h3 class="sub-heading">Security findings</h3>'
      f'<div class="findings-stats">'
      f'<span class="findings-stat findings-stat-high"><strong>{high}</strong> high</span>'
      f'<span class="findings-stat findings-stat-medium"><strong>{medium}</strong> medium</span>'
      f'</div><p style="font-size:12px;color:var(--muted);margin-top:8px">'
      f'See the <a href="#findings" style="color:var(--accent)">Findings section</a> below for full details.</p>'
      f'</div>')
 else:
     findings_block = ''

 return (f'<div class="two-col">'
 f'<div><h3 class="sub-heading">System settings</h3>{stat_grid}{sys_table}</div>'
 f'{findings_block}</div>')


def render_interfaces(interfaces: list[dict]) -> str:
 if not interfaces:
  return '<div class="empty-state">No interfaces defined.</div>'
 # Exclude VLAN interfaces (shown in separate section)
 phys = [i for i in interfaces if i.get("type") != "vlan"]
 if not phys:
  return '<div class="empty-state">No physical interfaces defined.</div>'
 ths = "".join(f"<th>{html_escape(h)}</th>" for h in
   ["Name", "IP / CIDR", "Type", "Role", "Access", "DHCP Server", "Description"])
 trs = ""
 for i in phys:
  role = i.get("role", "")
  dhcp = badge("DHCP ✓", "enabled") if i.get("dhcp_server") else ""
  name = html_escape(i['name'])
  aid = anchor_id(i['name'], "iface-")
  trs += (f'<tr id="{aid}"><td><a href="#{aid}" class="obj-link">'
    f'<strong>{name}</strong></a></td>'
    f'<td>{html_escape(i.get("cidr", "") or i.get("ip", "") or "—")}</td>'
    f'<td>{html_escape(i.get("type", ""))}</td>'
    f'<td>{badge(role, role) if role else "—"}</td>'
    f'<td>{html_escape(i.get("access", "") or "—")}</td>'
    f'<td>{dhcp}</td>'
    f'<td>{html_escape(i.get("description", "") or "—")}</td></tr>')
 return (f'<div class="table-wrap"><table class="data-table">'
   f'<thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>')


def render_routes(routes: list[dict]) -> str:
 headers = ["#", "Destination", "Gateway", "Device", "Distance", "Priority", "Comment"]
 def row(r):
  dst = html_escape(r["dst"])
  if r.get("is_default"):
   dst += " " + badge("default", "wan")
  dev = r.get("device", "")
  device_cell = f'<a href="#{anchor_id(dev, "iface-")}" class="obj-link">{html_escape(dev)}</a>' if dev else "—"
  return (f'<tr><td>{html_escape(r["seq"])}</td><td>{dst}</td>'
    f'<td>{html_escape(r["gateway"] or "—")}</td><td>{device_cell}</td>'
    f'<td>{html_escape(r["distance"])}</td><td>{html_escape(r["priority"])}</td>'
    f'<td>{html_escape(r["comment"] or "—")}</td></tr>')
 return render_data_table(routes, headers, row, "No static routes defined.")


def render_policy_routes(proutes: list[dict]) -> str:
    if not proutes:
        return '<div class="empty-state">No policy-based routes defined.</div>'
    ths = "".join(f"<th>{html_escape(h)}</th>" for h in
        ["#", "Incoming", "Source", "Destination", "Protocol/Port", "Gateway", "Outgoing", "Flags", "Comment"])
    trs = ""
    for r in proutes:
        proto = r.get("protocol", "0")
        proto_display = ""
        if proto == "0":
            proto_display = badge("any", "disabled")
        elif proto == "6":
            proto_display = "TCP"
        elif proto == "17":
            proto_display = "UDP"
        elif proto == "1":
            proto_display = "ICMP"
        else:
            proto_display = f"proto {html_escape(proto)}"
        sport = r.get("start_port", "")
        if sport:
            eport = r.get("end_port", sport)
            proto_display += f" :{sport}" if sport == eport else f" :{sport}-{eport}"
        flags = []
        if r.get("status") == "disabled":
            flags.append(badge("inactive", "disabled"))
        if r.get("tos"):
            flags.append(f"TOS {html_escape(r['tos'])}")
        if r.get("action"):
            flags.append(html_escape(r["action"]))
        flag_html = " ".join(flags) if flags else "—"
        input_devs = ", ".join(_link_iface(d) for d in r.get("input_device", [])) or "—"
        output_dev = _link_iface(r["output_device"]) if r.get("output_device") else "—"
        gw = html_escape(r["gateway"]) if r.get("gateway") else "—"
        src = ", ".join(_link_grp(s) for s in r.get("src", [])) or "all"
        dst = ", ".join(_link_grp(s) for s in r.get("dst", [])) or "0.0.0.0/0"
        trs += (f'<tr><td>{html_escape(r["seq"])}</td>'
            f'<td>{input_devs}</td>'
            f'<td>{src}</td>'
            f'<td>{dst}</td>'
            f'<td>{proto_display}</td>'
            f'<td>{gw}</td>'
            f'<td>{output_dev}</td>'
            f'<td>{flag_html}</td>'
            f'<td>{html_escape(r["comments"] or "—")}</td></tr>')
    return (f'<div class="table-wrap"><table class="data-table">'
        f'<thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>')


def render_addresses(addresses: list[dict]) -> str:
 if not addresses:
  return '<div class="empty-state">No address objects defined.</div>'
 ths = "".join(f"<th>{html_escape(h)}</th>" for h in
   ["Name", "Type", "Value", "Usage", "Comment"])
 trs = ""
 for a in addresses:
  name = html_escape(a["name"])
  cnt = a.get("usage_count", 0)
  cnt_cell = (f'<span class="usage-link" data-obj-name="{_js_name(a["name"])}" onclick="showObjectUsage(this.dataset.objName,event)" title="Show usage in policies" style="cursor:pointer;font-size:12px;font-family:var(--mono);color:var(--green)">{cnt}x</span>'
       if cnt > 0 else f'<span style="font-size:11px;color:var(--dim)">0</span>')
  aid = anchor_id(a["name"], "addr-")
  trs += (f'<tr id="{aid}"><td><a href="#" class="obj-link" data-obj-name="{_js_name(a["name"])}" onclick="showObjectUsage(this.dataset.objName,event);return false">{name}</a></td>'
    f'<td>{badge(a["type"], a["type"])}</td>'
    f'<td>{html_escape(a["value"])}</td>'
    f'<td>{cnt_cell}</td>'
    f'<td>{html_escape(a["comment"] or "—")}</td></tr>')
 return (f'<div class="table-wrap"><table class="data-table">'
   f'<thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>')


def render_groups(groups: list[dict]) -> str:
 if not groups:
  return '<div class="empty-state">No address groups defined.</div>'
 ths = "".join(f"<th>{html_escape(h)}</th>" for h in
   ["Name", "Members", "Usage", "Comment"])
 trs = ""
 for g in groups:
  name = html_escape(g["name"])
  cnt = g.get("usage_count", 0)
  cnt_cell = (f'<span class="usage-link" data-obj-name="{_js_name(g["name"])}" onclick="showObjectUsage(this.dataset.objName,event)" title="Show usage in policies" style="cursor:pointer;font-size:12px;font-family:var(--mono);color:var(--green)">{cnt}x</span>'
       if cnt > 0 else f'<span style="font-size:11px;color:var(--dim)">0</span>')
  aid = anchor_id(g["name"], "grp-")
  members = ", ".join(
   f'<a href="#{anchor_id(m, "addr-")}" class="obj-link">{html_escape(m)}</a>'
   for m in g["members"]
  ) or "—"
  trs += (f'<tr id="{aid}"><td><a href="#" class="obj-link" data-obj-name="{_js_name(g["name"])}" onclick="showObjectUsage(this.dataset.objName,event);return false">{name}</a></td>'
    f'<td>{members}</td>'
    f'<td>{cnt_cell}</td>'
    f'<td>{html_escape(g["comment"] or "—")}</td></tr>')
 return (f'<div class="table-wrap"><table class="data-table">'
   f'<thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>')


def render_services(services: list[dict]) -> str:
 if not services:
  return '<div class="empty-state">No custom services defined.</div>'
 ths = "".join(f"<th>{html_escape(h)}</th>" for h in
   ["Name", "Protocol", "TCP ports", "UDP ports", "ICMP", "Usage", "Comment"])
 trs = ""
 for s in services:
  name = html_escape(s["name"])
  cnt = s.get("usage_count", 0)
  cnt_cell = (f'<span class="usage-link" data-obj-name="{_js_name(s["name"])}" onclick="showObjectUsage(this.dataset.objName,event)" title="Show usage in policies" style="cursor:pointer;font-size:12px;font-family:var(--mono);color:var(--green)">{cnt}x</span>'
       if cnt > 0 else f'<span style="font-size:11px;color:var(--dim)">0</span>')
  aid = anchor_id(s["name"], "svc-")
  trs += (f'<tr id="{aid}"><td><a href="#" class="obj-link" data-obj-name="{_js_name(s["name"])}" onclick="showObjectUsage(this.dataset.objName,event);return false">{name}</a></td>'
    f'<td>{html_escape(s["protocol"])}</td>'
    f'<td>{html_escape(s["tcp_ports"] or "—")}</td>'
    f'<td>{html_escape(s["udp_ports"] or "—")}</td>'
    f'<td>{html_escape(s["icmp"] or "—")}</td>'
    f'<td>{cnt_cell}</td>'
    f'<td>{html_escape(s["comment"] or "—")}</td></tr>')
 return (f'<div class="table-wrap"><table class="data-table">'
   f'<thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>')

def render_service_groups(groups: list[dict]) -> str:
 if not groups:
  return '<div class="empty-state">No service groups defined.</div>'
 ths = "".join(f"<th>{html_escape(h)}</th>" for h in
   ["Name", "Members", "Usage", "Comment"])
 trs = ""
 for g in groups:
  name = html_escape(g["name"])
  cnt = g.get("usage_count", 0)
  cnt_cell = (f'<span class="usage-link" data-obj-name="{_js_name(g["name"])}" onclick="showObjectUsage(this.dataset.objName,event)" title="Show usage in policies" style="cursor:pointer;font-size:12px;font-family:var(--mono);color:var(--green)">{cnt}x</span>'
       if cnt > 0 else f'<span style="font-size:11px;color:var(--dim)">0</span>')
  aid = anchor_id(g["name"], "svcgrp-")
  members = ", ".join(_link_svc(m) for m in g.get("members", [])) or "—"
  trs += (f'<tr id="{aid}"><td><a href="#" class="obj-link" data-obj-name="{_js_name(g["name"])}" onclick="showObjectUsage(this.dataset.objName,event);return false">{name}</a></td>'
    f'<td>{members}</td>'
    f'<td>{cnt_cell}</td>'
    f'<td>{html_escape(g["comment"] or "—")}</td></tr>')
 return (f'<div class="table-wrap"><table class="data-table">'
   f'<thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>')


def _link_iface(name: str) -> str:
 return f'<a href="#{anchor_id(name, "iface-")}" class="obj-link">{html_escape(name)}</a>'

def _link_addr(name: str) -> str:
 return f'<a href="#{anchor_id(name, "addr-")}" class="obj-link">{html_escape(name)}</a>'

def _link_grp(name: str) -> str:
 """Link to an address object or group, trying addr- first then grp-."""
 aid_addr = anchor_id(name, "addr-")
 aid_grp = anchor_id(name, "grp-")
 return (f'<a href="#{aid_addr}" class="obj-link"'
   f' onclick="event.preventDefault();'
   f' var e=document.getElementById(\'{aid_addr}\')'
   f' ||document.getElementById(\'{aid_grp}\');'
   f' if(e)e.scrollIntoView({{behavior:\'smooth\'}})">'
   f'{html_escape(name)}</a>')

def _link_pool(name: str) -> str:
 """Link to an IP pool entry."""
 return f'<a href="#{anchor_id(name, "pool-")}" class="obj-link">{html_escape(name)}</a>'

def _link_svc(name: str) -> str:
 """Link to a service or service group, trying svc- first then svcgrp-."""
 aid_svc = anchor_id(name, "svc-")
 aid_grp = anchor_id(name, "svcgrp-")
 return (f'<a href="#{aid_svc}" class="obj-link"'
   f' onclick="event.preventDefault();'
   f' var e=document.getElementById(\'{aid_svc}\')'
   f' ||document.getElementById(\'{aid_grp}\');'
   f' if(e)e.scrollIntoView({{behavior:\'smooth\'}})">'
   f'{html_escape(name)}</a>')

_POL_FLOW_ICONS = {
    "iface": '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><path d="m10 17 5-5-5-5"/><path d="M15 12H3"/>',
    "source": '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    "deny": '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
    "accept": '<circle cx="12" cy="12" r="10"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/>',
    "dest": '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    "service": '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
}
_POL_SHIELD_ICON = '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'
_POL_ARROW_ICON = '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>'


def render_policies(policies: list[dict]) -> str:
 if not policies:
  return '<div class="empty-state">No firewall policies found.</div>'

 cards = []
 for p in policies:
  seq = p["seq"]
  name_txt = p["name"]
  # Split policy name on its arrow separator ("SRC > DST") so the arrow
  # renders as a muted marker like the mockup.
  if " > " in name_txt:
   n1, n2 = name_txt.split(" > ", 1)
   name_html = f'{html_escape(n1)} <span>&gt;</span> {html_escape(n2)}'
  else:
   name_html = html_escape(name_txt)

  # Interfaces — chip + meta per direction
  def _if_chips(names: list[str]) -> str:
   if not names:
    return '<span class="ifchip">—</span>'
   shown = "".join(f'<span class="ifchip">{_link_iface(x)}</span>' for x in names[:3])
   meta = (f'{len(names)} interfaces' if len(names) > 3
           else ("interface" if len(names) == 1 else f"{len(names)} interfaces"))
   return shown + f'<span class="ifmeta">{meta}</span>'
  src_if = _if_chips(p["srcintf"])
  dst_if = _if_chips(p["dstintf"])

  def _obj_row(label: str, parts: list[str], is_all: bool) -> str:
   if not parts:
    parts = ["<em>all</em>"]
   chips = ""
   for x in parts:
    if is_all and "all" in x.lower():
     chips += f'<span class="obj all">{x}</span>'
    else:
     chips += f'<span class="obj">{x}</span>'
   return (f'<div class="list"><div class="cap">{label} <b>{len(parts)}</b></div>'
           f'<div class="row">{chips}</div></div>')

  src_addr_raw = p["srcaddr"]
  dst_addr_raw = p["dstaddr"]
  src_parts = [_link_grp(x) for x in src_addr_raw]
  dst_parts = [_link_grp(x) for x in dst_addr_raw]
  isdb_list = p.get("isdb", [])
  if isdb_list:
   dst_parts = [html_escape(i[5:]) for i in isdb_list] + ([] if dst_addr_raw == ["all"] else dst_parts)
  src_row = _obj_row("SOURCE", src_parts, src_addr_raw == ["all"])
  dst_row = _obj_row("DESTINATION", dst_parts, dst_addr_raw == ["all"])

  # Services + schedule: "SERVICE ALL · SCHEDULE ALWAYS"
  svc_raw = [html_escape(x) for x in p["services"]] if p["services"] else ["ALL"]
  svc_name = ", ".join(svc_raw[:4]) if svc_raw != ["ALL"] else "ALL"
  schedule = html_escape(p["schedule"] or "always").upper()
  svc_txt = f"SERVICE {svc_name} · SCHEDULE {schedule}"

  action = p["action"]
  deny = action in ("deny", "deny-redirect", "deny6-redirect", "blocked")
  action_cls = "deny" if deny else "accept"
  action_pill = (f'<span class="action deny">✕ DENY</span>' if deny else
                 f'<span class="action accept">✓ ACCEPT</span>')

  # Status chips
  chips = []
  chips.append(f'<span class="chip {"green" if p["status"] != "disabled" else "red"}">'
               f'{"ENABLED" if p["status"] != "disabled" else "DISABLED"}</span>')
  chips.append(f'<span class="chip {"red" if deny else "green"}">{"DENY ACTION" if deny else "ACCEPT"}</span>')
  if p.get("logtraffic") not in ("disable", ""):
   chips.append('<span class="chip green">LOG ALL TRAFFIC</span>')
  else:
   chips.append('<span class="chip amber">NO LOG</span>')
  if p.get("dnat"):
   chips.append('<span class="chip green">DNAT</span>')
  elif p.get("natpool"):
   chips.append('<span class="chip green">NAT POOL</span>')
  elif p.get("nat"):
   chips.append('<span class="chip green">NAT</span>')
  else:
   chips.append('<span class="chip amber">NO NAT</span>')
  prof_labels = [("AV", p.get("av")), ("IPS", p.get("ips")), ("WebFilter", p.get("webfilter")),
                   ("AppCtrl", p.get("appctrl")), ("DLP", p.get("dlp")), ("DNSFilter", p.get("dnsfilter")),
                   ("EmailFilter", p.get("emailfilter")), ("CIFS", p.get("cifs")),
                   ("ProtOpt", p.get("protocolopt")), ("SSLSsh", p.get("sslssh")),
                   ("VideoFilter", p.get("videofilter")), ("VoIP", p.get("voip")),
                   ("WAF", p.get("waf")), ("ProfileGroup", p.get("profile_group"))]
  profs = [(lbl, v) for lbl, v in prof_labels if v]
  if profs:
   for lbl, v in profs:
    chips.append(f'<span class="chip dim" title="{html_escape(lbl)}: {html_escape(v)}">'
                 f'{html_escape(lbl)}: {html_escape(v)}</span>')
  else:
   chips.append('<span class="chip amber">NO SECURITY PROFILES</span>')

  comment_html = (f'<div class="pol-comment">💬 {html_escape(p.get("comments", ""))}</div>'
                  if p.get("comments", "").strip() else "")

  cards.append(f'''
<div class="policy-card" id="policy-{seq}">
 <div class="p-head">
  <h2>{name_html}</h2>
  <span class="p-id">#{seq}</span>
 </div>
 <hr class="p-hr">

 <div class="pipe">
  <div class="node act {action_cls}">
   <span class="dir">ACT</span>
   {action_pill}
   <span class="svc">{svc_txt}</span>
  </div>
  <div class="node iface-row">
   <span class="dir">IN</span>
   <div class="chips">{src_if}</div>
  </div>
  <div class="node iface-row">
   <span class="dir">OUT</span>
   <div class="chips">{dst_if}</div>
  </div>
 </div>
 <hr class="p-hr">

 {src_row}{dst_row}

 <div class="strip">{"".join(chips)}</div>
 {comment_html}
</div>''')

 return "".join(cards)


def render_vpn_ra(vpns: list[dict]) -> str:
 """Render IPsec Remote Access (FortiClient/dialup with IP pool) tunnels."""
 if not vpns:
  return '<div class="empty-state">No IPsec Remote Access tunnels defined.</div>'
 headers = ["Name", "Interface", "IKE", "Proposal", "IP Pool", "DPD", "Comment"]
 def row(v):
  name = html_escape(v["name"])
  iface = _link_iface(v.get("interface", "")) if v.get("interface") else "—"
  ike = badge(f"IKEv{v['ike_version']}", f"ikev{v['ike_version']}")
  proposal = html_escape(v.get("proposal", "") or "—")
  ip_pool = "—"
  if v.get("ipv4_start_ip"):
   ip_pool = f"{html_escape(v['ipv4_start_ip'])} – {html_escape(v.get('ipv4_end_ip', v['ipv4_start_ip']))}"
  elif v.get("ipv6_start_ip"):
   ip_pool = f"{html_escape(v['ipv6_start_ip'])} – {html_escape(v.get('ipv6_end_ip', v['ipv6_start_ip']))}"
  dpd = badge("enabled", "enabled") if v.get("dpd") == "enable" else badge("disabled", "disabled")
  comment = html_escape(v.get("comment", "") or "—")
  return f'<tr><td><strong>{name}</strong></td><td>{iface}</td><td>{ike}</td><td>{proposal}</td><td style="font-family:var(--mono);font-size:12px">{ip_pool}</td><td>{dpd}</td><td>{comment}</td></tr>'
 return render_data_table(vpns, headers, row, "No IPsec Remote Access tunnels defined.")

def render_vpn(vpns: list[dict]) -> str:
 if not vpns:
  return '<div class="empty-state">No VPN tunnels defined.</div>'

 cards = []
 for v in vpns:
  dpd_badge = (badge("enabled", "enabled") if v.get("dpd") == "enable"
         else badge("disabled", "disabled"))
  psk_badge = (badge("set", "mfa") if v["psk_set"]
          else badge("not set", "disabled"))
  comment_html = (f'<span style="color:var(--muted);font-size:11px">'
           f'{html_escape(v["comment"])}</span>'
           if v.get("comment") else "")

  local_iface = v.get("interface", "")
  iface_link = _link_iface(local_iface) if local_iface else "—"
  meta_items = [
   ("Local interface", iface_link),
   ("Remote gateway", badge("Dynamic / Dial-up", "info")
       if not v["remote_gw"] else html_escape(v["remote_gw"])),
   ("IKE version", badge(f"IKEv{v['ike_version']}", "ikev2")),
   ("Proposal (P1)", html_escape(v["proposal"] or "—")),
   ("DPD", dpd_badge),
   ("Pre-shared key", psk_badge),
  ]
  meta_html = "".join(
   f'<div class="vpn-meta-item">'
   f'<div class="vpn-meta-label">{label}</div>'
   f'<div class="vpn-meta-value">{value}</div></div>'
   for label, value in meta_items
  )

  p2_list = v.get("phase2", [])
  if p2_list:
   p2_rows = []
   for p2 in p2_list:
    src = p2.get("src_subnet", "") or "0.0.0.0/0"
    dst = p2.get("dst_subnet", "") or "0.0.0.0/0"
    p2_rows.append([
     html_escape(p2["name"]),
     html_escape(src),
     html_escape(dst),
     html_escape(p2.get("proposal", "") or "—"),
     html_escape(p2.get("dhgrp", "") or "—"),
    ])
   p2_table = table_html(
    ["Phase 2 name", "Local subnet", "Remote subnet",
     "Proposal", "DH group"],
    p2_rows)
  else:
   p2_table = '<div class="empty-state" style="padding:.75rem">No Phase 2 selectors defined.</div>'

  tunnel_id = html_escape(v["name"]).replace(" ", "_")
  cards.append(
   f'<div class="vpn-card vpn-collapsible collapsed" id="vpn-{tunnel_id}">'
   f'<div class="vpn-card-header" onclick="toggleVpn(this)">'
   f'<span class="vpn-tunnel-name">🔒 {html_escape(v["name"])}</span>'
   f'{comment_html}'
   f'<span class="vpn-caret">▼</span></div>'
   f'<div class="vpn-body">'
   f'<div class="vpn-card-meta">{meta_html}</div>'
   f'<div class="vpn-phase2-wrap">'
   f'<div class="vpn-phase2-title">Phase 2 — Encryption Domains</div>'
   f'{p2_table}</div></div></div>'
  )

 return "".join(cards)


def render_ssl_vpn(ssl_vpn: dict) -> str:
 def v(key, default="—"):
  val = ssl_vpn.get(key, default)
  return html_escape(str(val)) if val and val != default else default

 status = ssl_vpn.get("status", "disable")
 status_badge = badge("Enabled", "enabled") if status == "enable" else badge("Disabled", "disabled")

 port = v("port")
 srvcert = v("servercert")
 src_intf = v("source_interface")
 intfs = ", ".join(ssl_vpn.get("listen_interfaces", [])) or "—"
 pools = ", ".join(ssl_vpn.get("tunnel_ip_pools", [])) or "—"
 pools6 = ", ".join(ssl_vpn.get("tunnel_ipv6_pools", [])) or "—"
 src_addr_list = ssl_vpn.get("source_address", [])
 src_addr_str = ", ".join(src_addr_list) if src_addr_list else ""
 dns1 = v("dns_server1", "")
 dns2 = v("dns_server2", "")
 dns_suf = v("dns_suffix", "")

 # Colors
 g = "rgba(52,211,153,.15)"
 r = "rgba(248,113,113,.15)"

 # ── Status bar ──
 status_bar = f'''
<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:12px">
 <div>{status_badge}</div>
 <div style="font-size:12px;color:var(--dim)">Port: <strong style="color:var(--fg)">{port}</strong></div>
 <div style="font-size:12px;color:var(--dim)">Cert: <strong style="color:var(--fg)">{srvcert}</strong></div>
 <div style="font-size:12px;color:var(--dim)">Src intf: <strong style="color:var(--fg)">{src_intf}</strong></div>
</div>'''

 # ── Helper to build a card ──
 def card(title, body_lines):
  items = "".join(f'<div style="display:flex;justify-content:space-between;align-items:baseline;padding:4px 0;border-bottom:1px solid var(--border);font-size:12px"><span style="color:var(--dim)">{html_escape(k)}</span><span style="font-weight:500;text-align:right">{v}</span></div>' for k, v in body_lines if v)
  return f'<div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:8px 12px"><h4 style="font-size:12px;font-weight:600;margin:0 0 6px 0;color:var(--muted)">{html_escape(title)}</h4>{items}</div>'

 # ── Three-column grid ──
 def yesno(val): return badge("Yes", "enabled") if val == "enable" else badge("No", "disabled")

 # Portal names for General card
 portal_names = [p.get("name", "—") for p in ssl_vpn.get("portals", [])]
 portal_str = ", ".join(portal_names) if portal_names else "None"

 tls_v = ssl_vpn.get("tls_versions", "") or ssl_vpn.get("ssl_version", "tls-1.2")

 card1 = card("General", [
  ("Listen interfaces", intfs),
  ("Tunnel IPv4 pools", pools),
  ("Tunnel IPv6 pools", pools6),
  ("Max concurrent users", v("max_concurrent_user")),
  ("Portals", portal_str),
 ])

 card2 = card("Security", [
  ("TLS version", tls_v),
  ("DTLS", yesno(ssl_vpn.get("dtls_tunnel", ""))),
  ("HSTS", yesno(ssl_vpn.get("hsts", ""))),
  ("Client cert required", yesno(ssl_vpn.get("require_client_cert", ""))),
  ("Auth type", v("auth_type")),
  ("HTTP→HTTPS", yesno(ssl_vpn.get("http_redirect", ""))),
  ("HTTPS→HTTP", yesno(ssl_vpn.get("https_redirect", ""))),
  ("Banned ciphers", v("banned_cipher")),
 ])

 # Source addresses with red warning
 src_html = src_addr_str if src_addr_str else (
  '<span style="color:#f87171;font-size:11px">⚠ None — any source allowed</span>')

 card3 = card("Source Restrictions &amp; Timeouts", [
  ("Source addresses", src_html),
  ("Source negate", yesno(ssl_vpn.get("source_address_negate", ""))),
  ("Idle timeout (s)", v("idle_timeout")),
  ("Auth timeout (s)", v("auth_timeout")),
  ("Login timeout (s)", v("login_timeout")),
  ("Login attempt limit", v("login_attempt_limit")),
  ("Login block time (s)", v("login_block_time")),
 ])

 cards_grid = f'<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:12px">{card1}{card2}{card3}</div>'

 # ── Portals ──
 portals = ssl_vpn.get("portals", [])
 if portals:
  portal_cards = []
  for p in portals:
   pp = ", ".join(p.get("tunnel_ip_pools", [])) or "—"
   st = p.get("split_tunneling", "disable")
   lul = p.get("limit_user_logins", "disable")
   sd = p.get("split_dns", [])

   # Badges
   badges_data = []
   if pp:
    badges_data.append(("Pools: " + pp, "info"))
   badges_data.append(("Split: ON" if st == "enable" else "Split: OFF", "enabled" if st == "enable" else "disabled"))
   badges_data.append(("Login: Limit" if lul == "enable" else "Login: Unlimited", "enabled" if lul == "enable" else "disabled"))
   badges_html = "".join(badge(t, s) for t, s in badges_data)

   # Split-DNS table
   if sd:
    sd_rows = ""
    for sde in sd:
     dom = html_escape(sde.get("domains", ""))
     d1v = html_escape(sde.get("dns_server1", ""))
     d2v = html_escape(sde.get("dns_server2", ""))
     dns_str = d1v + (", " + d2v if d2v else "")
     sd_rows += f'<tr><td style="padding:2px 8px;border-bottom:1px solid var(--border);font-size:11px">{dom}</td><td style="padding:2px 8px;border-bottom:1px solid var(--border);font-size:11px;font-family:var(--mono)">{dns_str}</td></tr>'
    sd_html = f'<table style="width:100%;margin-top:6px;border-collapse:collapse"><tr><th style="padding:2px 8px;font-size:10px;text-align:left;color:var(--dim)">Domain</th><th style="padding:2px 8px;font-size:10px;text-align:left;color:var(--dim)">DNS server</th></tr>{sd_rows}</table>'
   else:
    sd_html = '<div style="font-size:10px;color:var(--dim);margin-top:4px">No split-DNS configured</div>'

   portal_cards.append(
    f'<div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:8px 10px">'
    f'<div style="font-weight:600;font-size:13px;margin-bottom:4px">{html_escape(p["name"])}</div>'
    f'<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:4px">{badges_html}</div>'
    f'{sd_html}</div>'
   )

  portals_html = (
   '<h3 style="font-size:14px;font-weight:600;margin:16px 0 8px 0;color:var(--muted)">Web Portals</h3>'
   '<div style="display:flex;flex-direction:column;gap:8px">' + "".join(portal_cards) + '</div>')
 else:
  portals_html = '<div style="color:var(--dim);font-size:12px;margin-top:8px">No web portals defined.</div>'

 # ── Authentication Rules ──
 auth_rules = ssl_vpn.get("auth_rules", [])
 if auth_rules:
  ar_rows = []
  for r in auth_rules:
   groups_str = ", ".join(html_escape(g) for g in r.get("groups", []))
   ar_rows.append([html_escape("#" + str(r["id"])), groups_str, html_escape(r.get("portal", ""))])
  ar_html = (
   '<h3 style="font-size:14px;font-weight:600;margin:16px 0 8px 0;color:var(--muted)">Authentication Rules — Group to Portal</h3>'
   + table_html(["Rule", "Groups", "Portal"], ar_rows, "No authentication rules defined."))
 else:
  ar_html = ""

 # Disclaimer
 disclaimer = ('<div style="margin-top:16px;padding:10px 12px;background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);border-radius:8px;font-size:11px;color:var(--muted);line-height:1.6">'
     '<strong style="color:var(--amber)">⚠ Note</strong><br>'
     'Parsing the SSL-VPN configuration from the .conf file may be incomplete, '
     'as some relevant settings are not included in the exported configuration. '
     'In addition, <strong style="color:var(--text)">Fortinet removed this feature from version 7.6.x onwards</strong>.'
     '</div>')

 return disclaimer + status_bar + cards_grid + portals_html + ar_html

def render_nat_vips(vips: list[dict]) -> str:
 vips_only = [v for v in vips if v.get("kind") != "ippool"]
 pools_only = [v for v in vips if v.get("kind") == "ippool"]
 parts = []
 # ── VIP / DNAT ──
 if vips_only:
  rows = []
  for v in vips_only:
   ext = html_escape(v["ext_ip"])
   if v.get("ext_port"):
    ext += f":{html_escape(v['ext_port'])}"
   mapped = html_escape(v["mapped_ip"])
   if v.get("mapped_port"):
    mapped += f":{html_escape(v['mapped_port'])}"
   aid = anchor_id(v["name"], "vip-")
   name_cell = f'<span id="{aid}">{html_escape(v["name"])}</span>'
   rows.append([
    name_cell,
    html_escape(v["ext_intf"]),
    ext, mapped,
    badge("port-fwd", "nat") if v["port_forward"] else badge("1:1 NAT", "ipmask"),
    html_escape(v["comment"] or "—"),
   ])
  parts.append('<h3 class="sub-heading">VIPs / DNAT</h3>')
  parts.append(table_html(
   ["Name", "Ext. intf", "External IP:port", "Mapped IP:port", "Type", "Comment"],
   rows, "No VIP / DNAT entries found"))
 # ── IP Pools ──
 if pools_only:
  p_rows = []
  for p in pools_only:
   ip_range = p["ext_ip"]
   if p.get("end_ip") and p["end_ip"] != p["ext_ip"]:
    ip_range += f" – {html_escape(p['end_ip'])}"
   aid = anchor_id(p["name"], "pool-")
   name_cell = f'<span id="{aid}">{html_escape(p["name"])}</span>'
   p_rows.append([
    name_cell,
    html_escape(p["ext_intf"]),
    html_escape(ip_range),
    badge("IP Pool", "nat"),
    html_escape(p["comment"] or "—"),
   ])
  parts.append('<h3 class="sub-heading">IP Pools (SNAT)</h3>')
  parts.append(table_html(
   ["Name", "Interface", "IP Range", "Type", "Comment"],
   p_rows, "No IP pools defined"))
 if not parts:
  return '<div class="empty-state">No VIP / NAT entries found.</div>'
 return "".join(parts)


def render_zones(zones: list[dict]) -> str:
 headers = ["Zone name", "Member interfaces", "Intra-zone"]
 def row(z):
  name = html_escape(z["name"])
  aid = anchor_id(z["name"], "zone-")
  members = ", ".join(f'<a href="#{anchor_id(m, "iface-")}" class="obj-link">{html_escape(m)}</a>' for m in z["members"]) or "—"
  iz = badge("allowed", "enabled") if z["intrazone"] == "allow" else badge("denied", "disabled")
  return f'<tr id="{aid}"><td><a href="#{aid}" class="obj-link"><strong>{name}</strong></a></td><td>{members}</td><td>{iz}</td></tr>'
 return render_data_table(zones, headers, row, "No zones defined.")


def render_layer3(data: dict) -> str:
    """Render combined Layer 3 section: SD-WAN + BGP + OSPF."""
    sdwan = data.get("sdwan", {})
    bgp = data.get("bgp", {})
    ospf = data.get("ospf", {})

    sdwan_active = sdwan.get("status") == "enable"
    bgp_active = bgp.get("status") == "configured"
    ospf_active = ospf.get("status") == "configured"
    active_count = sum([bgp_active, ospf_active])

    if active_count == 0 and not sdwan_active:
        return '<div class="empty-state">No Layer 3 routing protocols configured (SD-WAN, BGP, OSPF).</div>'

    parts = []

    # ── Summary bar ──
    badges = []
    if sdwan_active:
        badges.append(f'{badge("SD-WAN", "enabled")} '
                      f'<span style="font-size:11px;color:var(--muted)">'
                      f'{len(sdwan.get("members", []))} members · '
                      f'{len(sdwan.get("services", []))} rules</span>')
    if bgp_active:
        badges.append(f'{badge("BGP", "wan")} '
                      f'<span style="font-size:11px;color:var(--muted)">'
                      f'AS {html_escape(bgp.get("as", ""))} · '
                      f'{len(bgp.get("neighbors", []))} peers</span>')
    if ospf_active:
        badges.append(f'{badge("OSPF", "info")} '
                      f'<span style="font-size:11px;color:var(--muted)">'
                      f'{len(ospf.get("areas", []))} areas · '
                      f'{len(ospf.get("interfaces", []))} interfaces</span>')

    if sdwan_active or active_count > 0:
        proto_badges = badges[1:]  # skip SD-WAN badge
        badge_html = ""
        if proto_badges:
            badge_html = f'<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">' \
                + "".join(f'<span style="display:inline-flex;align-items:center;gap:4px;'
                           f'background:var(--bg);border:1px solid var(--border);'
                           f'border-radius:6px;padding:4px 10px">{b}</span>' for b in proto_badges) \
                + '</div>'
        parts.append(
            f'<div style="margin-bottom:1.25rem;padding:12px 16px;'
            f'background:rgba(249,115,22,.06);border:1px solid rgba(249,115,22,.2);'
            f'border-radius:8px">'
            f'<div style="font-weight:700;color:var(--text);margin-bottom:6px;font-size:14px">'
            f'{active_count} Routing Protocol{"s" if active_count != 1 else ""} Active</div>'
            f'{badge_html}'
            f'</div>')

    # ── SD-WAN ──
    if sdwan_active:
        parts.append('<h3 class="sub-heading" style="border-left:3px solid #34d399;padding-left:10px">🌍 SD-WAN</h3>')
        parts.append(render_sdwan(sdwan))

    # ── BGP ──
    if bgp_active:
        parts.append('<h3 class="sub-heading" style="border-left:3px solid #f97316;padding-left:10px">🔀 BGP</h3>')
        parts.append(render_bgp(bgp))

    # ── OSPF ──
    if ospf_active:
        parts.append('<h3 class="sub-heading" style="border-left:3px solid #fbbf24;padding-left:10px">🔄 OSPF</h3>')
        parts.append(render_ospf(ospf))

    return "".join(parts)


def render_dhcp(dhcp_servers: list[dict]) -> str:
    if not dhcp_servers:
        return '<div class="empty-state">No DHCP servers configured.</div>'

    cards = []
    for d in dhcp_servers:
        status_b = badge("active", "enabled") if d.get("status", "enable") == "enable" else badge("inactive", "disabled")
        iface = d.get("interface", "")
        iface_link = _link_iface(iface) if iface else "—"

        # Scope info — network address + /CIDR
        netmask = d.get("netmask", "")
        cidr = mask_to_cidr_prefix(netmask) if netmask else ""
        ip_start = d.get("ip_start", "")
        ip_end = d.get("ip_end", "")
        # Compute network address from ip_start + netmask
        network_addr = ip_start
        if ip_start and netmask and cidr:
         network_addr = apply_netmask(ip_start, netmask)
        scope = f'{network_addr or "—"} – {ip_end or "—"}'
        if cidr:
         scope += f' /{cidr}'

        # Details columns
        details = []
        if d.get("gateway"):
            details.append(f'<span>GW: <strong>{html_escape(d["gateway"])}</strong></span>')
        if d.get("lease_time"):
            details.append(f'<span>Lease: {html_escape(d["lease_time"])}s</span>')
        if d.get("domain"):
            details.append(f'<span>Domain: {html_escape(d["domain"])}</span>')
        dns = d.get("dns_servers", [])
        if dns:
            details.append(f'<span>DNS: {" ".join(html_escape(s) for s in dns)}</span>')
        ntp = d.get("ntp_servers", [])
        if ntp:
            details.append(f'<span>NTP: {" ".join(html_escape(s) for s in ntp)}</span>')
        opts = d.get("options", [])
        if opts:
            details.append(f'<span>Options: {" ".join(html_escape(o) for o in opts)}</span>')
        ex = d.get("excludes", [])
        if ex:
            details.append(f'<span style="color:var(--amber)">Excluded: {" ".join(html_escape(e) for e in ex)}</span>')

        cards.append(f'''
<div class="policy-card" id="dhcp-{html_escape(d['id'])}">
 <div class="policy-header" onclick="togglePolicy(this)">
  <span class="policy-seq">DHCP</span>
  <span class="policy-name">{html_escape(d['id'])} · {iface_link}</span>
  <div class="policy-badges">{status_b}</div>
  <span class="policy-caret">▼</span>
 </div>
 <div class="policy-body">
  <div style="padding:.75rem 0">
   <div style="font-family:var(--mono);font-size:14px;color:var(--accent);margin-bottom:.5rem">{scope}</div>
   <div style="display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted)">{''.join(f'<span style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:4px 8px">{d}</span>' for d in details)}</div>
  </div>
 </div>
</div>''')

    return "".join(cards)


def render_ha(ha: dict) -> str:
    ha_mode = ha.get("mode", "standalone")
    if ha_mode == "standalone":
        return '<div class="empty-state">HA not configured (standalone device).</div>'

    ha_labels = {"a-p": "Active-Passive", "a-a": "Active-Active"}
    mode_display = ha_labels.get(ha_mode, ha_mode)
    parts = []
    parts.append(
        f'<div style="margin-bottom:1rem;padding:12px 16px;'
        f'background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.3);'
        f'border-radius:8px;display:flex;flex-wrap:wrap;gap:12px;align-items:center;font-size:13px">'
        f'<span><strong>HA Mode:</strong> {html_escape(mode_display)}</span>'
    )
    if ha.get("group_name"):
        parts[0] += f'<span><strong>Group:</strong> {html_escape(ha["group_name"])}</span>'
    if ha.get("group_id"):
        parts[0] += f'<span><strong>ID:</strong> {html_escape(ha["group_id"])}</span>'
    parts[0] += f'<span><strong>Priority:</strong> {html_escape(ha.get("priority", "—"))}</span>'
    parts[0] += '</div>'

    # Detail rows
    rows = []
    hb = ", ".join(html_escape(i) for i in ha.get("hb_interface", [])) or "—"
    rows.append(["Heartbeat interfaces", hb])
    rows.append(["Heartbeat lost threshold", html_escape(ha.get("hb_lost_threshold", "—"))])
    rows.append(["Override", badge(ha.get("override", "disable"), "enabled" if ha["override"] == "enable" else "disabled")])
    rows.append(["Session sync", html_escape(ha.get("session_sync", "—"))])
    rows.append(["Session pickup", badge(ha.get("session_pickup", "disable"), "enabled" if ha.get("session_pickup") == "enable" else "disabled")])
    rows.append(["Unicast heartbeat", badge(ha.get("unicast", "disable"), "enabled" if ha.get("unicast") == "enable" else "disabled")])
    peers = ha.get("peer_ips", [])
    rows.append(["Peer IPs", ", ".join(html_escape(p) for p in peers) if peers else "—"])
    rows.append(["Encryption", badge(ha.get("encryption", "disable"), "enabled" if ha.get("encryption") == "enable" else "disabled")])
    if ha.get("password_set"):
     rows.append(["Password", badge("set", "mfa")])
    if ha.get("hb_interval"):
     rows.append(["HB interval", html_escape(ha["hb_interval"])])
    monitored = ha.get("monitored", [])
    rows.append(["Monitored interfaces", ", ".join(_link_iface(m) for m in monitored) if monitored else "—"])

    parts.append(table_html(["Setting", "Value"], rows))

    # Virtual clusters
    vcs = ha.get("vclusters", [])
    if vcs:
        parts.append('<h3 class="sub-heading">Virtual Clusters</h3>')
        vc_rows = []
        for v in vcs:
            mon = ", ".join(_link_iface(m) for m in v.get("monitor", [])) or "—"
            vc_rows.append([
                html_escape(v["id"]),
                html_escape(v.get("vdom", "—")),
                html_escape(v.get("priority", "—")),
                badge(v.get("override", "disable"), "enabled" if v.get("override") == "enable" else "disabled"),
                mon,
            ])
        parts.append(table_html(
            ["VCluster", "VDOM", "Priority", "Override", "Monitored"],
            vc_rows))

    return "".join(parts)


def render_shapers(shapers_data: dict) -> str:
    shapers = shapers_data.get("shapers", [])
    per_ip = shapers_data.get("per_ip", [])
    policies = shapers_data.get("policies", [])

    if not shapers and not per_ip and not policies:
        return '<div class="empty-state">No traffic shaping configured.</div>'

    parts = []

    # Shaper definitions
    if shapers:
        s_rows = []
        for s in shapers:
            s_rows.append([
                html_escape(s["name"]),
                html_escape(s.get("guaranteed", "—") or "—"),
                html_escape(s.get("maximum", "—") or "—"),
                badge(s.get("priority", "high"), s.get("priority", "high")),
                badge(s.get("per_policy", "disable"), "enabled" if s.get("per_policy") == "enable" else "disabled"),
                html_escape(s.get("cos", "—") or "—"),
            ])
        parts.append('<h3 class="sub-heading">Bandwidth Definitions</h3>')
        parts.append(table_html(
            ["Name", "Guaranteed BW", "Maximum BW", "Priority", "Per-Policy", "CoS"],
            s_rows))

    # Per-IP shapers
    if per_ip:
        p_rows = []
        for p in per_ip:
            p_rows.append([
                html_escape(p["name"]),
                html_escape(p.get("max_bandwidth", "—") or "—"),
                html_escape(p.get("max_concurrent", "—") or "—"),
            ])
        parts.append('<h3 class="sub-heading">Per-IP Shapers</h3>')
        parts.append(table_html(
            ["Name", "Max Bandwidth", "Max Sessions"], p_rows))

    # Shaping policies
    if policies:
        sp_rows = []
        for p in policies:
            src_intf = ", ".join(_link_iface(i) for i in p.get("srcintf", [])) or "—"
            dst_intf = ", ".join(_link_iface(i) for i in p.get("dstintf", [])) or "—"
            src_addr = ", ".join(html_escape(a) for a in p.get("srcaddr", [])) or "all"
            dst_addr = ", ".join(html_escape(a) for a in p.get("dstaddr", [])) or "all"
            sp_rows.append([
                html_escape(p["seq"]),
                html_escape(p.get("name", "—") or "—"),
                src_intf,
                dst_intf,
                src_addr + " → " + dst_addr,
                html_escape(p.get("traffic_shaper", "—") or "—"),
                html_escape(p.get("traffic_shaper_reverse", "—") or "—"),
                html_escape(p.get("per_ip_shaper", "—") or "—"),
                badge(p.get("status", "enabled"), p.get("status", "enabled")),
            ])
        parts.append('<h3 class="sub-heading">Shaping Policies</h3>')
        parts.append(table_html(
            ["#", "Name", "Src Intf", "Dst Intf", "Src → Dst",
             "Shaper", "Reverse Shaper", "Per-IP", "Status"],
            sp_rows))

    return "".join(parts)


def render_certificates(certs: list[dict]) -> str:
 headers = ["Certificate", "Range", "Source", "Subject", "Comment"]
 def row(c):
  subj = html_escape(c.get("subject", c["name"])) or html_escape(c["name"])
  san_str = ", ".join(html_escape(s) for s in c.get("sans", [])[:3])
  if len(c.get("sans", [])) > 3:
   san_str += f" +{len(c['sans']) - 3}"
  return (f'<tr><td><strong>{subj}</strong></td>'
    f'<td>{html_escape(c.get("range", "—") or "—")}</td>'
    f'<td>{badge(c.get("source", "—") or "—", "info")}</td>'
    f'<td>{san_str or "—"}</td>'
    f'<td>{html_escape(c.get("comment", "—") or "—")}</td></tr>')
 return render_data_table(certs, headers, row, "No user-defined certificates found.")
def render_vlans(interfaces: list[dict]) -> str:
 """Render VLAN interface overview (parent + VLAN ID)."""
 vlans = [i for i in interfaces if i.get("type") == "vlan"]
 headers = ["VLAN Interface", "VLAN ID", "Parent Interface", "IP / CIDR", "Role", "Access", "Description"]
 def row(v):
  name = html_escape(v['name']); aid = anchor_id(v['name'], "iface-"); role = v.get("role", "")
  return (f'<tr id="{aid}"><td><a href="#{aid}" class="obj-link"><strong>{name}</strong></a></td>'
    f'<td>{html_escape(v.get("vlanid", "—"))}</td>'
    f'<td>{_link_iface(v.get("interface", "—"))}</td>'
    f'<td>{html_escape(v.get("cidr", "") or v.get("ip", "") or "—")}</td>'
    f'<td>{badge(role, role) if role else "—"}</td>'
    f'<td>{html_escape(v.get("access", "") or "—")}</td>'
    f'<td>{html_escape(v.get("description", "") or "—")}</td></tr>')
 return render_data_table(vlans, headers, row, "No VLAN interfaces found.")


def render_sdwan(sdwan: dict) -> str:
    if sdwan.get("status") != "enable":
        return '<div class="empty-state">SD-WAN not configured or disabled.</div>'

    parts = []
    parts.append(f'<div class="sdwan-status" style="margin-bottom:1rem;padding:10px 14px;'
                 f'background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.3);'
                 f'border-radius:8px;display:flex;align-items:center;gap:10px">'
                 f'<span style="font-size:24px">🟢</span>'
                 f'<div><strong>SD-WAN Active</strong> · '
                 f'{len(sdwan["zones"])} zones · {len(sdwan["members"])} members · '
                 f'{len(sdwan["health_checks"])} health checks · '
                 f'{len(sdwan["services"])} service rules</div></div>')

    # ── Zones ──
    zones = sdwan.get("zones", [])
    if zones:
        z_rows = []
        for z in zones:
            z_rows.append([
                html_escape(z["name"]),
                html_escape(z["sla_tie_break"]),
            ])
        parts.append('<h3 class="sub-heading">SD-WAN Zones</h3>')
        parts.append(table_html(["Zone", "SLA Tie-break"], z_rows,
                                "No zones defined."))

    # ── Precompute helpers ──
    members = sdwan.get("members", [])
    health_checks = sdwan.get("health_checks", [])

    # Build map: member_seq → list of health check names
    member_hc_map: dict[str, list[str]] = {m["seq"]: [] for m in members}
    for hc in health_checks:
        for m_seq in hc.get("members", []):
            if m_seq in member_hc_map:
                member_hc_map[m_seq].append(hc["name"])

    # ════════════════════════════════════════════════════════════════════
    # 🃏 Member Health Cards
    # ════════════════════════════════════════════════════════════════════
    if members:
        cards_html = ""
        for m in members:
            iface = m.get("interface", "")
            iface_link = _link_iface(iface) if iface else "—"
            is_up = m.get("status", "enable") == "enable"
            status_icon = "🟢" if is_up else "🔴"
            status_text = "UP" if is_up else "DOWN"
            status_color = "var(--green)" if is_up else "var(--red)"
            status_bg = "rgba(52,211,153,.1)" if is_up else "rgba(248,113,113,.1)"
            status_border = "rgba(52,211,153,.35)" if is_up else "rgba(248,113,113,.35)"

            hc_list = member_hc_map.get(m["seq"], [])
            hc_pills = ""
            if hc_list:
                hc_pills = "".join(
                    f'<span style="background:var(--bg);border:1px solid var(--border);'
                    f'border-radius:4px;padding:2px 8px;font-size:10px;'
                    f'font-family:var(--mono);color:var(--muted)">{html_escape(h)}</span>'
                    for h in hc_list
                )

            hc_section = (
                f'<div style="margin-top:2px;display:flex;flex-wrap:wrap;'
                f'gap:4px;align-items:center">'
                f'<span style="font-size:9px;text-transform:uppercase;'
                f'letter-spacing:.06em;color:var(--dim);font-weight:600">'
                f'🔍 Health Checks</span>{hc_pills}</div>'
            ) if hc_pills else (
                '<div style="font-size:10px;color:var(--dim);'
                'font-style:italic">No health checks assigned</div>'
            )
            cards_html += f'''
<div class="sdwan-member-card" style="background:var(--surface);border:1px solid var(--border);
 border-radius:8px;padding:14px;display:flex;flex-direction:column;gap:8px;transition:border-color .2s">
 <div style="display:flex;align-items:center;gap:8px">
  <span style="font-family:var(--mono);font-size:13px;font-weight:600;
   color:var(--accent);min-width:30px">#{html_escape(m["seq"])}</span>
  <span style="font-size:14px;font-weight:600;color:var(--text);flex:1">{iface_link}</span>
  <span style="padding:3px 10px;border-radius:20px;font-size:10px;font-weight:600;
   font-family:var(--mono);color:{status_color};background:{status_bg};
   border:1px solid {status_border}">{status_icon} {status_text}</span>
 </div>
 <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;font-size:12px">
  <div><span style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.04em">Zone</span><br>
   <span style="font-family:var(--mono)">{html_escape(m.get("zone", "") or "—")}</span></div>
  <div><span style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.04em">Source IP</span><br>
   <span style="font-family:var(--mono)">{html_escape(m.get("source", "") or "—")}</span></div>
  <div><span style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.04em">Gateway</span><br>
   <span style="font-family:var(--mono)">{html_escape(m.get("gateway", "") or "—")}</span></div>
  <div><span style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.04em">Weight</span><br>
   <span style="font-family:var(--mono)">{html_escape(m.get("weight", "") or "—")}</span></div>
  <div><span style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.04em">Priority</span><br>
   <span style="font-family:var(--mono)">{html_escape(m.get("priority", "") or "—")}</span></div>
  <div><span style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.04em">Cost</span><br>
   <span style="font-family:var(--mono)">{html_escape(m.get("cost", "") or "—")}</span></div>
 </div>
 {hc_section}
</div>'''
        parts.append('<h3 class="sub-heading">SD-WAN Member Health Cards</h3>')
        parts.append(f'<div class="sdwan-card-grid" style="display:grid;'
                     f'grid-template-columns:repeat(auto-fill,minmax(320px,1fr));'
                     f'gap:12px;margin-bottom:1.5rem">{cards_html}</div>')

    # ════════════════════════════════════════════════════════════════════
    # 🔬 SLA Health Check Status Indicators
    # ════════════════════════════════════════════════════════════════════
    if health_checks:
        sla_html = ""
        for hc in health_checks:
            proto_b = badge(hc.get("protocol", "ping"), hc.get("protocol", "ping"))
            server = html_escape(hc.get("server", ""))
            interval = html_escape(hc.get("interval", "") or "—")
            failtime = html_escape(hc.get("failtime", "") or "—")
            members_checked = hc.get("members", [])

            # Build per-member status pills
            indicators = ""
            for m_seq in sorted(members_checked):
                member = next((m for m in members if m["seq"] == m_seq), None)
                if member:
                    m_up = member.get("status", "enable") == "enable"
                    m_color = "var(--green)" if m_up else "var(--red)"
                    m_icon = "🟢" if m_up else "🔴"
                    m_iface = html_escape(member.get("interface", m_seq))
                    indicators += (
                        f'<span style="display:inline-flex;align-items:center;gap:4px;'
                        f'padding:3px 10px;border-radius:20px;font-size:10px;'
                        f'font-family:var(--mono);color:{m_color};'
                        f'background:var(--bg);border:1px solid var(--border)">'
                        f'{m_icon} {m_iface}</span>')
                else:
                    indicators += (
                        f'<span style="display:inline-flex;align-items:center;gap:4px;'
                        f'padding:3px 10px;border-radius:20px;font-size:10px;'
                        f'font-family:var(--mono);color:var(--dim);'
                        f'background:var(--bg);border:1px solid var(--border)">'
                        f'⚫ #{html_escape(m_seq)}</span>')
            if not indicators:
                indicators = ('<span style="color:var(--dim);font-size:11px;font-style:italic">'
                              'No members assigned</span>')

            sla_html += f'''
<div class="sla-check-card" style="background:var(--surface);border:1px solid var(--border);
 border-radius:8px;padding:14px;margin-bottom:10px">
 <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap">
  <span style="font-size:14px;font-weight:600;color:var(--text)">{html_escape(hc["name"])}</span>
  {proto_b}
  <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">
   → {server}</span>
  <span style="margin-left:auto;font-size:10px;color:var(--dim);font-family:var(--mono);
   white-space:nowrap">⏱ {interval}ms · {failtime} failures</span>
 </div>
 <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding:8px 12px;
  background:var(--bg);border-radius:6px">
  <span style="font-size:9px;text-transform:uppercase;letter-spacing:.06em;
   color:var(--dim);font-weight:600;margin-right:4px">Monitors</span>
  {indicators}
 </div>'''
            # ── SLA Targets ──
            sla_targets = hc.get("sla_targets", [])
            if sla_targets:
                sla_items = ""
                for st in sla_targets:
                    parts_inner = []
                    lt = st.get("latency_threshold", "")
                    jt = st.get("jitter_threshold", "")
                    plt = st.get("packetloss_threshold", "")
                    lcf = st.get("link_cost_factor", "")
                    if lt:
                        parts_inner.append(f'Latency: ≤{html_escape(lt)}ms')
                    if jt:
                        parts_inner.append(f'Jitter: ≤{html_escape(jt)}ms')
                    if plt:
                        parts_inner.append(f'Loss: ≤{html_escape(plt)}%')
                    if lcf:
                        parts_inner.append(f'Factor: {html_escape(lcf)}')
                    sla_label = f'SLA #{html_escape(st["id"])}'
                    sla_items += (f'<div style="padding:3px 8px;background:rgba(251,191,36,.1);'
                                 f'border:1px solid rgba(251,191,36,.25);border-radius:4px;'
                                 f'font-size:10px;font-family:var(--mono);color:var(--amber)">'
                                 f'<strong>{sla_label}</strong>: {" | ".join(parts_inner) if parts_inner else "—"}</div>')
                sla_html += (f'<div style="margin-top:8px;display:flex;flex-wrap:wrap;'
                            f'gap:4px;align-items:center">'
                            f'<span style="font-size:9px;text-transform:uppercase;letter-spacing:.06em;'
                            f'color:var(--dim);font-weight:600">🎯 SLA Targets</span>{sla_items}</div>')
            sla_html += '</div>'''
        parts.append('<h3 class="sub-heading">SLA Health Check Status</h3>')
        parts.append(sla_html)

    # ── Members Detail Table (existing, preserved) ──
    if members:
        m_rows = []
        for m in members:
            iface = m.get("interface", "")
            iface_link = _link_iface(iface) if iface else "—"
            status_b = badge("up", "enabled") if m.get("status", "enable") == "enable" else badge("down", "disabled")
            m_rows.append([
                html_escape(m["seq"]),
                iface_link,
                html_escape(m.get("zone", "") or "—"),
                html_escape(m.get("source", "") or "—"),
                html_escape(m.get("gateway", "") or "—"),
                html_escape(m.get("priority", "") or "—"),
                html_escape(m.get("weight", "") or "—"),
                html_escape(m.get("cost", "") or "—"),
                status_b,
            ])
        parts.append('<h3 class="sub-heading">SD-WAN Members Detail</h3>')
        parts.append(table_html(
            ["#", "Interface", "Zone", "Source", "Gateway",
             "Priority", "Weight", "Cost", "Status"],
            m_rows, "No members defined."))

    # ── Health Checks Detail Table (existing, preserved) ──
    if health_checks:
        hc_rows = []
        for h in health_checks:
            hc_rows.append([
                html_escape(h["name"]),
                html_escape(h["server"]),
                badge(h["protocol"], h["protocol"]),
                html_escape(", ".join(h["members"])) if h["members"] else "—",
                html_escape(h.get("interval", "") or "—") + " ms",
                html_escape(h.get("failtime", "") or "—") + " failures",
            ])
        parts.append('<h3 class="sub-heading">Health Checks Detail</h3>')
        parts.append(table_html(
            ["Name", "Server", "Protocol", "Member Seqs",
             "Interval", "Fail Threshold"],
            hc_rows, "No health checks defined."))

    # ════════════════════════════════════════════════════════════════════
    # 📊 SD-WAN Rules (compact)
    # ════════════════════════════════════════════════════════════════════
    services = sdwan.get("services", [])
    if services:
        svc_rows = []
        for s in services:
            src = ", ".join(_link_grp(a) for a in s.get("src", [])) or "all"
            dst = ", ".join(_link_grp(a) for a in s.get("dst", [])) or "all"
            prio_mems = ", ".join(_link_iface(m) for m in s.get("priority_members", [])) or "—"
            hc_names = ", ".join(html_escape(h) for h in s.get("health_check", [])) or "—"
            svc_rows.append([
                html_escape(s["seq"]),
                f'<strong>{html_escape(s["name"])}</strong>',
                badge(s["mode"], s["mode"]),
                f'<span style="font-family:var(--mono);font-size:11px">{src}</span>',
                f'<span style="font-family:var(--mono);font-size:11px">{dst}</span>',
                f'<span style="font-family:var(--mono);font-size:11px">{prio_mems}</span>',
                hc_names,
            ])
        parts.append('<h3 class="sub-heading">SD-WAN Rules</h3>')
        parts.append(table_html(
            ["#", "Name", "Mode", "Source", "Destination",
             "Priority Members", "Health Check"],
            svc_rows, "No service rules defined."))

    return "".join(parts)


def render_bgp(bgp: dict) -> str:
    if bgp.get("status") != "configured":
        return '<div class="empty-state">BGP not configured.</div>'

    parts = []

    # ── Summary card ──
    summary = (
        f'<div style="margin-bottom:1rem;padding:10px 14px;'
        f'background:rgba(249,115,22,.06);border:1px solid rgba(249,115,22,.25);'
        f'border-radius:6px;display:flex;flex-wrap:wrap;gap:12px;font-size:13px">'
        f'<span><strong>AS:</strong> {html_escape(bgp["as"])}</span>'
        f'<span><strong>Router-ID:</strong> {html_escape(bgp["router_id"])}</span>'
    )
    if bgp.get("ebgp_multipath") == "enable":
        summary += f'<span>{badge("ECMP", "enabled")}</span>'
    summary += '</div>'
    parts.append(summary)

    # ── Redistribution ──
    redist = bgp.get("redistribute", [])
    active_redist = [r for r in redist if r.get("status") == "enable"]
    if active_redist:
        parts.append(
            f'<div style="margin-bottom:1rem;font-size:12px;color:var(--muted)">'
            f'Redistributing: {", ".join(badge(r["protocol"], "enabled") for r in active_redist)}'
            f'</div>')

    # ── Neighbors ──
    neighbors = bgp.get("neighbors", [])
    if neighbors:
        n_rows = []
        for n in neighbors:
            remote_as = n["remote_as"]
            ebgp = remote_as != bgp.get("as", "") and remote_as != ""
            peer_type = badge("eBGP", "wan") if ebgp else badge("iBGP", "info")
            n_rows.append([
                html_escape(n["ip"]),
                html_escape(remote_as),
                peer_type,
                html_escape(n.get("description", "") or "—"),
                badge(n.get("soft_reconfig", "disable"), "enabled" if n.get("soft_reconfig") == "enable" else "disabled"),
                html_escape(n.get("update_source", "") or "—"),
                html_escape(n.get("route_map_in", "") or n.get("prefix_list_in", "") or "—"),
                html_escape(n.get("route_map_out", "") or n.get("prefix_list_out", "") or "—"),
                badge("self", "enabled") if n.get("next_hop_self") == "enable" else "—",
            ])
        parts.append('<h3 class="sub-heading">BGP Neighbors</h3>')
        parts.append(table_html(
            ["Peer IP", "Remote AS", "Type", "Description",
             "Soft Reconfig", "Update Source", "Filter IN", "Filter OUT",
             "Next-Hop-Self"],
            n_rows, "No BGP neighbors defined."))

    # ── Networks ──
    networks = bgp.get("networks", [])
    if networks:
        net_rows = [[html_escape(n["seq"]), html_escape(n["prefix"])]
                     for n in networks]
        parts.append('<h3 class="sub-heading">Advertised Networks</h3>')
        parts.append(table_html(["#", "Prefix"], net_rows,
                                "No networks advertised."))

    return "".join(parts)


def render_ospf(ospf: dict) -> str:
    if ospf.get("status") != "configured":
        return '<div class="empty-state">OSPF not configured.</div>'

    parts = []

    # ── Summary card ──
    summary = (
        f'<div style="margin-bottom:1rem;padding:10px 14px;'
        f'background:rgba(249,115,22,.06);border:1px solid rgba(249,115,22,.25);'
        f'border-radius:6px;display:flex;flex-wrap:wrap;gap:12px;font-size:13px">'
        f'<span><strong>Router-ID:</strong> {html_escape(ospf["router_id"])}</span>'
    )
    if ospf.get("default_metric"):
        summary += f'<span><strong>Default Metric:</strong> {html_escape(ospf["default_metric"])}</span>'
    summary += f'<span>{len(ospf["areas"])} areas</span>'
    summary += '</div>'
    parts.append(summary)

    # ── Redistribution ──
    redist = ospf.get("redistribute", [])
    active_redist = [r for r in redist if r.get("status") == "enable"]
    if active_redist:
        parts.append(
            f'<div style="margin-bottom:1rem;font-size:12px;color:var(--muted)">'
            f'Redistributing: {", ".join(badge(r["protocol"], "enabled") for r in active_redist)}'
            f'</div>')

    # ── Areas ──
    areas = ospf.get("areas", [])
    if areas:
        a_rows = []
        for a in areas:
            area_type = a.get("type", "regular")
            type_badge = badge(area_type, area_type)
            auth = html_escape(a.get("authentication") or "—")
            a_rows.append([html_escape(a["id"]), type_badge, auth])
        parts.append('<h3 class="sub-heading">OSPF Areas</h3>')
        parts.append(table_html(["Area ID", "Type", "Authentication"],
                                a_rows, "No areas defined."))

    # ── Networks ──
    networks = ospf.get("networks", [])
    if networks:
        n_rows = [[html_escape(n["seq"]),
                   html_escape(n["prefix"]),
                   html_escape(n.get("area", "") or "—")]
                  for n in networks]
        parts.append('<h3 class="sub-heading">Network Advertisements</h3>')
        parts.append(table_html(["#", "Prefix", "Area"],
                                n_rows, "No networks defined."))

    # ── Interfaces ──
    interfaces = ospf.get("interfaces", [])
    if interfaces:
        i_rows = []
        for i in interfaces:
            iface = i.get("interface", "")
            iface_link = _link_iface(iface) if iface else "—"
            i_rows.append([
                html_escape(i["name"]),
                iface_link,
                html_escape(i.get("network_type", "") or "—"),
                html_escape(i.get("cost", "") or "—"),
                html_escape(i.get("hello_interval", "") or "—"),
                html_escape(i.get("dead_interval", "") or "—"),
                badge("passive", "info") if i.get("passive") == "enable" else "—",
            ])
        parts.append('<h3 class="sub-heading">OSPF Interfaces</h3>')
        parts.append(table_html(
            ["Name", "Interface", "Network Type", "Cost",
             "Hello", "Dead", "Passive"],
            i_rows, "No OSPF interfaces defined."))

    return "".join(parts)
def render_findings(findings: list[dict]) -> str:
 """Render a dedicated full-page findings section with CIS refs and remediation."""
 if not findings:
  return '<div class="empty-state">No findings detected. Device is well-hardened!</div>'

 # Group by (admin-effective) severity
 groups = {"high": [], "medium": [], "low": [], "info": []}
 for f in findings:
  s = _eff_sev(f)
  if s not in groups:
   s = "info"
  groups[s].append(f)

 def render_finding_group(sev: str, label: str, count_cls: str, color: str, items: list) -> str:
  if not items:
   return ""
  items_html = ""
  for f in items:
   snip = (f.get("snippet") or "").strip()
   snip_html = (f'<pre class="finding-snippet">{html_escape(snip)}</pre>'
                if snip else "")
   items_html += (
    f'<div class="finding finding-{sev}">'
    f'<div class="finding-title">'
    f'{badge(f.get("cis_ref", sev.upper()), sev)} '
    f'<a href="#{html_escape(f.get("target_id", ""))}" class="finding-link">'
    f'<strong>{html_escape(f["title"])}</strong></a></div>'
    f'<div class="finding-detail">{html_escape(f["detail"])}</div>'
    f'{snip_html}'
    f'<div class="finding-remediation">💡 {html_escape(f.get("override_remediation") or f.get("remediation", ""))}</div>'
    f'</div>'
   )
  return (f'<div class="finding-group">'
    f'<div class="finding-group-header" role="button" tabindex="0" aria-expanded="false" '
    f'onclick="toggleFindings(this)" '
    f'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){{event.preventDefault();toggleFindings(this)}}">'
    f'<span class="dot" style="background:{color}"></span>'
    f'<span class="fg-lbl">{label}</span>'
    f'<span class="fg-count {count_cls}">{len(items)}</span>'
    f'<span class="fg-state">COLLAPSED</span>'
    f'<span class="chev"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg></span>'
    f'</div>'
    f'<div class="finding-group-body" style="border-left-color:{color}">'
    f'<div class="findings-list">{items_html}</div></div></div>')

 html = ""
 for sev, label, count_cls, color in [
  ("high", "High severity", "red", "var(--red)"),
  ("medium", "Medium severity", "amber", "var(--amber)"),
  ("low", "Low severity", "green", "var(--green)"),
  ("info", "Informational", "blue", "var(--blue)"),
 ]:
  html += render_finding_group(sev, label, count_cls, color, groups[sev])

 return html


def render_admins(admins: list[dict]) -> str:
 rows = []
 for a in admins:
  mfa = (badge(a["two_factor"], "mfa")
      if a["two_factor"] not in ("disable", "")
      else badge("none", "disabled"))
  hosts = (", ".join(a["trusted_hosts"])
       if a["trusted_hosts"]
       else badge("unrestricted ⚠", "high"))
  rows.append([
   html_escape(a["username"]),
   badge(a["profile"],
     "high" if a["profile"] == "super_admin" else "default"),
   html_escape(a["vdom"]),
   mfa,
   badge("set", "mfa") if a["ssh_key"] else "—",
   hosts,
   html_escape(a["comments"] or "—"),
  ])
 return table_html(
  ["Username", "Profile", "VDOM", "2FA", "SSH key", "Trusted hosts", "Comments"],
  rows, "No admin accounts found (section may be suppressed)")





# ══════════════════════════════════════════════════════════════════════════════
# NEW REPORT DESIGN — single-column "magazine" (port of new_report.html)
# The classic sidebar report is replaced by 9 numbered panels built from the
# same extractors. Summary components (stats, donut, kv, bars, vpn grid) are
# rendered here; the full per-object data tables/cards reuse the existing
# render_* functions, restyled by static/report.css.
# ══════════════════════════════════════════════════════════════════════════════

# Thin-stroke overview stat icons (colors via .chip.c-* css classes)
_STAT_ICONS = {
    "interfaces": ("c-blue", '<path d="m15 20 3-3h2a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h2l3 3z"/><path d="M6 8v1M10 8v1M14 8v1M18 8v1"/>'),
    "policies": ("c-orange", '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>'),
    "vpn": ("c-green", '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>'),
    "admins": ("c-amber2", '<circle cx="12" cy="8" r="5"/><path d="M20 21a8 8 0 0 0-16 0"/>'),
    "addresses": ("c-blue", '<path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/><path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65"/><path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"/>'),
    "routes": ("c-amber", '<circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/>'),
    "dhcp": ("c-red", '<path d="m3 17 2 2 4-4"/><path d="m3 7 2 2 4-4"/><path d="M13 6h8M13 12h8M13 18h8"/>'),
    "vlans": ("c-green", '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>'),
}

def _stat(key: str, value, label: str) -> str:
    color, paths = _STAT_ICONS.get(key, ("c-blue", ""))
    if isinstance(value, str) and " / " in value:
        a, b = value.split(" / ", 1)
        value_html = f'{html_escape(a)}<span class="slash"> / </span>{html_escape(b)}'
    else:
        value_html = html_escape(str(value))
    return (f'<div class="stat"><div class="stat-chip {color}"><svg class="ic" viewBox="0 0 24 24">{paths}</svg></div>'
            f'<div class="val">{value_html}</div>'
            f'<div class="lbl">{html_escape(label)}</div></div>')

def _panel(title: str, inner: str, cls: str = "") -> str:
    c = f" {cls}" if cls else ""
    return f'<div class="panel{c}"><div class="p-title">{title}</div>{inner}</div>'

def _kv(label: str, value_html: str) -> str:
    return f'<div class="kv"><span>{html_escape(label)}</span><span>{value_html}</span></div>'

def _bar(label: str, count: int, maxc: int, color: str = "var(--blue)") -> str:
    w = round(100 * count / maxc) if maxc else 0
    return (f'<div class="bar-row"><span>{html_escape(label)}</span>'
            f'<span class="sev-bar"><i style="width:{w}%;background:{color}"></i></span>'
            f'<b>{count}</b></div>')

def _mag_section(num: int, sid: str, title: str, inner: str) -> str:
    return (f'<section class="section" id="{sid}">'
            f'<div class="sec-head"><span class="sec-num">{num:02d}</span>'
            f'<span class="sec-title">{html_escape(title)}</span><span class="sec-line"></span></div>'
            f'{inner}</section>')

def _mag_sub(sid: str, title: str, content: str) -> str:
    """Collapsible sub-block inside a panel group (keeps data at a glance)."""
    return (f'<div class="section-sub" id="{sid}" data-collapsed="true">'
            f'<div class="subhead" role="button" tabindex="0" aria-expanded="false" '
            f'onclick="toggleSub(this)" '
            f'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){{event.preventDefault();toggleSub(this)}}">'
            f'<span class="subhead-title">{html_escape(title)}</span>'
            f'<span class="subhead-state">COLLAPSED</span>'
            f'<span class="chev"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg></span>'
            f'</div>'
            f'<div class="subhead-body">{content}</div></div>')

def _fw76_plus(data: dict) -> bool:
    fw = data.get("version_info", {}).get("firmware", "")
    if not fw:
        return False
    try:
        parts = fw.split(".")
        major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
        return major > 7 or (major == 7 and minor >= 6)
    except (ValueError, IndexError):
        return False

def render_mag_atglance(data: dict, meta: dict) -> str:
    policies = data["policies"]
    pol_on = sum(1 for p in policies if p["status"] == "enabled")
    stats = [
        _stat("interfaces", len(data["interfaces"]), "INTERFACES"),
        _stat("policies", f"{pol_on} / {len(policies)}", "POLICIES ACTIVE"),
        _stat("vpn", len(data["vpn_s2s"]), "IPSEC TUNNELS"),
        _stat("admins", len(data["admins"]), "ADMINISTRATORS"),
        _stat("addresses", len(data["addresses"]), "ADDRESS OBJECTS"),
        _stat("routes", len(data["routes"]), "STATIC ROUTES"),
        _stat("dhcp", len(data.get("dhcp_details", [])), "DHCP SCOPES"),
        _stat("vlans", len([i for i in data["interfaces"] if i.get("type") == "vlan"]), "VLAN INTERFACES"),
    ]
    return '<div class="stats">' + "".join(stats) + "</div>"

def render_mag_findings(data: dict) -> str:
    findings = data["findings"]
    groups = {"high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        s = _eff_sev(f)
        groups[s if s in groups else "info"].append(f)
    total = len(findings)
    n_high = len(groups["high"]); n_med = len(groups["medium"])
    n_low = len(groups["low"]); n_info = len(groups["info"])
    colors = {"high": "var(--red)", "medium": "var(--amber)",
              "low": "var(--green)", "info": "var(--blue)"}
    if total:
        bounds = [0.0]
        for k in ("high", "medium", "low", "info"):
            bounds.append(bounds[-1] + 360 * len(groups[k]) / total)
        stops = (f"{colors['high']} 0 {bounds[1]:.0f}deg, "
                 f"{colors['medium']} {bounds[1]:.0f}deg {bounds[2]:.0f}deg, "
                 f"{colors['low']} {bounds[2]:.0f}deg {bounds[3]:.0f}deg, "
                 f"{colors['info']} {bounds[3]:.0f}deg 360deg")
        donut = f'<div class="donut" style="background:conic-gradient({stops})">'
    else:
        donut = '<div class="donut" style="background:conic-gradient(var(--border) 0 360deg)">'
    donut += f'<div class="donut-c"><b>{total}</b><span>FINDINGS</span></div></div>'
    sev_rows = ""
    for k, label in (("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info")):
        n = len(groups[k])
        w = round(100 * n / max(1, n_high, n_med, n_low, n_info))
        sev_rows += (f'<div class="sev-row"><span class="dot" style="background:{colors[k]}"></span>'
                     f'{label}<span class="sev-bar"><i style="width:{w}%;background:{colors[k]}"></i></span>'
                     f'<b style="color:{colors[k]}">{n}</b></div>')
    left = f'<div class="panel donut-wrap">{donut}{sev_rows}</div>'

    right_parts = []
    for k, label in (("high", "HIGH SEVERITY"), ("medium", "MEDIUM SEVERITY"),
                     ("low", "LOW SEVERITY"), ("info", "INFO NOTES")):
        n = len(groups[k])
        if not n:
            continue
        items = "".join(f'<div class="hl-item">{html_escape(f["title"])}</div>'
                        for f in groups[k][:5])
        more = f'<div class="hl-more">…{n - 5} more</div>' if n > 5 else ""
        right_parts.append(f'<div class="hl-card {k}">'
                           f'<div class="hl-head"><span class="hl-lbl">{label}</span>'
                           f'<span class="hl-num">{n}</span></div>'
                           f'<div class="hl-list">{items}{more}</div></div>')
    right = "".join(right_parts) or '<div class="panel"><div class="note">No findings detected.</div></div>'
    grid = f'<div class="fnd-grid">{left}{right}</div>'
    detail = _mag_sub("findings-detail", "FULL FINDINGS DETAIL — REMEDIATION & CONFIG SNIPPETS",
                      render_findings(findings))
    return grid + detail

def render_mag_system(data: dict, meta: dict) -> str:
    g = data["global"]
    vi = data.get("version_info", {})
    rows = []
    if vi.get("firmware"):
        fw = html_escape(vi["firmware"]) + (f" build {html_escape(vi['build'])}" if vi.get("build") else "")
        rows.append(_kv("FIRMWARE", fw))
    if vi.get("serial"):
        label = "MODEL" if vi.get("model") else "SERIAL NUMBER"
        rows.append(_kv(label, html_escape(vi["serial"])))
    if g.get("timezone"):
        rows.append(_kv("TIMEZONE", html_escape(g["timezone"])))
    if g.get("admintimeout"):
        rows.append(_kv("ADMIN TIMEOUT", html_escape(g["admintimeout"]) + " MIN"))
    if g.get("admin-sport"):
        rows.append(_kv("HTTPS ADMIN PORT", html_escape(g["admin-sport"])))
    dns = data.get("dns", {})
    dns_vals = " · ".join(x for x in (dns.get("primary"), dns.get("secondary")) if x)
    if dns_vals:
        rows.append(_kv("DNS", html_escape(dns_vals)))
    ntp = data.get("ntp", {})
    if ntp.get("sync") == "enable":
        rows.append(_kv("NTP SYNC", '<span class="ok">enabled</span>'))
        if ntp.get("servers"):
            rows.append(_kv("NTP SERVERS", html_escape(" · ".join(ntp["servers"][:3]))))
    else:
        rows.append(_kv("NTP SYNC", '<span class="bad">disabled</span>'))
    sc = str(g.get("strong-crypto", ""))
    if sc:
        rows.append(_kv("STRONG CRYPTO",
            '<span class="ok">enabled</span>' if sc == "enable" else '<span class="bad">not enabled</span>'))
    sl = data.get("syslog", {})
    rows.append(_kv("SYSLOG",
        '<span class="ok">enabled</span>' if sl.get("status") == "enable"
        else '<span class="bad">disabled</span>'))
    if sl.get("server"):
        rows.append(_kv("SYSLOG SERVER", html_escape(f"{sl['server']}:{sl.get('port', '514')}")))
    if g.get("vdom"):
        rows.append(_kv("VDOM", html_escape(g["vdom"])))
    sys_panel = _panel("SYSTEM SETTINGS", "".join(rows) or '<div class="note">No system global data.</div>')

    ha = data.get("ha", {})
    if ha.get("mode") not in (None, "", "standalone"):
        ha_labels = {"a-p": "ACTIVE-PASSIVE", "a-a": "ACTIVE-ACTIVE"}
        mode = ha_labels.get(ha["mode"], html_escape(str(ha["mode"])))
        kvs = []
        if ha.get("hb_interface"):
            kvs.append(_kv("HEARTBEAT", html_escape(" · ".join(ha["hb_interface"]))))
        if ha.get("group_name"):
            kvs.append(_kv("GROUP", html_escape(ha["group_name"])))
        if ha.get("monitored"):
            kvs.append(_kv("MONITORED", html_escape(" · ".join(ha["monitored"]))))
        kvs.append(_kv("SESSION PICKUP",
            '<span class="ok">enabled</span>' if ha.get("session_pickup") == "enable"
            else '<span class="bad">disabled</span>'))
        if ha.get("password_set"):
            kvs.append(_kv("PASSWORD", "set"))
        ha_panel = (f'<div class="panel green-b" style="margin-bottom:16px">'
                    f'<div class="panel-title green"><span class="status-dot"></span>HA CLUSTER — {mode}</div>'
                    f'{"".join(kvs)}</div>')
    else:
        ha_panel = ('<div class="panel green-b" style="margin-bottom:16px">'
                    '<div class="panel-title green"><span class="status-dot"></span>HA CLUSTER — STANDALONE</div>'
                    '<div class="note">No cluster configured — this firewall runs alone.</div></div>')

    snmp = data.get("snmp", {})
    if snmp.get("status") == "enable":
        ver = []
        for c in snmp.get("communities", []):
            if c.get("query_v1") == "enable" or c.get("trap_v1") == "enable":
                ver.append("v1")
            if c.get("trap_v2c") == "enable":
                ver.append("v2c")
        if snmp.get("users"):
            ver.append("v3")
        vtxt = " · ".join(sorted(set(ver))) or "—"
        kvs = []
        if snmp.get("location"):
            kvs.append(_kv("LOCATION", html_escape(snmp["location"])))
        if snmp.get("contact"):
            kvs.append(_kv("CONTACT", html_escape(snmp["contact"])))
        for c in snmp.get("communities", [])[:3]:
            kvs.append(_kv("COMMUNITY", html_escape(c["name"])))
            hosts = ", ".join(hh["ip"] for hh in c.get("hosts", [])[:4])
            if hosts:
                kvs.append(_kv("HOST", html_escape(hosts)))
        inner = ('<div class="panel-title green"><span class="status-dot"></span>SNMP — ENABLED '
                 f'<span style="float:right;font-family:var(--mono);font-size:10px;color:var(--dim)">{vtxt}</span></div>'
                 + "".join(kvs))
        snmp_panel = f'<div class="panel green-b">{inner}</div>'
    else:
        snmp_panel = '<div class="panel"><div class="p-title">SNMP</div><div class="note">SNMP not enabled on this device.</div></div>'

    detail = ""
    if ha.get("mode") not in (None, "", "standalone"):
        detail += _mag_sub("ha", "HA CLUSTER — FULL SETTINGS", render_ha(ha))
    if snmp.get("status") == "enable":
        detail += _mag_sub("snmp", "SNMP — COMMUNITIES & v3 USERS", render_snmp(snmp))

    return (f'<div class="two-col"><div>{sys_panel}</div>'
            f'<div>{ha_panel}{snmp_panel}</div></div>' + detail)

def render_mag_network(data: dict, meta: dict) -> str:
    ifaces = [i for i in data["interfaces"] if i.get("type") != "vlan"]
    vlans = [i for i in data["interfaces"] if i.get("type") == "vlan"]
    dhcp = data.get("dhcp_details", [])
    zones = data.get("zones", [])

    detail = ""
    if ifaces:
        detail += _mag_sub("interfaces", "ALL INTERFACES", render_interfaces(data["interfaces"]))
    if vlans:
        detail += _mag_sub("vlans", "VLAN INTERFACE DETAIL", render_vlans(data["interfaces"]))
    if dhcp:
        detail += _mag_sub("dhcp", "DHCP SERVER DETAIL", render_dhcp(dhcp))
    if zones:
        detail += _mag_sub("zones", "ZONE DETAIL", render_zones(zones))

    # no summary panels; interfaces/vlans/dhcp/zones live in the detail sub-blocks
    return detail

def render_mag_routing(data: dict, meta: dict) -> str:
    routes = data["routes"]

    l3 = render_layer3(data)
    l3_empty = "No Layer 3 routing protocols configured" in l3
    if l3_empty:
        l3_panel = ('<div class="panel"><div class="p-title">LAYER 3 — SD-WAN / BGP / OSPF</div>'
                    '<div class="note">No SD-WAN, BGP or OSPF configured.</div></div>')
    else:
        l3_panel = f'<div class="panel"><div class="p-title">LAYER 3 — SD-WAN / BGP / OSPF</div>{l3}</div>'

    detail = ""
    if routes:
        detail += _mag_sub("routes", "ALL STATIC ROUTES", render_routes(routes))
    if data.get("policy_routes"):
        detail += _mag_sub("policy_routes", "POLICY ROUTES", render_policy_routes(data["policy_routes"]))
    return l3_panel + detail

def render_mag_policies(data: dict, meta: dict) -> str:
    policies = data["policies"]
    n = len(policies)
    act = sum(1 for p in policies if p["status"] == "enabled")
    dis = n - act
    acc = sum(1 for p in policies if p["action"] == "accept")
    den = max(n - acc, 0)
    nat_n = sum(1 for p in policies if p.get("nat"))
    nocomm = sum(1 for p in policies if not (p.get("comments") or "").strip())
    maxbar = max(acc, den, 1)
    tags = []
    if nat_n:
        tags.append(f'<span class="tag">NAT ON {nat_n}</span>')
    if nocomm:
        tags.append(f'<span class="tag warn">{nocomm} NO COMMENT</span>')
    pol = (f'<div class="big">{n} <small>{act} active · {dis} disabled</small></div>'
           f'<div style="margin-top:14px">'
           f'<div class="bar-row"><span>ACCEPT</span><span class="sev-bar"><i style="width:{round(100 * acc / maxbar)}%;background:var(--green)"></i></span><b style="color:var(--green)">{acc}</b></div>'
           f'<div class="bar-row"><span>DENY</span><span class="sev-bar"><i style="width:{round(100 * den / maxbar)}%;background:var(--red)"></i></span><b style="color:var(--red)">{den}</b></div></div>'
           + (f'<div style="margin-top:12px">{"".join(tags)}</div>' if tags else "")
           + '<div class="note">Full ruleset in the detail view below — click a policy to expand it.</div>')
    pol_panel = _panel("FIREWALL POLICIES", pol)

    vips = data.get("vips", [])
    vips_only = [v for v in vips if v.get("kind") == "vip"]
    pools = [v for v in vips if v.get("kind") == "ippool"]
    nat_inner = [f'<div class="big">{len(vips)} <small>VIPs · port-forwarding & 1:1 NAT</small></div>']
    if vips_only:
        vl = ""
        for v in vips_only[:6]:
            ext = v["ext_ip"] + (f":{v['ext_port']}" if v.get("ext_port") else "")
            mapped = v["mapped_ip"] + (f":{v['mapped_port']}" if v.get("mapped_port") else "")
            vl += f'{html_escape(v["name"])} <span class="m">{html_escape(ext)} → {html_escape(mapped)}</span><br>'
        if len(vips_only) > 6:
            vl += f'<span class="m">+ {len(vips_only) - 6} further VIP entries</span>'
        nat_inner.append(f'<div class="mono-list" style="margin-top:14px;font-size:10.5px;line-height:2.2">{vl}</div>')
    if pools:
        nat_inner.append(f'<div class="note">{len(pools)} SNAT IP pool(s) defined.</div>')
    if not vips:
        nat_inner.append('<div class="note">No VIP / NAT entries defined.</div>')
    nat_panel = _panel("NAT / VIPS", "".join(nat_inner))

    shapers_html = render_shapers(data.get("shapers", {}))
    shaper_detail = (_mag_sub("shapers", "TRAFFIC SHAPING", shapers_html)
                     if shapers_html and "empty-state" not in shapers_html else "")

    detail = ""
    if policies:
        detail += _mag_sub("policies", f"ALL {n} POLICIES", render_policies(policies))
    if vips:
        detail += _mag_sub("nat", "VIP / NAT DETAIL", render_nat_vips(vips))
    detail += shaper_detail
    return f'<div class="two-col">{pol_panel}{nat_panel}</div>' + detail

def render_mag_vpn(data: dict, meta: dict) -> str:
    s2s = data["vpn_s2s"]
    ra = data["vpn_ra"]
    ssl = data.get("ssl_vpn", {})
    # summary grid of tunnel cards removed — tunnels live in the detail view

    strip_bits = []
    strip_bits.append(f'IPsec remote access: {len(ra)} pool tunnel(s)' if ra
                      else 'IPsec remote access: none configured')
    if not _fw76_plus(data):
        if ssl.get("status") == "enable":
            strip_bits.append(f'SSL-VPN: enabled (port {html_escape(str(ssl.get("port", "")))})')
        else:
            strip_bits.append(f'SSL-VPN: disabled (port {html_escape(str(ssl.get("port", "")))})')
        strip_bits.append('— feature removed from FortiOS 7.6 onwards')
    strip = f'<div class="strip">{(" · ".join(strip_bits))}</div>'

    detail = ""
    if s2s:
        detail += _mag_sub("vpn-all", f"ALL {len(s2s)} S2S TUNNELS — PHASE 2 & KEYS", render_vpn(s2s))
    if ra:
        detail += _mag_sub("vpn_ra", "IPSEC REMOTE ACCESS", render_vpn_ra(ra))
    if not _fw76_plus(data) and ssl:
        detail += _mag_sub("sslvpn", "SSL-VPN REMOTE ACCESS", render_ssl_vpn(ssl))
    return strip + detail

def render_mag_objects(data: dict, meta: dict) -> str:
    addrs = data["addresses"]
    groups = data["groups"]
    svcs = data["services"]
    svcs_grp = data["service_groups"]
    by_type: dict[str, int] = {}
    for a in addrs:
        by_type[a.get("type", "other")] = by_type.get(a.get("type", "other"), 0) + 1
    tmax = max(by_type.values()) if by_type else 1
    tcolor = {"ipmask": "var(--blue)", "fqdn": "#C4B5FD", "iprange": "var(--green)",
              "geolocation": "var(--green)"}
    bars = ""
    for t, c in sorted(by_type.items(), key=lambda kv: -kv[1]):
        bars += _bar(t, c, tmax, tcolor.get(t, "var(--blue)"))
    add_panel = (f'<div class="big">{len(addrs)} <small>in {len(groups)} address groups</small></div>'
                 f'<div style="margin-top:14px">{bars}</div>')
    add_panel = _panel("ADDRESS OBJECTS", add_panel)

    sv_inner = [f'<div class="big">{len(svcs)} <small>custom service definitions</small></div>']
    if svcs_grp:
        sv_inner.append(f'<div class="p-title" style="margin-top:16px">SERVICE GROUPS — {len(svcs_grp)}</div>')
        sv_inner.append(''.join(f'<span class="tag" style="color:var(--text)">{html_escape(g["name"])}</span>'
                                for g in svcs_grp))
    sv_panel = _panel("SERVICES", "".join(sv_inner))

    detail = ""
    if addrs:
        detail += _mag_sub("addresses", f"ALL {len(addrs)} ADDRESS OBJECTS", render_addresses(addrs))
    if groups:
        detail += _mag_sub("groups", "ADDRESS GROUPS", render_groups(groups))
    if svcs:
        detail += _mag_sub("services", f"ALL {len(svcs)} CUSTOM SERVICES", render_services(svcs))
    if svcs_grp:
        detail += _mag_sub("service_groups", "SERVICE GROUPS", render_service_groups(svcs_grp))
    return f'<div class="two-col">{add_panel}{sv_panel}</div>' + detail

def render_mag_admins(data: dict, meta: dict) -> str:
    admins = data["admins"]
    certs = data.get("certificates", [])
    super_n = sum(1 for a in admins if a.get("profile") == "super_admin")
    trust_n = sum(1 for a in admins if a.get("trusted_hosts"))
    mfa_n = sum(1 for a in admins if a.get("two_factor") not in ("disable", ""))
    head_tags = ""
    if admins:
        head_tags = (f'<span class="tag danger">{trust_n}/{len(admins)} TRUSTED HOSTS</span> '
                     f'<span class="tag danger">{mfa_n}/{len(admins)} MFA</span>')
    adm_names = " · ".join(html_escape(a["username"]) for a in admins[:10]) or "none"
    more = f' +{len(admins) - 10}' if len(admins) > 10 else ""
    adm_inner = (f'<div class="adm-head">{len(admins)} administrator{"s" if len(admins) != 1 else ""}'
                 f' — {super_n} super_admin {head_tags}</div>'
                 f'<div class="mono-list" style="color:var(--muted)">{adm_names}{more}</div>')
    adm_panel = f'<div class="panel adm">{adm_inner}</div>'

    cert_names = " · ".join(html_escape((c.get("subject") or c["name"])[:40]) for c in certs[:10]) or "none"
    more_c = f' +{len(certs) - 10}' if len(certs) > 10 else ""
    cert_inner = (f'<div style="font-size:12px;font-weight:700;margin-bottom:10px">{len(certs)} certificates</div>'
                  f'<div class="mono-list" style="color:var(--muted)">{cert_names}{more_c}</div>')
    cert_panel = f'<div class="panel">{cert_inner}</div>'

    detail = ""
    if admins:
        detail += _mag_sub("admins-all", "ADMINISTRATOR DETAIL", render_admins(admins))
    if certs:
        detail += _mag_sub("certs", "CERTIFICATE DETAIL", render_certificates(certs))
    return (f'<div style="display:grid;grid-template-columns:1fr 316px;gap:16px">'
            f'{adm_panel}{cert_panel}</div>' + detail)

def build_report(data: dict, meta: dict, settings: dict | None = None) -> str:
    """Assemble the final report HTML — magazine design (new_report.html).

    ``settings`` (from settings.py) filters which sections are rendered:
    unselected sections are removed from their panel entirely; the overview
    stats are always shown; findings follow ``cis_enabled``.
    ``None`` → everything on.
    """
    cfg = settings or {}
    section_cfg = cfg.get("sections") or {}
    cis_enabled = cfg.get("cis_enabled", True)

    hostname = data["global"].get("hostname", "Unknown")
    gen_ts = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    prepared_by = meta.get("prepared_by", "")
    client = meta.get("client", "")

    def on(sid: str) -> bool:
        return section_cfg.get(sid, True)

    # ── header chips ──
    vi = data.get("version_info", {})
    fw = vi.get("firmware", "")
    if vi.get("build"):
        fw += f" build {vi['build']}"
    dev_bits = " · ".join(x for x in (vi.get("model") or "", fw) if x)
    chips = [f'<span class="chip">GENERATED {gen_ts}</span>']
    ha = data.get("ha", {})
    ha_labels = {"a-p": "HA · ACTIVE-PASSIVE", "a-a": "HA · ACTIVE-ACTIVE"}
    if ha.get("mode") in ("a-p", "a-a"):
        chips.append(f'<span class="chip green">{ha_labels[ha["mode"]]}</span>')
    if vi.get("serial"):
        chips.append(f'<span class="chip">SN {html_escape(vi["serial"])}</span>')
    if client:
        chips.append(f'<span class="chip accent">CLIENT · {html_escape(client)}</span>')
    if prepared_by:
        chips.append(f'<span class="chip">PREPARED BY · {html_escape(prepared_by)}</span>')

    # ── numbered panels ──
    toc_plan = []  # (num, sid, short_title) for the TOC, filled as panels are built
    panels = []

    def add_panel(num, sid, title, inner):
        panels.append(_mag_section(num, sid, title, inner))
        toc_plan.append((num, sid, _TOC_SHORT.get(sid, title.split("—")[0].strip().upper()[:18])))

    add_panel(1, "overview", "OVERVIEW", render_mag_atglance(data, meta))

    if cis_enabled:
        add_panel(2, "findings", f"SECURITY FINDINGS — {len(data['findings'])}",
                  render_mag_findings(data))

    if any(on(k) for k in ("admins", "ha", "snmp")):
        add_panel(3, "system", "SYSTEM · HA · SNMP", render_mag_system(data, meta))

    if any(on(k) for k in ("interfaces", "vlans", "dhcp", "zones")):
        add_panel(4, "network", "NETWORK · VLANS · DHCP · ZONES", render_mag_network(data, meta))

    if any(on(k) for k in ("routes", "policy_routes", "layer3")):
        add_panel(5, "routing", "ROUTING · SD-WAN", render_mag_routing(data, meta))

    if any(on(k) for k in ("policies", "nat", "shapers")):
        add_panel(6, "polnat", "FIREWALL POLICIES · NAT", render_mag_policies(data, meta))

    if any(on(k) for k in ("vpn", "vpn_ra", "sslvpn")):
        vpn_title = f"VPN — {len(data['vpn_s2s'])} S2S IPSEC TUNNELS"
        add_panel(7, "vpn", vpn_title, render_mag_vpn(data, meta))

    if any(on(k) for k in ("addresses", "groups", "services", "service_groups")):
        add_panel(8, "objects", "OBJECTS · SERVICES", render_mag_objects(data, meta))

    if any(on(k) for k in ("admins", "certs")):
        add_panel(9, "admins", "ADMINISTRATORS · CERTIFICATES", render_mag_admins(data, meta))

    # ── sidebar navigation ──
    counts = {"findings": len(data.get("findings") or []),
              "polnat": len(data.get("policies") or []),
              "vpn": len(data.get("vpn_s2s") or [])}
    toc = ""
    for num, sid, t in toc_plan:
        icon = _icon(_NAV_ICON_KEYS.get(sid, "overview"))
        badge = ""
        if sid in counts and counts[sid]:
            badge = f'<span class="badge{" red" if sid == "findings" else ""}">{counts[sid]}</span>'
        toc += (f'<a class="item" href="#{sid}">{icon}<span class="num">{num:02d}</span>'
                f'<span class="item-txt">{html_escape(t)}</span>{badge}</a>')
    ha_line = ""
    if ha.get("mode") in ha_labels:
        ha_line = f'<div class="ha">{ha_labels[ha["mode"]]}</div>'
    build_line = ""
    if vi.get("firmware"):
        build_line = (f'<div class="build">FORTIOS {html_escape(vi["firmware"])}'
                      + (f" · BUILD {html_escape(str(vi['build']))}" if vi.get("build") else "")
                      + "</div>")
    sidebar = (f'<aside class="sidebar">'
               f'<div class="brand">{_BRAND_ICON}<b>FORTIDOC</b></div>'
               f'<hr>'
               f'<div class="sb-search">{_SEARCH_ICON}'
               f'<input id="searchInput" type="text" placeholder="Search sections…" oninput="searchReport()">'
               f'<div class="matches" id="searchCount">0 matches</div></div>'
               f'<div class="group">REPORT SECTIONS</div>'
               f'<nav class="toc">{toc}</nav>'
               f'<div class="device"><hr><div class="host">{html_escape(hostname).upper()}</div>'
               f'{ha_line}{build_line}</div>'
               f'</aside>')

    title_bits = " · ".join(x for x in (fw, vi.get("model") or "") if x)
    footer = (f'<footer>FORTIDOC · {html_escape(hostname).upper()}'
              + (f' · {html_escape(title_bits).upper()}' if title_bits else "")
              + f' · GENERATED {gen_ts}</footer>')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>FireDoc — {html_escape(hostname)}</title>
{_favicon_link()}
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
{_REPORT_CSS}
</style>
</head>
<body>
<div class="page">

{sidebar}
<div class="content">
<header class="header">
  <div class="eyebrow">FIREDOC — CONFIGURATION AUDIT REPORT</div>
  <h1>{html_escape(hostname)}</h1>
  <div class="subtitle">{html_escape(dev_bits or "FortiGate")}{(" · " + html_escape(client)) if client else ""}</div>
  <div class="chips">{"".join(chips)}</div>
</header>

{chr(10).join(panels)}

{footer}
</div>
</div>
<div class="footerbar"></div>

<div id="usage-close-btn">
  <span class="usage-name"></span> <span class="usage-close-x">✕</span>
</div>

<script>
{_REPORT_JS}
</script>
</body>
</html>"""
    # Clean surrogate characters (can appear from CESU-8 encoded configs)
    html = html.encode("utf-8", errors="replace").decode("utf-8")
    return html


# ── Diff report (FortiCompare) — magazine design, same system as build_report ──
_DIFF_SECTION_ICONS = {
    "interfaces": "interfaces", "addresses": "addresses", "services": "services",
    "policies": "policies", "routes": "routes", "vpn": "vpn", "nat": "nat",
    "dns": "snmp", "ntp": "snmp", "ha": "ha",
}

def build_diff(data: dict, gen_ts: str) -> str:
    """Assemble the diff report HTML — magazine design (same system as
    build_report): report.css base + diff_report.css layer, report.js for
    search/scrollspy/disclosure. ``data`` is the diff_configs() result."""
    import base64
    favicon = ""
    try:
        favicon = base64.b64encode((_STATIC_DIR / "favicon.svg").read_text("utf-8").encode("utf-8")).decode("ascii")
    except Exception:
        pass
    for s in data.get("sections", []):
        s["icon"] = _icon(_DIFF_SECTION_ICONS.get(s.get("id", ""), "overview"))
    html = _jinja.get_template("diff_report.html").render(
        hostname_a=data["hostname_a"], hostname_b=data["hostname_b"],
        version_a=data["version_a"], version_b=data["version_b"],
        sections=data["sections"], summary=data["summary"], gen_ts=gen_ts,
        favicon_b64=favicon, base_css=_REPORT_CSS, diff_css=_DIFF_CSS,
        base_js=_REPORT_JS, brand_icon=_BRAND_ICON, search_icon=_SEARCH_ICON,
        overview_icon=_icon("overview"), index_icon=_icon("routes"),
    )
    return html.encode("utf-8", errors="replace").decode("utf-8")
