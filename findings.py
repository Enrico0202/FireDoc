"""
findings.py — CIS benchmark compliance analysis for FortiOS configs.
"""

from analysis import detect_unused_objects
from parser import find_config, node_snippet

# ══════════════════════════════════════════════════════════════════════════════
# SECURITY FINDINGS
# ══════════════════════════════════════════════════════════════════════════════

# ── CIS Benchmark references ──────────────────────────────────────────────────
# FortiOS 7.x CIS Benchmark categories used:
#   1.x  Account & Access Control    3.x  Network Configuration
#   2.x  Logging & Monitoring        4.x  System & Device Hardening
#   5.x  Firewall Policies
# ──────────────────────────────────────────────────────────────────────────────

CIS_REF = {
 "1.1.1": "Ensure admin accounts use strong authentication (MFA)",
 "1.1.3": "Ensure trusted hosts are configured for admin accounts",
 "1.1.4": "Ensure admin idle timeout is set appropriately",
 "2.1.1": "Ensure logging is enabled on all firewall policies",
 "2.1.2": "Ensure syslog is configured for external log forwarding",
 "3.1.1": "Ensure default routes are properly configured (only one default)",
 "5.1.1": "Ensure no any-to-any allow policies exist",
 "5.1.2": "Ensure unused policies are disabled",
 "4.1.1": "Ensure strong cryptographic ciphers are enabled",
}


def _add_finding(findings, severity, category, cis_ref, title, detail, remediation, target_id=None, finding_id=None, snippet=""):
 """Append a standardised finding dict."""
 f = {"severity": severity, "category": category, "cis_ref": cis_ref,
   "title": title, "detail": detail, "remediation": remediation}
 if finding_id:
  f["finding_id"] = finding_id
 if target_id:
  f["target_id"] = target_id
 if snippet:
  f["snippet"] = snippet
 findings.append(f)


def _snip(node, max_lines: int = 25) -> str:
 """Verbatim source text of a parsed node ('' when position unknown)."""
 try:
  return node_snippet(node, max_lines)
 except Exception:
  return ""


def _policy_block_node(root, seq):
 """Parsed object node of firewall policy #seq (by table name)."""
 try:
  block = find_config(root, "firewall policy")
  for name, obj in block.get("table", {}).items():
   try:
    if int(name) == int(seq):
     return obj
   except (TypeError, ValueError):
    continue
 except Exception:
  pass
 return None


def _obj_block_node(root, path, name):
 """Parsed object node of table entry *name* in config *path*."""
 try:
  block = find_config(root, path)
  return block.get("table", {}).get(str(name))
 except Exception:
  return None


def _key_snip(node, keys: list[str], pad: int = 3, max_lines: int = 12) -> str:
 """The 'set <key>' line(s) of a flat node, with a little context around.

  Falls back to the node's full block when the key is not present (e.g.
  the setting is missing entirely).
 """
 try:
  src = node.get("_src") or []
  s = node.get("_line", -1)
  e = node.get("_end", s)
  if s < 0 or e < s or not src:
   return _snip(node)
  block = src[s: e + 1]
  for key in keys:
   hit = next((i for i, l in enumerate(block) if l.strip().startswith(f"set {key}")), -1)
   if hit != -1:
    # include all consecutive lines for the same key (multi-value sets)
    j = hit
    while j + 1 < len(block) and block[j + 1].strip().startswith(f"set {key}"):
     j += 1
    lo, hi = max(0, hit - pad), min(len(block), j + 1 + pad)
    out = block[lo: hi]
    return "\n".join(out[:max_lines] + (["..."] if len(out) > max_lines else []))
  return _snip(node, max_lines)
 except Exception:
  return _snip(node)


def _raw_block_snip(root, path: str, keys: list[str], pad: int = 3, max_lines: int = 14) -> str:
 """Snippet from raw source for a top-level config block, by its own lines.

  Used for blocks whose settings sit above nested 'config' children where
  the parsed node doesn't carry the property (e.g. vpn ssl settings).
  Returns '' when the block is absent.
 """
 try:
  src = (root[0].get("_src") if root and isinstance(root[0], dict) else None) or []
  if not src:
   return ""
  header = "config " + path
  s = next((i for i, l in enumerate(src) if l.strip() == header), -1)
  if s == -1:
   return ""
  depth, e = 0, s
  for i in range(s, len(src)):
   l = src[i].strip()
   if l.startswith("config "):
    depth += 1
   elif l == "end":
    depth -= 1
    if depth == 0:
     e = i
     break
  block = src[s: e + 1]
  for key in keys:
   hit = next((i for i, l in enumerate(block) if l.strip().startswith(f"set {key}")), -1)
   if hit != -1:
    lo = max(0, hit - pad)
    out = block[lo: hit + 1 + pad]
    return "\n".join(out[:max_lines])
  return "\n".join(block[:max_lines])
 except Exception:
  return ""


def _snips(parts: list[str], limit: int = 6) -> str:
 """Join several snippets into one capped, labelled snippet."""
 parts = [p for p in parts if p]
 if not parts:
  return ""
 shown = parts[:limit]
 out = "\n\n".join(shown)
 if len(parts) > limit:
  out += f"\n\n… {len(parts) - limit} more"
 return out


def compute_findings(data: dict, root: list | None = None) -> list[dict]:
 """Generate security findings from extracted data.

 ``root`` is the parsed config tree (optional). When present, each finding
 carries a ``snippet`` — the verbatim config lines the check points at.
 """
 F: list[dict] = []; _f = lambda *a, **kw: _add_finding(F, *a, **kw)
 _pol = lambda seq: _policy_block_node(root, seq) if root else None

 # ── CIS 5.1.1: Any-to-any accept policies
 for p in data["policies"]:
  if p["status"] == "enabled" and p["action"] == "accept" and "all" in p["srcaddr"] and "all" in p["dstaddr"]:
   _f("high", "5.1.1 Firewall — Any-to-any", "CIS 5.1.1",
    f"Any-to-any accept policy: #{p['seq']} {p['name']}",
    "Policy accepts all traffic from any source to any destination without restriction. This violates the least-privilege principle.",
    "Restrict source/destination to specific address objects or groups instead of 'all'.", f"policy-{p['seq']}", finding_id="a2a_policy",
    snippet=_snip(_pol(p["seq"]), 18))

 # ── CIS 5.1.2: Disabled policies
 disabled = [p for p in data["policies"] if p["status"] == "disabled"]
 if disabled:
  names = ", ".join(f"#{p['seq']}" for p in disabled)
  _f("info", "5.1.2 Firewall — Cleanup", "CIS 5.1.2",
   f"{len(disabled)} disabled policy(s) detected: {names}",
   "Disabled policies clutter the config and may indicate incomplete cleanup after rule changes.",
   "Review and remove disabled policies that are no longer needed.", finding_id="disabled_policies_cis",
   snippet=_snips([_snip(_pol(p["seq"]), 10) for p in disabled], 3))

 # ── CIS 2.1.1: Logging on policies
 for p in data["policies"]:
  if p["status"] == "enabled" and p["logtraffic"] == "disable":
   _f("medium", "2.1.1 Logging — Policy logging", "CIS 2.1.1",
    f"Logging disabled on policy #{p['seq']} {p['name']}",
    "Traffic matched by this policy is not logged, reducing visibility for incident response and troubleshooting.",
    "Enable logging on this policy. Set 'logtraffic' to 'all' or 'utm'.", f"policy-{p['seq']}", finding_id="policy_no_logging",
    snippet=_key_snip(_pol(p["seq"]), ["logtraffic"]))

 # ── CIS 2.1.2: Syslog forwarding
 if data["syslog"].get("status", "disable") != "enable":
  _f("medium", "2.1.2 Logging — Syslog", "CIS 2.1.2",
   "Syslog not configured or disabled",
   "Logs are not being forwarded to an external SIEM or syslog server.",
   "Configure 'log syslogd setting' with your SIEM/server IP and enable it.", finding_id="syslog_not_configured",
   snippet=_raw_block_snip(root, "log syslogd setting", ["status"]) if root else "")

 # ── CIS 1.1.1: MFA on admin accounts
 for a in data["admins"]:
  if a["two_factor"] in ("disable", ""):
   _f("medium", "1.1.1 Access — MFA", "CIS 1.1.1",
    f"No MFA on account: {a['username']}",
    f"Profile: {a['profile']}. Two-factor authentication is disabled for this admin account.",
    "Enable FortiToken or a compatible TOTP token for this account.", "admins", finding_id="admin_no_mfa",
    snippet=_key_snip(_obj_block_node(root, "system admin", a["username"]), ["two-factor"]) if root else "")

 # ── CIS 1.1.3: Trusted host restrictions
 for a in data["admins"]:
  if not a["trusted_hosts"]:
   _f("high", "1.1.3 Access — Trusted hosts", "CIS 1.1.3",
    f"No trusted-host restriction: {a['username']}",
    "Management access is not restricted by source IP. Admin can log in from any network.",
    "Add 'set trusthost1 <IP/netmask>' for each admin to restrict management access.", "admins", finding_id="admin_no_trusted_host",
    snippet=_key_snip(_obj_block_node(root, "system admin", a["username"]), ["trusthost1", "accprofile"]) if root else "")

 # ── CIS 1.1.4: Admin idle timeout
 timeout = data["global"].get("admintimeout", "")
 if timeout and int(timeout) > 30:
  _f("low", "1.1.4 Access — Idle timeout", "CIS 1.1.4",
   f"Admin idle timeout is {timeout} minutes (recommended: ≤30)",
   "Long admin idle timeouts increase the risk of session hijacking from unattended workstations.",
   "Set 'set admintimeout 30' in system global.", finding_id="admin_idle_timeout",
   snippet=_key_snip(find_config(root, "system global"), ["admintimeout"], pad=1) if root else "")

 # ── CIS 3.1.1: Multiple default routes
 defaults = [r for r in data["routes"] if r.get("is_default")]
 if len(defaults) > 1:
  _f("info", "3.1.1 Routing — Default routes", "CIS 3.1.1",
   f"{len(defaults)} default routes detected (ECMP/failover)",
   "Multiple default routes are configured. Verify this is intentional for ECMP or failover.",
   "Ensure only one active default route unless ECMP or SD-WAN failover is required.", finding_id="multiple_default_routes",
   snippet=_snips([_snip(_obj_block_node(root, "router static", r["seq"]), 6) for r in defaults], 4) if root else "")

 # ── CIS 4.1.1: Strong crypto
 if data["global"].get("strong-crypto", "") != "enable":
  _f("medium", "4.1.1 Hardening — Strong crypto", "CIS 4.1.1",
   "Strong crypto is not enabled",
   "Legacy ciphers and protocols may be accepted for administrative access (HTTPS/SSH).",
   "Enable 'set strong-crypto enable' in system global to disable weak ciphers.", finding_id="strong_crypto_off",
   snippet=_key_snip(find_config(root, "system global"), ["strong-crypto"], pad=1) if root else "")

 # ── SSL-VPN enabled (informational)
 ssl_enabled = data.get("ssl_vpn", {}).get("status") == "enable"
 if ssl_enabled:
  ssl_port = data["ssl_vpn"].get("port", "443")
  snip = ""
  if root:
   snip = _raw_block_snip(root, "vpn ssl settings", ["status", "port"]) or _raw_block_snip(root, "vpn ssl setting", ["status", "port"])
  _f("info", "4.1.2 Hardening — SSL-VPN", "CIS 4.1.2",
   f"SSL-VPN enabled on port {ssl_port}",
   "SSL-VPN is a common attack vector. Ensure it's patched, restrict source IPs, and enable MFA.",
   "Consider restricting SSL-VPN to specific source IPs and enabling FortiToken.", finding_id="ssl_vpn_enabled",
   snippet=snip)

 # ── Policy anomaly: Any/Any/Allow without logging
 for p in data["policies"]:
  if "-ignore" in (p.get("comments", "") or "").lower():
   continue
  if (p["status"] == "enabled" and p["action"] == "accept"
      and "all" in [s.lower() for s in p.get("srcaddr", [])]
      and "all" in [s.lower() for s in p.get("dstaddr", [])]
      and p.get("logtraffic") == "disable"):
   _f("medium", "5.2 Firewall — Any/Any/Allow without logging", "BEST PRACTICE",
    f"Any/Any/Allow policy #{p['seq']} {p['name']} without logging",
    "This policy allows all traffic but has logging disabled. "
    "Without logs, troubleshooting and incident response are severely hindered.",
    "Enable logging (set logtraffic all) on this policy, or restrict source/destination.",
    f"policy-{p['seq']}", finding_id="a2a_no_logging",
    snippet=_key_snip(_pol(p["seq"]), ["logtraffic"]))

 # ── Policy anomaly: Any/Any/Allow without UTM profiles
 for p in data["policies"]:
  if "-ignore" in (p.get("comments", "") or "").lower():
   continue
  if (p["status"] == "enabled" and p["action"] == "accept"
      and "all" in [s.lower() for s in p.get("srcaddr", [])]
      and "all" in [s.lower() for s in p.get("dstaddr", [])]):
   has_utm = any(p.get(prof) for prof in
                  ["av", "ips", "webfilter", "appctrl"])
   if not has_utm:
    _f("medium", "5.3 Firewall — Any/Any/Allow without UTM", "BEST PRACTICE",
     f"Any/Any/Allow policy #{p['seq']} {p['name']} without UTM protection",
     "This policy accepts all traffic without AV, IPS, Web Filter, "
     "or App Control inspection. All traffic passes uninspected.",
     "Apply UTM security profiles (AV, IPS, WebFilter, AppCtrl) to inspect traffic.",
     f"policy-{p['seq']}", finding_id="a2a_no_utm",
     snippet=_key_snip(_pol(p["seq"]), ["av", "ips", "webfilter", "appctrl"]))

 # ── Policy anomaly: Disabled policies
 disabled_count = sum(1 for p in data["policies"]
                       if p.get("status") == "disabled"
                       and "-ignore" not in (p.get("comments", "") or "").lower())
 if disabled_count > 0:
  _f("medium", "5.4 Firewall — Disabled policies", "BEST PRACTICE",
   f"{disabled_count} disabled policy(s) found",
   "Disabled policies increase configuration complexity, lengthen policy evaluation, "
   "and may indicate incomplete cleanup after rule changes.",
   "Review and either remove or document why each disabled policy is retained.", finding_id="disabled_policies_bp",
   snippet=_snips([_snip(_pol(p["seq"]), 10) for p in data["policies"]
                   if p.get("status") == "disabled"
                   and "-ignore" not in (p.get("comments", "") or "").lower()], 3))

 # ── Policy anomaly: Policies without comments
 no_comment = [p for p in data["policies"]
                if p.get("status") == "enabled"
                and not p.get("comments", "")
                and "-ignore" not in (p.get("comments", "") or "").lower()]
 if no_comment:
  names = ", ".join(f"#{p['seq']} {p['name']}" for p in no_comment[:5])
  suffix = f" and {len(no_comment) - 5} more…" if len(no_comment) > 5 else ""
  _f("medium", "5.5 Firewall — Policy without comments", "BEST PRACTICE",
   f"{len(no_comment)} policy(s) without comments: {names}{suffix}",
   "Uncommented policies make audits and troubleshooting difficult. "
   "Other team members cannot determine the policy's purpose or owner.",
   "Add meaningful comments to each policy describing its purpose, "
   "requester, and change ticket reference.", finding_id="policy_no_comments",
   snippet=_snips([_snip(_pol(p["seq"]), 10) for p in no_comment], 3))

 # ── Unused objects
 unused = detect_unused_objects(data)
 for name in unused.get("unused_addresses", []):
  _f("info", "5.1 Housekeeping — Unused objects", "CIS 5.1",
   f"Unused address object: {name}",
   f"Address object '{name}' is not referenced by any policy, group, or VIP.",
   "Remove unused address objects to simplify the configuration.", finding_id="unused_address",
   snippet=_snip(_obj_block_node(root, "firewall address", name)) if root else "")
 for name in unused.get("unused_groups", []):
  _f("info", "5.1 Housekeeping — Unused objects", "CIS 5.1",
   f"Unused address group: {name}",
   f"Address group '{name}' is not referenced by any policy or VIP.",
   "Remove unused address groups to simplify the configuration.", finding_id="unused_address_group",
   snippet=_snip(_obj_block_node(root, "firewall addrgrp", name)) if root else "")

 return F




# ══════════════════════════════════════════════════════════════════════════════
# FINDING CATALOG — every check the engine knows, in report order.
# The admin UI renders this list; admins can disable a check, override its
# severity, and rewrite its remediation per finding id.
# (fid, title, description, cis_ref, default_severity)
# ══════════════════════════════════════════════════════════════════════════════

SEVERITIES = ["high", "medium", "low", "info"]

FINDER_CATALOG = [
    ("a2a_policy", "Any-to-any accept policy",
     "Firewall policy accepts all traffic from any source to any destination.",
     "CIS 5.1.1", "high",
     "Restrict source/destination to specific address objects or groups instead of 'all'."),
    ("disabled_policies_cis", "Disabled firewall policies (CIS)",
     "Policies that are disabled but not removed (CIS housekeeping).",
     "CIS 5.1.2", "info",
     "Review and remove disabled policies that are no longer needed."),
    ("policy_no_logging", "Policy logging disabled",
     "Individual policy with traffic logging turned off.",
     "CIS 2.1.1", "medium",
     "Enable logging on this policy. Set 'logtraffic' to 'all' or 'utm'."),
    ("syslog_not_configured", "Syslog forwarding not configured",
     "Logs not forwarded to an external syslog server / SIEM.",
     "CIS 2.1.2", "medium",
     "Configure 'log syslogd setting' with your SIEM/server IP and enable it."),
    ("admin_no_mfa", "Admin account without MFA",
     "Admin account with two-factor authentication disabled.",
     "CIS 1.1.1", "medium",
     "Enable FortiToken or a compatible TOTP token for this account."),
    ("admin_no_trusted_host", "Admin without trusted-host restriction",
     "Admin can log in from any source IP.",
     "CIS 1.1.3", "high",
     "Add 'set trusthost1 <IP/netmask>' for each admin to restrict management access."),
    ("admin_idle_timeout", "Admin idle timeout too long",
     "Admin session idle timeout exceeds 30 minutes.",
     "CIS 1.1.4", "low",
     "Set 'set admintimeout 30' in system global."),
    ("multiple_default_routes", "Multiple default routes",
     "More than one default route (verify ECMP/failover intent).",
     "CIS 3.1.1", "info",
     "Ensure only one active default route unless ECMP or SD-WAN failover is required."),
    ("strong_crypto_off", "Strong crypto not enabled",
     "Weak ciphers may be accepted for administrative access.",
     "CIS 4.1.1", "medium",
     "Enable 'set strong-crypto enable' in system global to disable weak ciphers."),
    ("ssl_vpn_enabled", "SSL-VPN enabled",
     "SSL-VPN remote access is active — a common attack vector.",
     "CIS 4.1.2", "info",
     "Consider restricting SSL-VPN to specific source IPs and enabling FortiToken."),
    ("a2a_no_logging", "Any/Any/Allow without logging",
     "Any-to-any accept policy with logging disabled.",
     "BEST PRACTICE", "medium",
     "Enable logging (set logtraffic all) on this policy, or restrict source/destination."),
    ("a2a_no_utm", "Any/Any/Allow without UTM",
     "Any-to-any accept policy without AV/IPS/WebFilter/AppCtrl.",
     "BEST PRACTICE", "medium",
     "Apply UTM security profiles (AV, IPS, WebFilter, AppCtrl) to inspect traffic."),
    ("disabled_policies_bp", "Disabled firewall policies (best practice)",
     "Disabled policies clutter the config and slow policy evaluation.",
     "BEST PRACTICE", "medium",
     "Review and either remove or document why each disabled policy is retained."),
    ("policy_no_comments", "Policy without comments",
     "Enabled policy carrying no comment / owner / ticket reference.",
     "BEST PRACTICE", "medium",
     "Add meaningful comments to each policy describing its purpose, requester, and change ticket reference."),
    ("unused_address", "Unused address object",
     "Address object referenced by no policy, group, or VIP.",
     "CIS 5.1", "info",
     "Remove unused address objects to simplify the configuration."),
    ("unused_address_group", "Unused address group",
     "Address group referenced by no policy or VIP.",
     "CIS 5.1", "info",
     "Remove unused address groups to simplify the configuration."),
]

_CATALOG = {fid: {"title": t, "description": d, "ref": r, "severity": s, "remediation": rem}
            for fid, t, d, r, s, rem in FINDER_CATALOG}


def finding_severity(f: dict) -> str:
    """Effective severity of a finding: admin override wins, else built-in."""
    return f.get("override_severity") or f.get("severity", "info")


def _custom_pattern_snip(raw: str, line_idx: int, context: int = 2) -> str:
    """Snippet around a raw line (0-based): the match plus a little context,
    capped — used for custom findings that carry a search pattern."""
    lines = raw.splitlines()
    start = max(0, line_idx - context)
    end = min(len(lines), line_idx + context + 2)
    out = []
    for i in range(start, end):
        out.append(f"{i + 1:5d}  {lines[i]}" if i != line_idx else f"{i + 1:5d}  {lines[i]} ←")
    return "\n".join(out)


def _scan_custom_pattern(raw: str, pattern: str):
    """Search the raw config for a custom finding's pattern.

    Plain substring match (case-insensitive) by default; if the pattern
    looks like a regex (contains [ ( | ^ $ * ? . { } or escapes) it is tried
    as a regex first. Returns (match_count, first_line_idx) — (0, -1) if the
    pattern never matches."""
    import re as _re
    pat = (pattern or "").strip()
    if not pat:
        return 0, -1
    count, first = 0, -1
    looks_regex = any(ch in pat for ch in r"[\(\\^$|*?{") or " " in pat and "\\" in pat
    if looks_regex:
        try:
            rx = _re.compile(pat, _re.IGNORECASE)
        except _re.error:
            rx = None
        if rx is not None:
            for i, line in enumerate(raw.splitlines()):
                if rx.search(line):
                    count += 1
                    if first == -1:
                        first = i
            return count, first
    needle = pat.lower()
    for i, line in enumerate(raw.splitlines()):
        if needle in line.lower():
            count += 1
            if first == -1:
                first = i
    return count, first


def apply_finding_settings(findings: list[dict], settings: dict, raw: str | None = None) -> None:
    """Apply admin overrides to findings IN PLACE.

    - ``finding_overrides[<id>].enabled is False`` → finding dropped
    - ``finding_overrides[<id>].severity``          → ``override_severity``
    - ``finding_overrides[<id>].remediation``       → ``override_remediation``
      (empty string = keep the built-in text)
    - ``custom_findings`` are appended. Each may carry a ``pattern``:
        * pattern set + ``raw`` given → the finding only fires when the
          pattern matches the config; snippet auto-filled from the match.
        * pattern set, no ``raw`` (CLI path) → falls back to manual snippet.
        * pattern empty → always shown (manual annotation, old behaviour).
    """
    cfg = settings or {}
    overrides = cfg.get("finding_overrides") or {}
    keep = []
    for f in findings:
        fid = f.get("finding_id")
        ov = overrides.get(fid) if fid else None
        if isinstance(ov, dict) and ov.get("enabled") is False:
            continue
        if isinstance(ov, dict) and fid:
            sev = ov.get("severity")
            if sev in SEVERITIES:
                f["override_severity"] = sev
            rem = ov.get("remediation")
            if isinstance(rem, str) and rem.strip():
                f["override_remediation"] = rem.strip()
        keep.append(f)
    findings[:] = keep
    for c in cfg.get("custom_findings") or []:
        if not isinstance(c, dict):
            continue
        title = (c.get("title") or "").strip()
        if not title:
            continue
        if not c.get("enabled", True):
            continue
        pattern = (c.get("pattern") or "").strip()
        snippet = (c.get("snippet") or "").strip()
        detail = (c.get("description") or "").strip()
        # Pattern-based detection: the finding only fires when the pattern is
        # actually present in THIS config, and the snippet is the matched line
        # (with context) from the file itself. No pattern → manual annotation
        # (always shown, admin-provided snippet) — the old behaviour.
        if pattern and raw is not None:
            count, first = _scan_custom_pattern(raw, pattern)
            if count == 0:
                continue
            snippet = _custom_pattern_snip(raw, first)
            detail = f"{detail}\n" if detail else ""
            detail += (f"Pattern `{pattern}` matched on line {first + 1}"
                       + (f" ({count}× total)" if count > 1 else ""))
        findings.append({
            "finding_id": f"custom:{c.get('id', 'custom')}",
            "severity": c.get("severity") if c.get("severity") in SEVERITIES else "info",
            "category": "Custom",
            "cis_ref": "CUSTOM",
            "title": title,
            "detail": detail or "Custom finding defined in the admin panel.",
            "remediation": (c.get("remediation") or "").strip() or "—",
            "snippet": snippet,
            "target_id": None,
        })
