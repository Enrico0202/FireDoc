"""
diff.py — FortiGate Config Diff Engine
========================================
Compares two FortiOS config exports and produces a structured diff.

Matching semantics
------------------
Objects are matched by *identity*, never by raw sequence number:

  * firewall policies — named policies by name; unnamed policies (the
    common GUI-export case) by content identity
  * static routes     — by (dst, gateway, device)
  * everything else   — by object name

Matching runs in two stages: (1) primary key, (2) content-signature —
catches *renames* (same object, new name).  Objects that match neither are
reported honestly as removed + added pairs — pairing leftovers positionally
would invent "changes" between unrelated objects on a big rework.
FortiOS renumbers ``edit N`` on every move, so entries whose only changed
field is the seq label are collapsed into a single ``renumbered`` note
instead of flooding the report.
"""

import hashlib
from typing import Any, Callable

from parser import parse_config, prop, find_config
from extractors import (
    extract_version_info, extract_interfaces, extract_routes,
    extract_addresses, extract_services, extract_policies,
    extract_vpn, extract_nat_vips, extract_dns,
    extract_ntp, extract_ha,
)


# ── normalisation & field-level diff ────────────────────────────────────

def _norm(v: Any) -> str:
    """Stable string form of a value for comparison and display.
    Multi-value fields are sorted: FortiOS list order (allowaccess,
    address lists, services) is semantically irrelevant, so a pure
    reorder must never count as a change."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return " ".join(sorted(str(x) for x in v))
    return str(v)


def _norm_deep(v: Any) -> str:
    """Stable string form for (possibly nested) values."""
    if isinstance(v, dict):
        return " ".join(f"{k}={_norm_deep(v[k])}" for k in sorted(v))
    if isinstance(v, (list, tuple)):
        return " ".join(_norm_deep(x) for x in v)
    return _norm(v)


def _changed_fields(before: dict, after: dict, exclude: set | None = None) -> list[dict]:
    """Per-field before/after for the attributes that actually differ.

    Each entry also carries ``is_list`` — True when either side was a
    multi-value attribute — so templates can render changed list items as
    chips instead of one text wall.
    """
    fields = []
    for k in sorted(set(before) | set(after)):
        if exclude and k in exclude:
            continue
        vb_raw, va_raw = before.get(k), after.get(k)
        vb, va = _norm(vb_raw), _norm(va_raw)
        if vb != va:
            fields.append({
                "field": k,
                "before": vb,
                "after": va,
                "is_list": isinstance(vb_raw, (list, tuple))
                           or isinstance(va_raw, (list, tuple)),
            })
    return fields


# ── identity matching ───────────────────────────────────────────────────

def _keyed(items: list[dict], key_fn: Callable[[dict], str]) -> list[tuple[str, dict]]:
    """(match_key, item) pairs in original order; duplicate keys are
    disambiguated by occurrence: ``name``, ``name (2)``, ``name (3)``…"""
    seen: dict[str, int] = {}
    out: list[tuple[str, dict]] = []
    for it in items:
        k = key_fn(it)
        c = seen.get(k, 0)
        seen[k] = c + 1
        out.append(((k if c == 0 else f"{k} ({c + 1})"), it))
    return out


def _content_sig(item: dict, exclude: set) -> str:
    """Content identity of an object (stable, excluding ``exclude``)."""
    h = hashlib.sha256()
    for k in sorted(item):
        if k in exclude:
            continue
        h.update(k.encode())
        h.update(b"=")
        h.update(_norm(item[k]).encode())
    return h.hexdigest()


def _policy_is_unnamed(p: dict) -> bool:
    name = p.get("name") or ""
    return not name or name == "(unnamed)"


def _compute_diff(
    before: list[dict], after: list[dict],
    key_fn: Callable[[dict], str], exclude_keys: set | None = None,
    identity_fields: frozenset = frozenset(),
    unnamed_ok: bool = False,
) -> dict:
    """Compute added / removed / changed between two object lists.

    Matching stages: (1) primary key, (2) content signature (renames).
    ``identity_fields`` are excluded from the content signature (they are
    the match key itself, e.g. ``"name"``).  ``unnamed_ok`` is accepted for
    signature compatibility (unnamed objects match by content signature via
    their key function).

    Returns ``{"added": [...], "removed": [...], "changed": [...]}`` where
    each changed entry carries the matching ``key``, both full objects, and
    ``fields`` — the per-attribute before/after of what actually changed.
    """
    ex = set(exclude_keys or ())
    sig_ex = ex | set(identity_fields) | {"seq"}

    kb = _keyed(before, key_fn)
    ka = _keyed(after, key_fn)

    # stage 1 — primary key match (FIFO within each key)
    a_by_key: dict[str, list[int]] = {}
    for j, (k, _) in enumerate(ka):
        a_by_key.setdefault(k, []).append(j)

    pairs: list[tuple[str, int, int]] = []      # (label, bidx, aidx)
    removed: list[int] = []
    for bidx, (k, _) in enumerate(kb):
        lst = a_by_key.get(k)
        if lst:
            pairs.append((k, bidx, lst.pop(0)))
        else:
            removed.append(bidx)
    added: list[int] = []
    for lst in a_by_key.values():
        added.extend(lst)

    # stage 2 — content-signature match (renames / duplicates)
    if removed and added:
        sig_map: dict[str, list[int]] = {}
        for j in added:
            sig_map.setdefault(_content_sig(after[j], sig_ex), []).append(j)
        still_removed = []
        for bidx in removed:
            lst = sig_map.get(_content_sig(before[bidx], sig_ex))
            if lst:
                j = lst.pop(0)
                added.remove(j)
                pairs.append((key_fn(before[bidx]), bidx, j))
            else:
                still_removed.append(bidx)
        removed = still_removed

    # No positional stage-3 fallback: pairing leftovers by position invented
    # "changes" between unrelated objects (e.g. policy #1 in A vs policy #6
    # in B on a big policy rework).  Unmatched objects are reported honestly
    # as removed+added pairs; an edited *identical* object is still caught
    # by the content signature in stage 2.

    changed = []
    for label, bidx, j in pairs:
        b, a = before[bidx], after[j]
        fields = _changed_fields(b, a, ex)
        if fields:
            changed.append({
                "key": label,
                "before": b,
                "after": a,
                "fields": fields,
            })

    return {
        "added": [after[j] for j in added],
        "removed": [before[i] for i in removed],
        "changed": changed,
    }


def _diff_count(d: dict | None) -> int:
    if not d:
        return 0
    return len(d["added"]) + len(d["removed"]) + len(d["changed"])


# ── identity key functions ──────────────────────────────────────────────

def _policy_key(p: dict) -> str:
    """Named policies match by name (survives renumbering); unnamed ones
    are identified by content (a renumber does not change their content)."""
    name = p.get("name") or ""
    if name and name != "(unnamed)":
        return name
    return _content_sig(p, {"seq"})


def _route_key(r: dict) -> str:
    """Identity of a static route: (dst, gateway, device).  Rendered with the
    non-empty parts only, so the label reads ``203.0.113.81/8 via 1.1.1.1 on wan1``
    instead of ``203.0.113.81/8|1.1.1.1|wan1`` (and ``203.0.113.81/8`` when gw/dev are
    absent).  Uniqueness is preserved — identical tuples still collide and are
    disambiguated by occurrence in ``_keyed``."""
    parts = [r.get("dst") or "?"]
    if r.get("gateway"):
        parts.append("via " + _norm(r["gateway"]))
    if r.get("device"):
        parts.append("on " + _norm(r["device"]))
    return " ".join(parts)


def _name_key(item: dict) -> str:
    return item.get("name") or item.get("username") or item.get("ip") or "?"


# ── policy change presentation (human-readable grouping) ────────────────

POLICY_FIELD_LABELS = {
    "seq": "Sequence",
    "srcintf": "Incoming interface",
    "dstintf": "Outgoing interface",
    "srcaddr": "Source address",
    "dstaddr": "Destination address",
    "services": "Services",
    "schedule": "Schedule",
    "action": "Action",
    "status": "Status",
    "nat": "NAT",
    "natpool": "NAT pool",
    "logtraffic": "Traffic logging",
    "comments": "Comment",
    "av": "Antivirus profile",
    "ips": "IPS sensor",
    "webfilter": "Web filter profile",
    "appctrl": "Application control",
    "dlp": "DLP sensor",
    "dnsfilter": "DNS filter profile",
    "emailfilter": "Email filter profile",
    "cifs": "CIFS filter profile",
    "protocolopt": "Protocol options profile",
    "sslssh": "SSL/SSH profile",
    "videofilter": "Video filter profile",
    "voip": "VoIP filter profile",
    "waf": "WAF profile",
    "profile_group": "Profile group",
    "isdb": "Internet service DB",
}

POLICY_GROUPS = (
    ("Traffic", ("srcintf", "dstintf", "srcaddr", "dstaddr", "services", "schedule")),
    ("Access", ("action", "status", "nat", "natpool", "logtraffic", "comments")),
    ("Security profiles", ("av", "ips", "webfilter", "appctrl", "dlp", "dnsfilter",
                          "emailfilter", "cifs", "protocolopt", "sslssh",
                          "videofilter", "voip", "waf", "profile_group", "isdb")),
)


def _policy_change_view(ch: dict) -> dict:
    """Presentation view of one changed policy for the report: the raw
    per-field list is regrouped into human sections (Traffic / Access /
    Security profiles) with labelled rows, and a name change is surfaced
    as a separate 'renamed' banner.  Multi-value fields (interfaces,
    address lists, services, ISDB names) are reduced to the items that
    were removed / added plus an 'unchanged' count, so the template can
    render a few chips instead of one text wall."""
    b_raw, a_raw = ch["before"], ch["after"]
    renamed = None
    for f in ch["fields"]:
        if f["field"] == "name":
            renamed = {"before": f["before"] or "(unnamed)",
                       "after": f["after"] or "(unnamed)"}
            break
    groups = []
    for title, keys in POLICY_GROUPS:
        rows = []
        for k in keys:
            f = next((x for x in ch["fields"] if x["field"] == k), None)
            if f is None:
                continue
            vb, va = b_raw.get(k), a_raw.get(k)
            row = {"field": k, "label": POLICY_FIELD_LABELS.get(k, k),
                   "before": f["before"], "after": f["after"]}
            if isinstance(vb, (list, tuple)) or isinstance(va, (list, tuple)):
                bl = [str(x) for x in (vb or [])]
                al = [str(x) for x in (va or [])]
                aset, bset = set(al), set(bl)
                row["is_list"] = True
                row["b_removed"] = [x for x in bl if x not in aset]
                row["a_added"] = [x for x in al if x not in bset]
                row["n_keep"] = len(aset & bset)
            else:
                row["is_list"] = False
            rows.append(row)
        if rows:
            groups.append({"title": title, "rows": rows})
    grouped = {k for _, keys in POLICY_GROUPS for k in keys} | {"name"}
    rest = [x for x in ch["fields"] if x["field"] not in grouped]
    if rest:
        groups.append({
            "title": "Other",
            "rows": [{"field": x["field"],
                      "label": POLICY_FIELD_LABELS.get(x["field"], x["field"]),
                      "before": x["before"], "after": x["after"],
                      "is_list": False} for x in rest],
        })
    summary = " · ".join(r["label"] for g in groups for r in g["rows"])
    n_changes = sum(len(g["rows"]) for g in groups)
    return {"renamed": renamed, "groups": groups, "summary": summary,
            "n_changes": n_changes}


def _phase2_key(p2: dict) -> str:
    return f"{p2.get('tunnel', '')}/{p2.get('name', '')}"


def _flatten_phase2(vpn_rows: list[dict]) -> list[dict]:
    """Flatten per-tunnel phase2 entries into diff-able rows."""
    rows = []
    for t in vpn_rows:
        for p2 in t.get("phase2", []):
            rows.append({
                "tunnel": t.get("name", ""),
                "name": p2.get("name", ""),
                "proposal": p2.get("proposal", ""),
                "dhgrp": p2.get("dhgrp", ""),
                "src_subnet": p2.get("src_subnet", ""),
                "dst_subnet": p2.get("dst_subnet", ""),
            })
    return rows


# ── section builders ────────────────────────────────────────────────────

def _git_status(diff: dict, title: str) -> list[dict]:
    """Render a section's diff as `git diff --name-status` style rows:
    ``(A|M|D)  <object path>`` — one line per added / modified / removed object.
    The path is ``<section>/<object name>`` so two same-named objects in
    different sections stay distinguishable (like git's file paths)."""
    rows: list[dict] = []
    for it in diff["added"]:
        rows.append({"code": "A", "status": "added",
                     "path": f"{title.lower().replace(' ', '-')}/{_display_name(it)}"})
    for ch in diff["changed"]:
        a = ch["after"]
        rows.append({"code": "M", "status": "changed",
                     "path": f"{title.lower().replace(' ', '-')}/{_display_name(a)}"})
    for it in diff["removed"]:
        rows.append({"code": "D", "status": "removed",
                     "path": f"{title.lower().replace(' ', '-')}/{_display_name(it)}"})
    return rows


def _display_name(item: dict) -> str:
    """Human label for an object in a status line (name, or key fallbacks)."""
    for k in ("name", "username", "ip", "dst"):
        if item.get(k):
            return str(item[k])
    return str(item.get("seq", "?"))


def _list_section(id_, title, rows_a, rows_b, key_fn, exclude_keys: set | None = None,
                  label_field: str | None = None, identity_fields: frozenset = frozenset(),
                  unnamed_ok: bool = False) -> dict:
    """Build a list-diff section.

    ``label_field`` (e.g. ``"seq"``) marks a positional label: entries whose
    only changed field is that label are pure relabels/moves (FortiOS
    renumbers ``edit N`` on every move) and are collapsed into the
    ``renumbered`` note instead of flooding the report.

    ``git_status`` carries the `git diff --name-status` style change list for
    the report's overview (A = added, M = modified, D = deleted).
    """
    diff = _compute_diff(rows_a, rows_b, key_fn, exclude_keys,
                         identity_fields, unnamed_ok)
    renumbered: list[dict] = []
    if label_field:
        kept = []
        for ch in diff["changed"]:
            if all(f["field"] == label_field for f in ch["fields"]):
                renumbered.append(ch)
            else:
                kept.append(ch)
        diff["changed"] = kept
    return {
        "id": id_, "title": title,
        "diff": diff,
        "renumbered": renumbered,
        "git_status": _git_status(diff, title),
        "count": _diff_count(diff) + (1 if renumbered else 0),
        "total": max(len(rows_a), len(rows_b)),
    }


def _dict_section(id_, title, d_a: dict, d_b: dict) -> dict:
    changed = _norm_deep(d_a) != _norm_deep(d_b)
    return {
        "id": id_, "title": title,
        "diff": None,
        "changed": changed,
        "before": d_a, "after": d_b,
        "git_status": [{"code": "M", "status": "changed",
                        "path": title.lower().replace(" ", "-")}] if changed else [],
        "count": 1 if changed else 0,
        "total": 1,
    }


# ── main entry ──────────────────────────────────────────────────────────

def diff_configs(raw_a: str, raw_b: str, meta: dict) -> dict:
    """Compare two FortiOS configs and return structured diff data.

    meta: {"label_a": "Before", "label_b": "After", ...}
    """
    root_a = parse_config(raw_a)
    root_b = parse_config(raw_b)

    data: dict[str, Any] = {
        "version_a": extract_version_info(raw_a),
        "version_b": extract_version_info(raw_b),
        "hostname_a": None,
        "hostname_b": None,
        "meta": meta,
    }

    # System info
    ga = find_config(root_a, "system global")
    gb = find_config(root_b, "system global")
    data["hostname_a"] = prop(ga, "hostname", "Unknown")
    data["hostname_b"] = prop(gb, "hostname", "Unknown")

    sections = []

    # Interfaces
    ifaces_a, ifaces_b = extract_interfaces(root_a), extract_interfaces(root_b)
    sections.append(_list_section(
        "interfaces", "Interfaces", ifaces_a, ifaces_b, _name_key,
        exclude_keys={"usage_count", "dhcp_server"}, identity_fields=frozenset({"name"})))

    # Addresses
    addrs_a, addrs_b = extract_addresses(root_a), extract_addresses(root_b)
    sections.append(_list_section(
        "addresses", "Address Objects", addrs_a, addrs_b, _name_key,
        exclude_keys={"usage_count"}, identity_fields=frozenset({"name"})))

    # Services
    svc_a, svc_b = extract_services(root_a), extract_services(root_b)
    sections.append(_list_section(
        "services", "Custom Services", svc_a, svc_b, _name_key,
        exclude_keys={"usage_count"}, identity_fields=frozenset({"name"})))

    # Policies — named by name, unnamed by content; seq change = move
    pol_a, pol_b = extract_policies(root_a), extract_policies(root_b)
    pol_sec = _list_section(
        "policies", "Firewall Policies", pol_a, pol_b, _policy_key,
        exclude_keys={"dnat", "usage_count"}, label_field="seq",
        identity_fields=frozenset({"name"}), unnamed_ok=True)
    # human-readable presentation of each changed policy (grouped, labelled)
    for ch in pol_sec["diff"]["changed"]:
        ch["view"] = _policy_change_view(ch)
    sections.append(pol_sec)

    # Static Routes — matched by (dst, gateway, device), never by seq
    routes_a, routes_b = extract_routes(root_a), extract_routes(root_b)
    sections.append(_list_section(
        "routes", "Static Routes", routes_a, routes_b, _route_key,
        label_field="seq"))

    # VPN tunnels (phase1) — phase2 is diffed separately below
    vpn_a, vpn_b = extract_vpn(root_a), extract_vpn(root_b)
    vpn_sec = _list_section(
        "vpn", "IPsec Tunnels", vpn_a, vpn_b, _name_key,
        exclude_keys={"phase2", "psk_set"}, identity_fields=frozenset({"name"}))
    p2_a, p2_b = _flatten_phase2(vpn_a), _flatten_phase2(vpn_b)
    vpn_sec["phase2_diff"] = _compute_diff(p2_a, p2_b, _phase2_key)
    vpn_sec["phase2_status"] = _git_status(vpn_sec["phase2_diff"], "vpn/phase2")
    vpn_sec["count"] += _diff_count(vpn_sec["phase2_diff"])
    sections.append(vpn_sec)

    # NAT / VIPs
    vip_a, vip_b = extract_nat_vips(root_a), extract_nat_vips(root_b)
    sections.append(_list_section(
        "nat", "NAT / VIPs", vip_a, vip_b, _name_key,
        identity_fields=frozenset({"name"})))

    # Single-object sections
    sections.append(_dict_section(
        "dns", "DNS", extract_dns(root_a), extract_dns(root_b)))
    sections.append(_dict_section(
        "ntp", "NTP", extract_ntp(root_a), extract_ntp(root_b)))
    sections.append(_dict_section(
        "ha", "HA Cluster", extract_ha(root_a), extract_ha(root_b)))

    # Summary
    data["sections"] = sections
    data["summary"] = {
        "added": sum(len(s["diff"]["added"]) for s in sections if s.get("diff"))
                 + sum(len(s["phase2_diff"]["added"]) for s in sections if s.get("phase2_diff")),
        "removed": sum(len(s["diff"]["removed"]) for s in sections if s.get("diff"))
                   + sum(len(s["phase2_diff"]["removed"]) for s in sections if s.get("phase2_diff")),
        "changed": sum(len(s["diff"]["changed"]) for s in sections if s.get("diff"))
                   + sum(len(s["phase2_diff"]["changed"]) for s in sections if s.get("phase2_diff"))
                   + sum(1 for s in sections if s.get("diff") is None and s.get("changed")),
        "unchanged_sections": sum(1 for s in sections if s["count"] == 0),
    }

    return data
