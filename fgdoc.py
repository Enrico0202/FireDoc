#!/usr/bin/env python3
"""
FortiGate Doc Generator (FortiDoc)
Copyright 2026 Enrico Scheming
License: Apache-2.0 (see LICENSE)
"""

import sys
import re
import json
from pathlib import Path
from typing import Any

from parser import parse_config
from extractors import (
    extract_version_info, extract_global, extract_interfaces,
    extract_routes, extract_policy_routes, extract_addresses,
    extract_groups, extract_services, extract_service_groups,
    extract_policies, extract_vpn, extract_nat_vips, extract_admins,
    extract_dns, extract_ntp, extract_syslog, extract_snmp,
    extract_ssl_vpn, extract_dhcp_servers, extract_zones,
    extract_dhcp_details, extract_ha, extract_shapers,
    extract_certificates, extract_sdwan, extract_bgp, extract_ospf,
)
from findings import compute_findings, apply_finding_settings
from analysis import detect_unused_objects
from renderers import build_report


# ══════════════════════════════════════════════════════════════════════════════
# USER SETTINGS ← edit this block to customise behaviour
# ══════════════════════════════════════════════════════════════════════════════

CONFIG = {
 # ── Folder paths (relative to this script's location) ──────────────────
 "input_folder": "input", # drop your .conf file here
 "output_folder": "output", # HTML report is written here,

 # ── Section filter ───────────────────────────────────────────────────────
 # Leave empty [] to include all sections.
 # Valid values: interfaces routes addresses groups services policies nat vpn admins
 "sections": [],

 # ── Extra output ─────────────────────────────────────────────────────────
 # Write extracted data as JSON alongside the HTML report.
 "dump_json": False,
}

# ══════════════════════════════════════════════════════════════════════════════
# SHARED PIPELINE — used by both standalone main() and Flask app.py
# ══════════════════════════════════════════════════════════════════════════════


def process_config(raw: str, meta: dict, settings: dict | None = None) -> tuple[dict, str]:
 """Full processing pipeline: parse → extract → findings → render.
 Returns (data_dict, html_string). Use this from both main() and Flask app.py.

 ``settings`` (admin UI) filters which sections are rendered; None → all."""
 root = parse_config(raw)
 dhcp_servers = extract_dhcp_servers(root)

 data: dict[str, Any] = {
  "version_info": extract_version_info(raw),
  "global": extract_global(root),
  "interfaces": extract_interfaces(root, dhcp_servers),
  "routes": extract_routes(root),
  "sdwan": extract_sdwan(root),
  "bgp": extract_bgp(root),
  "ospf": extract_ospf(root),
  "addresses": extract_addresses(root),
  "zones": extract_zones(root),
  "groups": extract_groups(root),
  "services": extract_services(root),
  "service_groups": extract_service_groups(root),
  "policies": extract_policies(root),
  "vips": extract_nat_vips(root),
  "vpn": (vpn_all := extract_vpn(root)),
  "vpn_s2s": [v for v in vpn_all if not (v.get("type") == "dynamic" and (v.get("mode_cfg") == "enable" or v.get("ipv4_start_ip") or v.get("ipv6_start_ip")))],
  "vpn_ra": [v for v in vpn_all if v.get("type") == "dynamic" and (v.get("mode_cfg") == "enable" or v.get("ipv4_start_ip") or v.get("ipv6_start_ip"))],
  "policy_routes": extract_policy_routes(root),
  "dhcp_details": extract_dhcp_details(root),
  "ha": extract_ha(root),
  "snmp": extract_snmp(root),
  "shapers": extract_shapers(root),
  "certificates": extract_certificates(root),
  "ssl_vpn": extract_ssl_vpn(root),
  "admins": extract_admins(root),
  "dns": extract_dns(root),
  "ntp": extract_ntp(root),
  "syslog": extract_syslog(root),
  "dhcp_servers": list(dhcp_servers),
 }

 data["findings"] = compute_findings(data, root)
 # Apply admin overrides (per-finding severity/remediation/disable) + custom findings.
 # No settings (CLI / pre-admin) → overrides is empty → built-ins unchanged.
 apply_finding_settings(data["findings"], settings or {}, raw)

 # ── DNAT detection: check if policy dstaddr matches a VIP name ──
 vip_names: set[str] = set()
 for v in data.get("vips", []):
  if v.get("kind") == "vip":
   vip_names.add(v["name"])
 for p in data.get("policies", []):
  dnat_vips = [a for a in p.get("dstaddr", []) if a in vip_names]
  p["dnat"] = dnat_vips if dnat_vips else []

 # Usage counters — per-policy references only (srcaddr/dstaddr → address; service → service)
 _ref_addr: dict[str, int] = {}
 _ref_svc: dict[str, int] = {}
 for p in data.get("policies", []):
  for a in p.get("srcaddr", []):
   _ref_addr[a.lower()] = _ref_addr.get(a.lower(), 0) + 1
  for a in p.get("dstaddr", []):
   _ref_addr[a.lower()] = _ref_addr.get(a.lower(), 0) + 1
  for s in p.get("services", []):
   _ref_svc[s.lower()] = _ref_svc.get(s.lower(), 0) + 1
 for a in data.get("addresses", []):
  a["usage_count"] = _ref_addr.get(a["name"].lower(), 0)
 for g in data.get("groups", []):
  g["usage_count"] = _ref_addr.get(g["name"].lower(), 0)
 for s in data.get("services", []):
  s["usage_count"] = _ref_svc.get(s["name"].lower(), 0)
 for g in data.get("service_groups", []):
  g["usage_count"] = _ref_svc.get(g["name"].lower(), 0)

 html = build_report(data, meta, settings)
 return data, html


# ══════════════════════════════════════════════════════════════════════════════
# FOLDER SCANNER — finds exactly one config file in input/
# ══════════════════════════════════════════════════════════════════════════════

CONFIG_EXTENSIONS = {".conf", ".cfg", ".txt", ".log"}


def find_input_file(input_dir: Path) -> Path:
 """
 Locate exactly one config file in input_dir.

 Rules:
 - Accepted extensions: .conf .cfg .txt .log
 - Hidden files (starting with .) are ignored.
 - If zero files are found → print instructions and exit.
 - If more than one file is found → print a clear error and exit.
 - If exactly one file is found → return its Path.
 """
 candidates = [
  f for f in input_dir.iterdir()
  if f.is_file()
  and not f.name.startswith(".")
  and f.suffix.lower() in CONFIG_EXTENSIONS
 ]

 if len(candidates) == 0:
  print()
  print("=" * 60)
  print(" ERROR — No config file found in the input/ folder.")
  print("=" * 60)
  print()
  print(" Steps to fix:")
  print(f" 1. Export your FortiGate config (see README.md for")
  print(f" the full export guide).")
  print(f" 2. Copy the .conf file into: {input_dir}")
  print(f" 3. Run this script again.")
  print()
  print(" Accepted file extensions: .conf .cfg .txt .log")
  print()
  sys.exit(1)

 if len(candidates) > 1:
  print()
  print("=" * 60)
  print(" ERROR — More than one config file found in input/.")
  print("=" * 60)
  print()
  print(" The input/ folder must contain exactly ONE config file.")
  print(" Files found:")
  for f in sorted(candidates):
   print(f" • {f.name}")
  print()
  print(" Steps to fix:")
  print(" 1. Remove all but the one config file you want to")
  print(" document from the input/ folder.")
  print(" 2. Run this script again.")
  print()
  print(" Tip: move older config files to a separate archive")
  print(" folder outside this project to keep them safe.")
  print()
  sys.exit(1)

 return candidates[0]


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

SEPARATOR = "─" * 52


def main() -> None:
 """Standalone entry point: find input → process → write."""
 script_dir = Path(__file__).parent
 input_dir, output_dir = script_dir / CONFIG["input_folder"], script_dir / CONFIG["output_folder"]
 input_dir.mkdir(exist_ok=True); output_dir.mkdir(exist_ok=True)

 print(f"\n FortiGate Documentation Generator\n{SEPARATOR}")
 print(" [1/4] Scanning input/ folder …")
 input_path = find_input_file(input_dir)
 print(f" Found: {input_path.name}")
 print(" [2/4] Reading config …")
 raw = input_path.read_text(encoding="utf-8", errors="replace")
 print(f" {raw.count(chr(10)):,} lines")

 print(" [3/4] Parsing and extracting …")
 meta = {"client": "", "prepared_by": ""}
 data, html_out = process_config(raw, meta)

 # Optional section filter — clear non-selected keys and re-render
 if CONFIG.get("sections"):
  keep = set(CONFIG["sections"])
  for k in list(data.keys()):
   if k not in ("global", "dns", "ntp", "syslog") and k not in keep:
    data[k] = [] if isinstance(data[k], list) else {}
  html_out = build_report(data, meta)

 # Executive summary metrics
 unused = detect_unused_objects(data)
 data["summary_metrics"] = {
  "admin_https_ports": sorted({v for k, v in data["global"].items() if k == "admin-sport"}),
  "admin_http_ports": sorted({v for k, v in data["global"].items() if k in ("admin-http-port", "admin-sport-http")}),
  "super_admin_no_trusted": sum(1 for a in data["admins"] if a["profile"] == "super_admin" and not a["trusted_hosts"]),
  "ssl_vpn_status": data.get("ssl_vpn", {}).get("status", "unknown"),
  "ha_status": "enabled" if data["global"].get("ha", "") else "unknown",
  "firmware": data["version_info"].get("firmware", ""),
  "serial": data["version_info"].get("serial", ""),
  "total_unused_objects": len(unused.get("unused_addresses", [])) + len(unused.get("unused_groups", [])),
 }

 print(" [4/4] Writing output …")
 hostname = data["global"].get("hostname", input_path.stem)
 safe_name = re.sub(r"[^\w\-.]", "_", hostname)
 output_path = output_dir / f"{safe_name}_report.html"
 output_path.write_text(html_out, encoding="utf-8")

 if CONFIG.get("dump_json"):
  json_path = output_dir / f"{safe_name}_data.json"
  json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
  print(f" JSON data → {json_path.name}")

 high = sum(1 for f in data["findings"] if f["severity"] == "high")
 medium = sum(1 for f in data["findings"] if f["severity"] == "medium")
 print(f"\n{SEPARATOR}\n ✓ Report ready: output/{output_path.name}\n{SEPARATOR}"
    f"\n Hostname : {hostname}\n Interfaces: {len(data['interfaces'])}"
    f"\n Policies : {len(data['policies'])}\n VPN tunnels: {len(data['vpn'])}"
    f"\n Findings : {high} high | {medium} medium"
    + f"\n{SEPARATOR}\n")


if __name__ == "__main__":
 main()
