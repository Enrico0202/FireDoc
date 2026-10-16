"""
analysis.py — Unused object detection.
"""

# ══════════════════════════════════════════════════════════════════════════════
# DETECTORS — unused objects
# ══════════════════════════════════════════════════════════════════════════════

def detect_unused_objects(data: dict) -> dict:
 """
 Scan address objects and groups for references in firewall policies,
 VIPs, and group memberships.
 Services are excluded — predefined services (HTTP/HTTPS/SSH/DNS etc.)
 are always available and don't need usage tracking.
 Also skips FortiGate system/default objects (FCTEMS_*, FORTIGATE_*, etc.)
 which are auto-created and cannot be removed.
 """
 # FortiGate system/default object prefixes — auto-created, don't flag
 _FORTINET_PREFIXES = (
  "fctems_", "fortigate_", "forticlient_", "fabric_",
  "fsso_", "ems_", "sslvpn_", "fortitoken_",
  "fortiedr_", "fortideceptor_", "fortisase_",
  "fortiweb_", "fortiproxy_", "fortianalyzer_",
  "fortimanager_", "fortiauthenticator_",
  "fortiguard_", "fortisandbox_",
  "firewall_auth_",
  "ssl\\.", "adfs_", "o365_", "azure_",
 )
 import re
 _def_prefix = re.compile(r'^(' + '|'.join(_FORTINET_PREFIXES) + r')', re.I)

 def _is_fortinet_default(name: str) -> bool:
  return bool(_def_prefix.match(name))

 # Build sets of referenced names (lowercased)
 referenced_addresses: set[str] = set()
 referenced_groups: set[str] = set()

 for p in data.get("policies", []):
  for s in p.get("srcaddr", []):
   referenced_addresses.add(s.lower())
  for s in p.get("dstaddr", []):
   referenced_addresses.add(s.lower())

 for g in data.get("groups", []):
  for m in g.get("members", []):
   referenced_addresses.add(m.lower())

 for v in data.get("vips", []):
  if v.get("mapped_ip"):
   referenced_addresses.add(v["mapped_ip"].lower())
  if v.get("ext_ip"):
   referenced_addresses.add(v["ext_ip"].lower())

 # Also check if groups reference other groups
 for g in data.get("groups", []):
  for m in g.get("members", []):
   referenced_groups.add(m.lower())

 unused_addresses = []
 for a in data.get("addresses", []):
  name_lower = a["name"].lower()
  if _is_fortinet_default(a["name"]):
   continue
  if name_lower not in referenced_addresses:
   unused_addresses.append(a["name"])

 unused_groups = []
 for g in data.get("groups", []):
  name_lower = g["name"].lower()
  if _is_fortinet_default(g["name"]):
   continue
  if name_lower not in referenced_groups and name_lower not in referenced_addresses:
   unused_groups.append(g["name"])

 return {
  "unused_addresses": unused_addresses,
  "unused_groups": unused_groups,
 }


