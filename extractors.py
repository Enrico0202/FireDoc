"""
extractors.py — Data extraction from parsed FortiOS config tree.
"""

import re
from utils import js_name
from parser import find_config, find_config_in_obj, prop, prop_list

# ══════════════════════════════════════════════════════════════════════════════
# EXTRACTORS
# ══════════════════════════════════════════════════════════════════════════════

# Backward-compatible alias — moved to utils.py
_js_name = js_name


def mask_to_cidr(ip: str, mask: str) -> str:
 """Convert dotted-decimal mask to prefix-length CIDR notation."""
 if not mask:
  return ip
 try:
  bits = sum(bin(int(o)).count("1") for o in mask.split("."))
  return f"{ip}/{bits}"
 except Exception:
  return f"{ip}/{mask}"


def mask_to_cidr_prefix(mask: str) -> str:
 """Convert dotted-decimal mask to CIDR prefix length, e.g. 255.255.255.0 → 24."""
 try:
  bits = sum(bin(int(o)).count("1") for o in mask.split("."))
  return str(bits)
 except Exception:
  return ""


def apply_netmask(ip: str, mask: str) -> str:
 """Calculate network address from IP + dotted-decimal netmask."""
 try:
  ip_parts = [int(o) for o in ip.split(".")]
  mask_parts = [int(o) for o in mask.split(".")]
  net = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
  return ".".join(net)
 except Exception:
  return ip


def extract_table(root, config_path, field_map, *, list_fields=None, skip_names=None):
 """Extract table config entries into list of dicts.
 field_map: {src_property: dst_key} — each src maps to an output field.
 list_fields: set of src_property names to read with prop_list.
 skip_names: set of table entry names to skip.
 Each row gets 'name' = the table entry key automatically."""
 block = find_config(root, config_path)
 rows = []
 for name, obj in block.get("table", {}).items():
  if skip_names and name in skip_names:
   continue
  row = {"name": name}
  for src, dst in field_map.items():
   if list_fields and src in list_fields:
    row[dst] = prop_list(obj, src)
   else:
    row[dst] = prop(obj, src, "")
  rows.append(row)
 return rows


def extract_version_info(raw: str) -> dict:
 """Parse firmware, serial and model from the FortiOS config.

 Serial priority: 1) CSF device ID (most accurate),
 2) #config-version header, 3) hostname fallback."""
 result = {"firmware": "", "build": "", "serial": "", "model": ""}
 # 1) Firmware/build from #config-version header
 for line in raw.splitlines()[:30]:
  m = re.match(r"#config-version=([A-Z0-9]+)-(\d+\.\d+\.\d+)-FW-build(\d+)", line)
  if m:
   result["serial"] = m.group(1)
   result["firmware"] = m.group(2)
   result["build"] = m.group(3)
   break
 # 2) CSF device ID — overrides header serial if found (more specific)
 csf_m = re.search(r'set\s+csf-device\s+"([^"]+)"', raw)
 if csf_m:
  result["serial"] = csf_m.group(1)
  result["model"] = ""  # clear fallback marker
 # 3) Last fallback: hostname
 if not result["serial"]:
  host_m = re.search(r'set\s+hostname\s+"?([^"\s]+)"?', raw)
  if host_m:
   result["serial"] = host_m.group(1)
   result["model"] = "(hostname fallback)"
 return result


def extract_global(root: list[dict]) -> dict:
 g = find_config(root, "system global")
 return {k: v for k, v in g.get("properties", {}).items()
     if not k.startswith("__")}


def extract_interfaces(root: list[dict], dhcp_servers: set | None = None) -> list[dict]:
 if dhcp_servers is None:
  dhcp_servers = set()
 block = find_config(root, "system interface")
 rows = []
 skip = {"ssl.root", "vsys_ha", "fortilink", "naf.root"}
 for name, obj in block.get("table", {}).items():
  if name in skip:
   continue
  ip_raw = prop(obj, "ip", "")
  parts = ip_raw.split(" ", 1) if ip_raw else ["", ""]
  addr, mask = (parts + [""])[:2]
  dhcp_enabled = name in dhcp_servers
  vlanid_val = prop(obj, "vlanid", "")
  iftype = prop(obj, "type", "physical")
  if vlanid_val:
   iftype = "vlan"
  rows.append({
   "name": name,
   "ip": addr,
   "mask": mask,
   "cidr": mask_to_cidr(addr, mask) if addr else "",
   "type": iftype,
   "role": prop(obj, "role", ""),
   "access": " ".join(prop_list(obj, "allowaccess")),
   "description": prop(obj, "description", ""),
   "status": prop(obj, "status", "up"),
   "dhcp_server": dhcp_enabled,
   "interface": prop(obj, "interface", ""),
   "vlanid": prop(obj, "vlanid", ""),
  })
 return rows


def extract_routes(root: list[dict]) -> list[dict]:
 block = find_config(root, "router static")
 rows = []
 for name, obj in block.get("table", {}).items():
  dst_raw = prop(obj, "dst", "0.0.0.0 0.0.0.0")
  parts = dst_raw.split(" ", 1)
  net, msk = (parts + [""])[:2]
  rows.append({
   "seq": name,
   "dst": mask_to_cidr(net, msk),
   "gateway": prop(obj, "gateway", ""),
   "device": prop(obj, "device", ""),
   "distance": prop(obj, "distance", "10"),
   "priority": prop(obj, "priority", "0"),
   "comment": prop(obj, "comment", ""),
   "is_default": net == "0.0.0.0" and msk in ("0.0.0.0", ""),
  })
 rows.sort(key=lambda r: (int(r["distance"]), int(r["priority"])))
 return rows


def extract_policy_routes(root: list[dict]) -> list[dict]:
    """Extract policy-based routes from config router policy."""
    block = find_config(root, "router policy")
    rows = []
    for name, obj in block.get("table", {}).items():
        rows.append({
            "seq": name,
            "input_device": prop_list(obj, "input-device"),
            "src": prop_list(obj, "src") or prop_list(obj, "srcaddr"),
            "dst": prop_list(obj, "dst") or prop_list(obj, "dstaddr"),
            "protocol": prop(obj, "protocol", "0"),
            "start_port": prop(obj, "start-port", ""),
            "end_port": prop(obj, "end-port", ""),
            "tos": prop(obj, "tos", ""),
            "tos_mask": prop(obj, "tos-mask", ""),
            "gateway": prop(obj, "gateway", ""),
            "output_device": prop(obj, "output-device", ""),
            "status": "disabled" if prop(obj, "status", "enable") == "disable" else "enabled",
            "action": prop(obj, "action", ""),
            "priority": prop(obj, "priority", ""),
            "comments": prop(obj, "comments", ""),
        })
    rows.sort(key=lambda r: int(r["seq"]) if r["seq"].isdigit() else 0)
    return rows


def extract_addresses(root: list[dict]) -> list[dict]:
 block = find_config(root, "firewall address")
 rows = []
 for name, obj in block.get("table", {}).items():
  if name == "all":
   continue
  typ = prop(obj, "type", "ipmask")
  if typ == "ipmask":
   sub = prop(obj, "subnet", "")
   parts = sub.split(" ", 1)
   net, msk = (parts + [""])[:2]
   value = mask_to_cidr(net, msk) if net else sub
  elif typ == "iprange":
   value = f"{prop(obj, 'start-ip')} – {prop(obj, 'end-ip')}"
  elif typ == "fqdn":
   value = prop(obj, "fqdn")
  elif typ == "geography":
   value = f"country:{prop(obj, 'country')}"
  elif typ == "wildcard-fqdn":
   value = prop(obj, "wildcard-fqdn")
  else:
   value = typ
  rows.append({
   "name": name,
   "type": typ,
   "value": value,
   "comment": prop(obj, "comment", ""),
  })
 return rows


def extract_groups(root: list[dict]) -> list[dict]:
 return extract_table(root, "firewall addrgrp",
  {"member": "members", "comment": "comment"},
  list_fields={"member"})


def extract_services(root: list[dict]) -> list[dict]:
 block = find_config(root, "firewall service custom")
 rows = []
 for name, obj in block.get("table", {}).items():
  proto = prop(obj, "protocol", "TCP/UDP/SCTP")
  rows.append({
   "name": name,
   "protocol": proto,
   "tcp_ports": prop(obj, "tcp-portrange", ""),
   "udp_ports": prop(obj, "udp-portrange", ""),
   "icmp": f"{prop(obj, 'icmptype')}/{prop(obj, 'icmpcode', '0')}"
    if proto == "ICMP" else "",
   "comment": prop(obj, "comment", ""),
  })
 return rows

def extract_service_groups(root: list[dict]) -> list[dict]:
 block = find_config(root, "firewall service group")
 rows = []
 for name, obj in block.get("table", {}).items():
  rows.append({
   "name": name,
   "comment": prop(obj, "comment", ""),
   "members": prop_list(obj, "member"),
  })
 return rows


def extract_policies(root: list[dict]) -> list[dict]:
 block = find_config(root, "firewall policy")
 rows = []
 for name, obj in block.get("table", {}).items():
  rows.append({
   "seq": int(name) if name.isdigit() else 0,
   "name": prop(obj, "name", "(unnamed)"),
   "status": "disabled"
    if prop(obj, "status", "enable") == "disable"
    else "enabled",
   "action": "deny" if prop(obj, "action", "deny").lower() in ("block", "deny") else prop(obj, "action", "deny"),
   "srcintf": prop_list(obj, "srcintf"),
   "dstintf": prop_list(obj, "dstintf"),
   "srcaddr": prop_list(obj, "srcaddr"),
   "dstaddr": prop_list(obj, "dstaddr") or ["all"],
   "services": prop_list(obj, "service"),
   "isdb": [f"ISDB:{x}" for x in prop_list(obj, "internet-service-name")] if prop(obj, "internet-service", "disable") == "enable" else [],
   "schedule": prop(obj, "schedule", "always"),
   "nat": prop(obj, "nat", "disable") == "enable",
   "natpool": prop(obj, "poolname", ""),
   "logtraffic": prop(obj, "logtraffic", "utm"),
   "comments": prop(obj, "comments", ""),
   "av": prop(obj, "av-profile", ""),
   "ips": prop(obj, "ips-sensor", ""),
   "webfilter": prop(obj, "webfilter-profile", ""),
   "appctrl": prop(obj, "application", ""),
   "dlp": prop(obj, "dlp-sensor", ""),
   "dnsfilter": prop(obj, "dnsfilter-profile", ""),
   "emailfilter": prop(obj, "emailfilter-profile", ""),
   "cifs": prop(obj, "cifs-profile", ""),
   "protocolopt": prop(obj, "profile-protocol-options", ""),
   "sslssh": prop(obj, "ssl-ssh-profile", ""),
   "videofilter": prop(obj, "videofilter-profile", ""),
   "voip": prop(obj, "voip-profile", ""),
   "waf": prop(obj, "waf-profile", ""),
   "profile_group": prop(obj, "profile-group", ""),
  })
 rows.sort(key=lambda r: r["seq"])
 return rows


def extract_vpn(root: list[dict]) -> list[dict]:
 p1_block = find_config(root, "vpn ipsec phase1-interface")
 p2_block = find_config(root, "vpn ipsec phase2-interface")

 p2_map: dict[str, list[dict]] = {}
 for name, obj in p2_block.get("table", {}).items():
  ph1 = prop(obj, "phase1name", "")
  p2_map.setdefault(ph1, []).append({
   "name": name,
   "proposal": prop(obj, "proposal", ""),
   "dhgrp": " ".join(prop_list(obj, "dhgrp")),
   "src_subnet": prop(obj, "src-subnet", ""),
   "dst_subnet": prop(obj, "dst-subnet", ""),
  })

 rows = []
 for name, obj in p1_block.get("table", {}).items():
  rows.append({
   "name": name,
   "interface": prop(obj, "interface", ""),
   "remote_gw": prop(obj, "remote-gw", ""),
   "type": prop(obj, "type", "static"),
   "ike_version": prop(obj, "ike-version", "1"),
   "proposal": prop(obj, "proposal", ""),
   "dpd": prop(obj, "dpd", "disable"),
   "psk_set": bool(prop(obj, "psksecret", "")),
   "mode_cfg": prop(obj, "mode-cfg", "disable"),
   "ipv4_start_ip": prop(obj, "ipv4-start-ip", ""),
   "ipv4_end_ip": prop(obj, "ipv4-end-ip", ""),
   "ipv6_start_ip": prop(obj, "ipv6-start-ip", ""),
   "ipv6_end_ip": prop(obj, "ipv6-end-ip", ""),
   "comment": prop(obj, "comments", ""),
   "phase2": p2_map.get(name, []),
  })
 return rows


def extract_nat_vips(root: list[dict]) -> list[dict]:
 block = find_config(root, "firewall vip")
 rows = []
 for name, obj in block.get("table", {}).items():
  rows.append({
   "name": name,
   "ext_intf": prop(obj, "extintf", ""),
   "ext_ip": prop(obj, "extip", ""),
   "mapped_ip": prop(obj, "mappedip", ""),
   "port_forward": prop(obj, "portforward", "disable") == "enable",
   "ext_port": prop(obj, "extport", ""),
   "mapped_port": prop(obj, "mappedport", ""),
   "comment": prop(obj, "comment", ""),
   "kind": "vip",
  })
 # Also extract IP pools (config firewall ippool)
 pool_block = find_config(root, "firewall ippool")
 for pname, pobj in pool_block.get("table", {}).items():
  rows.append({
   "name": pname,
   "ext_intf": prop(pobj, "associated-interface", ""),
   "ext_ip": prop(pobj, "startip", ""),
   "end_ip": prop(pobj, "endip", ""),
   "comment": prop(pobj, "comments", ""),
   "kind": "ippool",
  })
 return rows


def extract_admins(root: list[dict]) -> list[dict]:
 block = find_config(root, "system admin")
 rows = []
 for name, obj in block.get("table", {}).items():
  trusted = [prop(obj, f"trusthost{i}", "")
        for i in range(1, 11)
        if prop(obj, f"trusthost{i}", "")]
  rows.append({
   "username": name,
   "profile": prop(obj, "accprofile", "prof_admin"),
   "vdom": prop(obj, "vdom", "root"),
   "two_factor": prop(obj, "two-factor", "disable"),
   "ssh_key": bool(prop(obj, "ssh-public-key1", "")),
   "trusted_hosts": trusted,
   "comments": prop(obj, "comments", ""),
  })
 return rows


def extract_dns(root: list[dict]) -> dict:
 g = find_config(root, "system dns")
 return {
  "primary": prop(g, "primary", ""),
  "secondary": prop(g, "secondary", ""),
  "domain": prop(g, "domain", ""),
 }


def extract_ntp(root: list[dict]) -> dict:
 g = find_config(root, "system ntp")
 # 1) Explicit NTP servers: config ntpserver sub-table
 ntpserver_block = find_config_in_obj(g, "ntpserver")
 servers = []
 for sid, sobj in ntpserver_block.get("table", {}).items():
  srv = prop(sobj, "server", "")
  if srv:
   servers.append(srv)
 # Fallback: check flat ntpserver1..ntpserverN
 if not servers:
  for i in range(1, 10):
   srv = prop(g, f"ntpserver{i}", "")
   if srv:
    servers.append(srv)
 # Fallback: 'server' flat
 if not servers:
  alt_server = prop(g, "server", "")
  if alt_server:
   servers.append(alt_server)
 # 2) Interfaces where the FW acts as NTP server (server-mode)
 server_mode = prop(g, "server-mode", "disable")
 ntp_server_ifaces = prop_list(g, "interface") if server_mode == "enable" else []
 # 3) Also interface-level allowaccess ntp
 iface_block = find_config(root, "system interface")
 ntp_access_ifaces = []
 for iname, iobj in iface_block.get("table", {}).items():
  access = prop(iobj, "allowaccess", "")
  if "ntp" in access.split():
   ntp_access_ifaces.append(iname)
 return {
  "sync": prop(g, "ntpsync", "disable"),
  "type": prop(g, "type", "fortiguard"),
  "server_mode": server_mode,
  "servers": servers,
  "ntp_interfaces": ntp_server_ifaces,
  "ntp_access_interfaces": ntp_access_ifaces,
  "source_ip": prop(g, "source-ip", ""),
 }


def extract_syslog(root: list[dict]) -> dict:
 g = find_config(root, "log syslogd setting")
 return {
  "status": prop(g, "status", "disable"),
  "server": prop(g, "server", ""),
  "port": prop(g, "port", "514"),
  "mode": prop(g, "mode", "udp"),
 }


def extract_snmp(root: list[dict]) -> dict:
 """Extract SNMP configuration from config system snmp sysinfo + community."""
 sysinfo = find_config(root, "system snmp sysinfo")
 community_block = find_config(root, "system snmp community")
 communities = []
 for cid, cobj in community_block.get("table", {}).items():
  hosts = []
  hosts_block = find_config_in_obj(cobj, "hosts")
  for hid, hobj in hosts_block.get("table", {}).items():
   hosts.append({
    "id": hid,
    "ip": prop(hobj, "ip", ""),
    "host_type": prop(hobj, "host-type", ""),
   })
  events = prop_list(cobj, "events")
  communities.append({
   "id": cid,
   "name": prop(cobj, "name", ""),
   "hosts": hosts,
   "events": events,
   "query_v1": prop(cobj, "query-v1-status", "disable"),
   "trap_v1": prop(cobj, "trap-v1-status", "disable"),
   "trap_v2c": prop(cobj, "trap-v2c-status", "disable"),
  })
 # SNMPv3 users
 user_block = find_config(root, "system snmp user")
 users = []
 for uid, uobj in user_block.get("table", {}).items():
  users.append({
   "name": prop(uobj, "name", uid),
   "security_level": prop(uobj, "security-level", ""),
   "auth_proto": prop(uobj, "auth-proto", ""),
   "priv_proto": prop(uobj, "priv-proto", ""),
   "auth_pwd_set": bool(prop(uobj, "auth-pwd", "")),
   "priv_pwd_set": bool(prop(uobj, "priv-pwd", "")),
   "queries": prop(uobj, "queries", "disable"),
   "notify_hosts": prop_list(uobj, "notify-hosts"),
   "events": prop_list(uobj, "events"),
  })
 return {
  "status": prop(sysinfo, "status", "disable"),
  "location": prop(sysinfo, "location", ""),
  "contact": prop(sysinfo, "contact-info", ""),
  "description": prop(sysinfo, "description", ""),
  "communities": communities,
  "users": users,
 }



def extract_ssl_vpn(root: list[dict]) -> dict:
 # Try both paths: 'vpn ssl settings' and 'vpn ssl setting'
 g = find_config(root, "vpn ssl settings")
 if not g.get("properties"):
  g = find_config(root, "vpn ssl setting")

 portals_block = find_config(root, "vpn ssl web portal")
 portals = []
 for pname, pobj in portals_block.get("table", {}).items():
  # Extract nested split-dns entries
  split_dns_block = find_config_in_obj(pobj, "split-dns")
  split_dns_entries = []
  for sd_id, sd_obj in split_dns_block.get("table", {}).items():
   split_dns_entries.append({
    "id": sd_id,
    "domains": prop(sd_obj, "domains", ""),
    "dns_server1": prop(sd_obj, "dns-server1", ""),
    "dns_server2": prop(sd_obj, "dns-server2", ""),
   })
  portals.append({
   "name": pname,
   "tunnel_ip_pools": prop_list(pobj, "tunnel-ip-pools"),
   "split_tunneling": prop(pobj, "split-tunneling", "disable"),
   "limit_user_logins": prop(pobj, "limit-user-logins", "disable"),
   "split_dns": split_dns_entries,
  })

 # Extract authentication rules (map groups to portals)
 auth_rules_block = find_config_in_obj(g, "authentication-rule")
 auth_rules = []
 for ar_id, ar_obj in auth_rules_block.get("table", {}).items():
  auth_rules.append({
   "id": ar_id,
   "groups": prop_list(ar_obj, "groups"),
   "portal": prop(ar_obj, "portal", ""),
  })

 status_raw = prop(g, "status", "disable")
 if isinstance(status_raw, list):
  status_raw = status_raw[0] if status_raw else "disable"

 def _get(key, default=""):
  v = prop(g, key, default)
  return v if not isinstance(v, list) else (v[0] if v else default)

 return {
  "status": status_raw,
  "port": _get("port", "443"),
  "servercert": _get("servercert"),
  "listen_interfaces": prop_list(g, "interface") or prop_list(g, "listen-interface"),
  "source_interface": _get("source-interface"),
  "tunnel_ip_pools": prop_list(g, "tunnel-ip-pools"),
  "tunnel_ipv6_pools": prop_list(g, "tunnel-ipv6-pools"),
  "source_address": prop_list(g, "source-address"),
  "source_address6": prop_list(g, "source-address6"),
  "source_address_negate": _get("source-address-negate"),
  "idle_timeout": _get("idle-timeout", "300"),
  "auth_timeout": _get("auth-timeout", "28800"),
  "login_timeout": _get("login-timeout"),
  "login_attempt_limit": _get("login-attempt-limit"),
  "login_block_time": _get("login-block-time"),
  "max_concurrent_user": _get("max-concurrent-user"),
  "dtls_tunnel": _get("dtls-tunnel"),
  "hsts": _get("hsts"),
  "ssl_version": _get("ssl-version", "tls-1.2"),
  "tls_versions": _get("tls-versions"),
  "ciphersuites": _get("ciphersuites"),
  "banned_cipher": _get("banned-cipher"),
  "cipher": _get("cipher"),
  "auth_type": _get("auth-type"),
  "auth_cert": _get("auth-cert"),
  "auth_portal": _get("auth-portal"),
  "default_portal": _get("default-portal"),
  "require_client_cert": _get("require-client-cert"),
  "dns_server1": _get("dns-server1"),
  "dns_server2": _get("dns-server2"),
  "dns_suffix": _get("dns-suffix"),
  "wins_server1": _get("wins-server1"),
  "wins_server2": _get("wins-server2"),
  "split_tunneling": _get("split-tunneling"),
  "split_tunnel_routing": _get("split-tunnel-routing-address"),
  "http_redirect": _get("http302-forward-to-https"),
  "https_redirect": _get("https-redirect"),
  "hsts": _get("hsts"),
  "portals": portals,
  "auth_rules": auth_rules,
 }


def extract_dhcp_servers(root: list[dict]) -> set[str]:
 """Return the set of interface names that have a DHCP server enabled."""
 block = find_config(root, "system dhcp server")
 interfaces: set[str] = set()
 for _name, obj in block.get("table", {}).items():
  iface = prop(obj, "interface", "")
  if iface:
   interfaces.add(iface)
 return interfaces


def extract_zones(root: list[dict]) -> list[dict]:
 """Extract zone definitions from config system zone."""
 # FortiGate 7.x uses 'interface' instead of 'member' for zone members
 def _zone_members(obj):
  return prop_list(obj, "interface") or prop_list(obj, "member")
 rows = []
 for name, obj in find_config(root, "system zone").get("table", {}).items():
  rows.append({
   "name": name,
   "members": _zone_members(obj),
   "intrazone": prop(obj, "intrazone", "deny"),
  })
 return rows


def extract_dhcp_details(root: list[dict]) -> list[dict]:
    """Extract full DHCP server details from config system dhcp server."""
    block = find_config(root, "system dhcp server")
    rows = []
    for name, obj in block.get("table", {}).items():
        # Collect DNS servers
        dns = []
        for i in range(1, 4):
            srv = prop(obj, f"dns-server{i}", "")
            if srv:
                dns.append(srv)
        # Collect options
        options = []
        for i in range(1, 11):
            opt = prop(obj, f"option{i}", "")
            if opt:
                options.append(opt)
        # Exclusion ranges
        exc_block = {"kind": "config", "table": {}}
        for child in obj.get("children", []):
            if child.get("path") == ["exclude-range"]:
                exc_block = child
                break
        excludes = []
        for ename, eobj in exc_block.get("table", {}).items():
            s = prop(eobj, "start-ip", "")
            e = prop(eobj, "end-ip", "")
            excludes.append(f"{s}-{e}" if s and e else s or e)
        # IP range — try direct props first, then nested config ip-range
        ip_start = prop(obj, "start-ip", "")
        ip_end = prop(obj, "end-ip", "")
        ip_range = prop(obj, "ip-range", "")
        if not ip_start and not ip_end:
         # Check nested config ip-range children
         for child in obj.get("children", []):
          if child.get("path") == ["ip-range"]:
           for rname, robj in child.get("table", {}).items():
            ip_start = ip_start or prop(robj, "start-ip", "")
            ip_end = ip_end or prop(robj, "end-ip", "")
            break
           break
        rows.append({
            "id": name,
            "interface": prop(obj, "interface", ""),
            "ip_start": ip_start or (ip_range.split(" ")[0] if ip_range else ""),
            "ip_end": ip_end or (ip_range.split(" ")[1] if ip_range and " " in ip_range else ""),
            "netmask": prop(obj, "netmask", ""),
            "gateway": prop(obj, "default-gateway", ""),
            "lease_time": prop(obj, "lease-time", ""),
            "domain": prop(obj, "domain", ""),
            "dns_servers": dns,
            "ntp_servers": [prop(obj, f"ntp-server{i}", "") for i in range(1, 4) if prop(obj, f"ntp-server{i}", "")],
            "wins_servers": [prop(obj, f"wins-server{i}", "") for i in range(1, 3) if prop(obj, f"wins-server{i}", "")],
            "options": options,
            "excludes": excludes,
            "status": prop(obj, "status", "enable"),
        })
    return rows


def extract_ha(root: list[dict]) -> dict:
    """Extract HA cluster status from config system ha."""
    block = find_config(root, "system ha")
    props = block.get("properties", {})
    if not props:
        return {"mode": "standalone"}

    mode = prop(block, "mode", "standalone")
    if mode in ("standalone", ""):
        return {"mode": "standalone"}

    # Monitored interfaces — try both 'monitor' (list) and 'monitor1'..'monitorN'
    monitored = prop_list(block, "monitor")
    if not monitored:
     for i in range(1, 21):
      iface = prop(block, f"monitor{i}", "")
      if iface:
       monitored.append(iface)

    # Vcluster status
    vcluster_block = block.get("properties", {}).get("__config_vcluster2", {})
    vclusters = []
    for vname, vobj in vcluster_block.get("table", {}).items():
        vclusters.append({
            "id": vname,
            "vdom": prop(vobj, "vdom", ""),
            "priority": prop(vobj, "priority", ""),
            "override": prop(vobj, "override", "disable"),
            "monitor": [prop(vobj, f"monitor{i}", "") for i in range(1, 11) if prop(vobj, f"monitor{i}", "")],
        })

    # Peer IPs
    peers = []
    for i in range(1, 5):
        p = prop(block, f"peer-hb-lost-interface{i}", "") or prop(block, f"unicast-hb-peerip{i}", "")
        if not p:
            p = prop(block, f"unicast-hb-peerip{i}", "")
        if p:
            peers.append(p)

    return {
        "mode": mode,
        "group_id": prop(block, "group-id", ""),
        "group_name": prop(block, "group-name", ""),
        "priority": prop(block, "priority", ""),
        "override": prop(block, "override", "disable"),
        "hb_interface": prop_list(block, "hbdev") or prop_list(block, "interface"),
        "hb_lost_threshold": prop(block, "hb-lost-threshold", ""),
        "session_sync": prop(block, "session-sync-dev", ""),
        "session_pickup": prop(block, "session-pickup", "disable"),
        "unicast": prop(block, "unicast-hb", "disable"),
        "peer_ips": peers,
        "encryption": prop(block, "encryption", "disable"),
        "monitored": monitored,
        "password_set": bool(prop(block, "password", "")),
        "hb_interval": prop(block, "hb-interval", ""),
        "vclusters": vclusters,
    }


def extract_shapers(root: list[dict]) -> dict:
    """Extract traffic shaping configuration."""
    # Traffic shapers (bandwidth definitions)
    ts_block = find_config(root, "firewall shaper traffic-shaper")
    shapers = []
    for name, obj in ts_block.get("table", {}).items():
        shapers.append({
            "name": name,
            "guaranteed": prop(obj, "guaranteed-bandwidth", ""),
            "maximum": prop(obj, "maximum-bandwidth", ""),
            "priority": prop(obj, "priority", "high"),
            "per_policy": prop(obj, "per-policy", "disable"),
            "cos": prop(obj, "cos-marking", ""),
        })

    # Per-IP shapers
    pis_block = find_config(root, "firewall shaper per-ip-shaper")
    per_ip = []
    for name, obj in pis_block.get("table", {}).items():
        per_ip.append({
            "name": name,
            "max_bandwidth": prop(obj, "max-bandwidth", ""),
            "max_concurrent": prop(obj, "max-concurrent-session", ""),
        })

    # Shaping policies
    sp_block = find_config(root, "firewall shaping-policy")
    policies = []
    for name, obj in sp_block.get("table", {}).items():
        policies.append({
            "seq": name,
            "name": prop(obj, "name", ""),
            "srcintf": prop_list(obj, "srcintf"),
            "dstintf": prop_list(obj, "dstintf"),
            "srcaddr": prop_list(obj, "srcaddr"),
            "dstaddr": prop_list(obj, "dstaddr"),
            "service": prop_list(obj, "service"),
            "traffic_shaper": prop(obj, "traffic-shaper", ""),
            "traffic_shaper_reverse": prop(obj, "traffic-shaper-reverse", ""),
            "per_ip_shaper": prop(obj, "per-ip-shaper", ""),
            "status": "disabled" if prop(obj, "status", "enable") == "disable" else "enabled",
            "comments": prop(obj, "comments", ""),
        })

    return {
        "shapers": shapers,
        "per_ip": per_ip,
        "policies": policies,
    }


def extract_certificates(root: list[dict]) -> list[dict]:
    """Extract local certificates from config vpn certificate local."""
    block = find_config(root, "vpn certificate local")
    rows = []
    for name, obj in block.get("table", {}).items():
        # Skip FortiGate factory/built-in certificates
        source = prop(obj, "source", "")
        if source == "factory":
            continue
        rows.append({
            "name": name,
            "range": prop(obj, "range", ""),
            "source": source,
            "comment": prop(obj, "comment", ""),
        })
    return rows
def extract_sdwan(root: list[dict]) -> dict:
    """Extract SD-WAN configuration from config system sdwan."""
    block = find_config(root, "system sdwan")
    if not block.get("properties", {}):
        return {"status": "disable", "zones": [], "members": [],
                "health_checks": [], "services": []}

    status = prop(block, "status", "disable")

    def _nested(prop_name: str) -> dict:
        """Get a nested config block from the SD-WAN properties."""
        child = block.get("properties", {}).get(prop_name, {})
        if isinstance(child, dict) and child.get("kind") == "config":
            return child
        return {"kind": "config", "path": [], "type": "table",
                "properties": {}, "table": {}}

    # ── Zones ──
    zones = []
    for name, obj in _nested("__config_zone").get("table", {}).items():
        zones.append({
            "name": name,
            "sla_tie_break": prop(obj, "service-sla-tie-break", "cfg-order"),
        })

    # ── Members ──
    members = []
    for name, obj in _nested("__config_members").get("table", {}).items():
        members.append({
            "seq": name,
            "interface": prop(obj, "interface", ""),
            "zone": prop(obj, "zone", ""),
            "source": prop(obj, "source", ""),
            "gateway": prop(obj, "gateway", ""),
            "priority": prop(obj, "priority", ""),
            "weight": prop(obj, "weight", ""),
            "cost": prop(obj, "cost", ""),
            "status": prop(obj, "status", "enable"),
        })

    # ── Health checks ──
    health_checks = []
    for name, obj in _nested("__config_health-check").get("table", {}).items():
        member_list = prop_list(obj, "members")
        # Extract nested SLA targets
        sla_block = find_config_in_obj(obj, "sla")
        sla_targets = []
        for sla_id, sla_obj in sla_block.get("table", {}).items():
            sla_targets.append({
                "id": sla_id,
                "link_cost_factor": prop(sla_obj, "link-cost-factor", ""),
                "latency_threshold": prop(sla_obj, "latency-threshold", ""),
                "jitter_threshold": prop(sla_obj, "jitter-threshold", ""),
                "packetloss_threshold": prop(sla_obj, "packetloss-threshold", ""),
            })
        health_checks.append({
            "name": name,
            "server": prop(obj, "server", ""),
            "protocol": prop(obj, "protocol", "ping"),
            "members": member_list,
            "interval": prop(obj, "interval", ""),
            "failtime": prop(obj, "failtime", ""),
            "sla_targets": sla_targets,
        })

    # ── Service rules ──
    services = []
    for name, obj in _nested("__config_service").get("table", {}).items():
        hc_list = prop_list(obj, "health-check")
        services.append({
            "seq": name,
            "name": prop(obj, "name", name),
            "mode": prop(obj, "mode", "sla"),
            "src": prop_list(obj, "src"),
            "dst": prop_list(obj, "dst"),
            "priority_members": prop_list(obj, "priority-members"),
            "health_check": hc_list,
        })

    return {
        "status": status,
        "zones": zones,
        "members": members,
        "health_checks": health_checks,
        "services": services,
    }


def extract_bgp(root: list[dict]) -> dict:
    """Extract BGP configuration from config router bgp."""
    block = find_config(root, "router bgp")
    if not block.get("properties", {}):
        return {"status": "not configured", "as": "", "router_id": "",
                "neighbors": [], "networks": [], "redistribute": []}

    as_num = prop(block, "as", "")
    router_id = prop(block, "router-id", "")

    # ── Neighbors ──
    neighbor_block = block.get("properties", {}).get("***neighbor", {})
    if not (isinstance(neighbor_block, dict) and neighbor_block.get("kind") == "config"):
        neighbor_block = find_config(root, "router bgp neighbor")
    neighbors = []
    for name, obj in neighbor_block.get("table", {}).items():
        neighbors.append({
            "ip": name,
            "remote_as": prop(obj, "remote-as", ""),
            "soft_reconfig": prop(obj, "soft-reconfiguration", "disable"),
            "description": prop(obj, "description", ""),
            "update_source": prop(obj, "update-source", ""),
            "route_map_out": prop(obj, "route-map-out", ""),
            "route_map_in": prop(obj, "route-map-in", ""),
            "prefix_list_in": prop(obj, "prefix-list-in", ""),
            "prefix_list_out": prop(obj, "prefix-list-out", ""),
            "next_hop_self": prop(obj, "next-hop-self", "disable"),
        })

    # ── Networks ──
    network_block = block.get("properties", {}).get("***network", {})
    if not (isinstance(network_block, dict) and network_block.get("kind") == "config"):
        network_block = find_config(root, "router bgp network")
    networks = []
    for name, obj in network_block.get("table", {}).items():
        raw_prefix = prop_list(obj, "prefix")
        prefix = " ".join(raw_prefix) if raw_prefix else ""
        networks.append({
            "seq": name,
            "prefix": prefix,
        })

    # ── Redistribution ──
    redistribute = []
    for k, v in block.get("properties", {}).items():
        if isinstance(v, dict) and v.get("kind") == "config" and v.get("path", [""])[0].startswith("redistribute"):
            proto = v["path"][1] if len(v.get("path", [])) > 1 else v["path"][0].replace("redistribute ", "")
            redistribute.append({
                "protocol": proto,
                "status": prop(v, "status", "disable"),
            })

    is_configured = bool(as_num or neighbors)
    return {
        "status": "configured" if is_configured else "not configured",
        "as": as_num,
        "router_id": router_id,
        "ebgp_multipath": prop(block, "ebgp-multipath", "disable"),
        "neighbors": neighbors,
        "networks": networks,
        "redistribute": redistribute,
    }


def extract_ospf(root: list[dict]) -> dict:
    """Extract OSPF configuration from config router ospf."""
    block = find_config(root, "router ospf")
    if not block.get("properties", {}):
        return {"status": "not configured", "router_id": "", "areas": [],
                "networks": [], "interfaces": [], "redistribute": []}

    router_id = prop(block, "router-id", "")
    default_metric = prop(block, "default-metric", "")

    # ── Areas ──
    area_block = block.get("properties", {}).get("***area", {})
    if not (isinstance(area_block, dict) and area_block.get("kind") == "config"):
        area_block = find_config(root, "router ospf area")
    areas = []
    for name, obj in area_block.get("table", {}).items():
        areas.append({
            "id": name,
            "type": prop(obj, "type", "regular"),
            "authentication": prop(obj, "authentication", ""),
        })

    # ── Networks ──
    net_block = block.get("properties", {}).get("***network", {})
    if not (isinstance(net_block, dict) and net_block.get("kind") == "config"):
        net_block = find_config(root, "router ospf network")
    networks = []
    for name, obj in net_block.get("table", {}).items():
        raw_prefix = prop_list(obj, "prefix")
        prefix = " ".join(raw_prefix) if raw_prefix else ""
        networks.append({
            "seq": name,
            "prefix": prefix,
            "area": prop(obj, "area", ""),
        })

    # ── OSPF Interfaces ──
    iface_block = block.get("properties", {}).get("***ospf-interface", {})
    if not (isinstance(iface_block, dict) and iface_block.get("kind") == "config"):
        iface_block = find_config(root, "router ospf ospf-interface")
    interfaces = []
    for name, obj in iface_block.get("table", {}).items():
        interfaces.append({
            "name": name,
            "interface": prop(obj, "interface", name),
            "network_type": prop(obj, "network-type", ""),
            "cost": prop(obj, "cost", ""),
            "hello_interval": prop(obj, "hello-interval", ""),
            "dead_interval": prop(obj, "dead-interval", ""),
            "passive": prop(obj, "passive", "disable"),
        })

    # ── Redistribution ──
    redistribute = []
    for k, v in block.get("properties", {}).items():
        if isinstance(v, dict) and v.get("kind") == "config" and v.get("path", [""])[0].startswith("redistribute"):
            proto = v["path"][1] if len(v.get("path", [])) > 1 else v["path"][0].replace("redistribute ", "")
            redistribute.append({
                "protocol": proto,
                "status": prop(v, "status", "disable"),
            })

    is_configured = bool(router_id or areas or networks or interfaces)
    return {
        "status": "configured" if is_configured else "not configured",
        "router_id": router_id,
        "default_metric": default_metric,
        "areas": areas,
        "networks": networks,
        "interfaces": interfaces,
        "redistribute": redistribute,
    }
