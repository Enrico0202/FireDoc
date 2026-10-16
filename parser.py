"""
parser.py — FortiOS config tokenizer and recursive parser.
"""

from typing import Any

# ══════════════════════════════════════════════════════════════════════════════
# PARSER
# ══════════════════════════════════════════════════════════════════════════════

def tokenise(line: str) -> list[str]:
 """Split a FortiOS config line into tokens, respecting quoted strings."""
 tokens: list[str] = []
 s = line.strip()
 i = 0
 while i < len(s):
  if s[i] == '"':
   end = s.find('"', i + 1)
   if end == -1:
    tokens.append(s[i + 1:])
    break
   tokens.append(s[i + 1:end])
   i = end + 1
  elif s[i] == ' ':
   i += 1
  else:
   end = s.find(' ', i)
   if end == -1:
    tokens.append(s[i:])
    break
   tokens.append(s[i:end])
   i = end + 1
 return tokens


def parse_config(raw: str) -> list[dict]:
 """
 Parse raw FortiOS config text into a list of ConfigNode dicts.

 Each ConfigNode:
 {
  "kind": "config",
  "path": ["system", "global"],
  "type": "flat" | "table",
  "properties": {"hostname": "FW-01", ...},
  "table": {"1": <ObjectNode>, ...}
 }

 Each ObjectNode:
 {
  "kind": "object",
  "name": "1",
  "properties": {...},
  "children": [<ConfigNode>, ...]
 }
 """
 lines = raw.splitlines()
 idx = [0] # mutable cursor shared across recursive calls

 def parse_config_block() -> dict:
  node: dict[str, Any] = {
   "kind": "config",
   "path": [],
   "type": "flat",
   "properties": {},
   "table": {},
   "_src": lines,
  }
  while idx[0] < len(lines):
   line = lines[idx[0]]
   tokens = tokenise(line)
   lineno = idx[0]
   idx[0] += 1
   if not tokens:
    continue
   kw = tokens[0]
   if kw == "end":
    node["type"] = "table" if node["table"] else "flat"
    if node.get("_line", -1) == -1:
     node["_line"] = lineno
    if node.get("_end", -1) == -1:
     node["_end"] = lineno
    return node
   elif kw == "config":
    if node.get("_line", -1) == -1:
     node["_line"] = lineno
    child = parse_config_block()
    child["_line"] = lineno
    child["path"] = tokens[1:]
    key = "__config_" + "_".join(tokens[1:])
    node["properties"][key] = child
   elif kw == "edit":
    if node.get("_line", -1) == -1:
     node["_line"] = lineno
    name = tokens[1] if len(tokens) > 1 else ""
    obj = parse_object_block(name)
    obj["_line"] = lineno
    node["table"][name] = obj
   elif kw == "set" and len(tokens) >= 3:
    if node.get("_line", -1) == -1:
     node["_line"] = lineno
    key = tokens[1]
    vals = tokens[2:]
    node["properties"][key] = vals[0] if len(vals) == 1 else vals
   elif kw == "unset" and len(tokens) >= 2:
    if node.get("_line", -1) == -1:
     node["_line"] = lineno
    node["properties"].pop(tokens[1], None)
  node["type"] = "table" if node["table"] else "flat"
  if node.get("_line", -1) != -1:
   node["_end"] = max(node.get("_end", -1), idx[0] - 1)
  return node

 def parse_object_block(name: str) -> dict:
  obj: dict[str, Any] = {
   "kind": "object",
   "name": name,
   "properties": {},
   "children": [],
   "_src": lines,
  }
  while idx[0] < len(lines):
   line = lines[idx[0]]
   tokens = tokenise(line)
   lineno = idx[0]
   idx[0] += 1
   if not tokens:
    continue
   kw = tokens[0]
   if kw == "next":
    if obj.get("_line", -1) == -1:
     obj["_line"] = lineno
    obj["_end"] = lineno
    return obj
   elif kw == "config":
    if obj.get("_line", -1) == -1:
     obj["_line"] = lineno
    child = parse_config_block()
    child["_line"] = lineno
    child["path"] = tokens[1:]
    obj["children"].append(child)
   elif kw == "set" and len(tokens) >= 3:
    if obj.get("_line", -1) == -1:
     obj["_line"] = lineno
    key = tokens[1]
    vals = tokens[2:]
    obj["properties"][key] = vals[0] if len(vals) == 1 else vals
   elif kw == "unset" and len(tokens) >= 2:
    if obj.get("_line", -1) == -1:
     obj["_line"] = lineno
    obj["properties"].pop(tokens[1], None)
  return obj

 root: list[dict] = []
 while idx[0] < len(lines):
  line = lines[idx[0]]
  tokens = tokenise(line)
  lineno = idx[0]
  idx[0] += 1
  if not tokens or tokens[0] != "config":
   continue
  node = parse_config_block()
  node["_line"] = lineno
  node["path"] = tokens[1:]
  root.append(node)
 return root


def node_snippet(node: dict, max_lines: int = 25) -> str:
    """Verbatim source text of a parsed node (header through end/next).

    The parser records each node's 0-based source line range as ``_line`` /
    ``_end`` and a reference to the raw line list (``_src``); this slices
    the original text so reports can show the exact config a finding
    points at. Returns '' when the node carries no source position.
    """
    src = node.get("_src") if isinstance(node, dict) else None
    s = node.get("_line", -1) if isinstance(node, dict) else -1
    if not src or s < 0:
        return ""
    e = node.get("_end", -1)
    if e < 0 or e < s:
        e = s
    out = src[s: e + 1]
    if len(out) > max_lines:
        out = out[:max_lines] + ["..."]
    return "\n".join(out)


def find_config_in_obj(obj: dict, target_path: str) -> dict:
    """Find a child config block by path within an object's properties or children."""
    # Search in properties (flat configs like 'set server')
    for key, val in obj.get("properties", {}).items():
        if isinstance(val, dict) and val.get("kind") == "config":
            if " ".join(val.get("path", [])) == target_path:
                return val
            deeper = _find_nested(val, target_path)
            if deeper is not None:
                return deeper
    # Also search in children (nested config blocks from 'config X ... end' inside edit)
    for child in obj.get("children", []):
        if isinstance(child, dict) and child.get("kind") == "config":
            if " ".join(child.get("path", [])) == target_path:
                return child
            deeper = _find_nested(child, target_path)
            if deeper is not None:
                return deeper
    return {"kind": "config", "path": target_path.split(), "type": "table",
            "properties": {}, "table": {}}


def _merge_configs(nodes: list[dict]) -> dict:
    """Merge duplicate ``config <path>`` blocks (FortiOS exports may contain
    the same config block more than once).  Later tables/properties win."""
    out = {"kind": "config", "path": nodes[0].get("path", []),
           "type": "flat", "properties": {}, "table": {}}
    for n in nodes:
        out["properties"].update(n.get("properties", {}))
        out["table"].update(n.get("table", {}))
    # Carry source-position info from the first occurrence so findings can
    # still point at a real config block (the merged view has no single span).
    for n in nodes:
        if n.get("_line", -1) >= 0:
            for k in ("_line", "_end", "_src"):
                if n.get(k) is not None:
                    out[k] = n[k]
            break
    out["type"] = "table" if out["table"] else "flat"
    return out


def find_all_configs(root: list[dict], path_str: str) -> list[dict]:
    """Return *all* ConfigNodes matching the given space-joined path."""
    found = []

    def _walk(node: dict, parent_path: str):
        parent = (parent_path + " " + " ".join(node.get("path", []))).strip()
        if parent == path_str:
            found.append(node)
            return  # matched node's own children cannot re-match the same path
        for key, val in node.get("properties", {}).items():
            if isinstance(val, dict) and val.get("kind") == "config":
                _walk(val, parent)
        for child in node.get("children", []):
            if isinstance(child, dict) and child.get("kind") == "config":
                _walk(child, parent)

    for node in root:
        _walk(node, "")
    return found


def find_config(root: list[dict], path_str: str) -> dict:
    """Return the ConfigNode matching the given space-joined path, or an empty
    stub.  If the export contains the same config block more than once, the
    occurrences are merged (later entries win) so no data is silently lost."""
    found = find_all_configs(root, path_str)
    if found:
        return _merge_configs(found) if len(found) > 1 else found[0]
    return {"kind": "config", "path": path_str.split(), "type": "table",
            "properties": {}, "table": {}}


def _find_nested(node: dict, path_str: str) -> dict | None:
 """Recursively search nested config blocks for a matching path."""
 parent_path = " ".join(node.get("path", []))
 for key, val in node.get("properties", {}).items():
  if isinstance(val, dict) and val.get("kind") == "config":
   child_path = " ".join(val.get("path", []))
   full_path = (parent_path + " " + child_path).strip()
   if full_path == path_str or child_path == path_str:
    return val
   # Recurse deeper
   deeper = _find_nested(val, path_str)
   if deeper is not None:
    return deeper
 return None


def prop(obj: dict, key: str, default: str = "") -> str:
 """Read a scalar property from a node's properties map."""
 v = obj.get("properties", {}).get(key, default)
 if isinstance(v, list):
  return v[0] if v else default
 return str(v) if v is not None else default


def prop_list(obj: dict, key: str) -> list[str]:
 """Read a multi-value property, always returning a list."""
 v = obj.get("properties", {}).get(key)
 if v is None:
  return []
 if isinstance(v, list):
  return [str(x) for x in v]
 return [str(v)]


