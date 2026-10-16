"""
yaml_config.py — FortiGate YAML export → FortiOS text config.

FortiGate's GUI can export a device as a YAML file (extension ".conf.yaml").
This module converts that YAML back into plain FortiOS CLI text so the existing
parse_config() / extractor pipeline can process it unchanged.

Mapping rules (verified against real FortiGate exports):
  * top-level YAML key  ->  config path (split on "_"); FortiOS type tokens
    never contain underscores, so "system_interface" -> "system interface",
    "wireless-controller_wids-profile" -> "wireless-controller wids-profile".
  * key value is a dict   ->  flat config block (properties only)
  * key value is a list   ->  table config block; each item is {name: {props}}
  * key value is None     ->  section omitted (empty in the export)
  * a value that is itself a dict inside an object -> nested "config" sub-block
  * a value that is a list of scalars               -> "set key v1 v2 ..."
  * a value that is [ENC, base64...]                -> "set key [ENC, ...]"

The only YAML fixup needed: FortiGate leaks a C-style \' (backslash-apostrophe)
into double-quoted scalars, which is not a valid YAML escape. PyYAML rejects it;
we normalise it to a bare apostrophe before loading.
"""

import yaml


def load_forti_yaml(raw: str) -> dict:
    """Load a FortiGate YAML export into a Python dict.

    Fixes the \' leak FortiGate introduces, which PyYAML cannot parse.
    """
    text = raw.replace("\\'", "'")
    return yaml.safe_load(text)


def detect_format(raw: bytes) -> str:
    """Classify an uploaded config blob.

    Returns one of:
      "conf"      plain FortiOS CLI text  (first real line is ``config ...``)
      "yaml"      FortiGate YAML export  (first real line is a ``key:`` mapping)
      "encrypted" FortiGate encrypted backup (``#FGBK`` header or non-UTF-8 bytes)
      "unknown"   anything else
    """
    # Encrypted FortiGate backups carry a #FGBK magic header.
    if raw[:5] == b"#FGBK":
        return "encrypted"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Binary payload we cannot text-parse -> treat as encrypted/unsupported.
        return "encrypted"
    # Skip leading comment lines; the first real line decides the format.
    first_real = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        first_real = line
        break
    if first_real is None:
        return "unknown"
    if first_real.startswith("config "):
        return "conf"
    # A top-level YAML mapping line like ``system_global:`` (key with a colon,
    # no value, before any indentation) identifies the YAML export format.
    if first_real.endswith(":") and " " not in first_real:
        return "yaml"
    return "unknown"


def _quote(name: str) -> str:
    """Quote a CLI token only when it contains a space."""
    return f'"{name}"' if " " in name else name


def _fmt_val(v) -> str:
    """Render a single set-value: scalar, or inline [a, b, c] list."""
    if isinstance(v, list):
        return "[" + ", ".join(_scalar(x) for x in v) + "]"
    return _scalar(v)


def _scalar(v) -> str:
    if v is None:
        return "none"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _render_block(obj: dict, indent: str, out: list[str]) -> None:
    """Render the property/sub-config contents of one node (object or section)."""
    for key, val in obj.items():
        if isinstance(val, dict):
            # nested config sub-block
            sub = key.split("_")
            out.append(f"{indent}config {' '.join(sub)}")
            _render_block(val, indent + "    ", out)
            out.append(f"{indent}end")
        elif isinstance(val, list):
            out.append(f"{indent}set {key} {_fmt_val(val)}")
        else:
            out.append(f"{indent}set {key} {_scalar(val)}")


def yaml_to_conf(doc: dict) -> str:
    """Convert a loaded FortiGate YAML dict into FortiOS text config."""
    out: list[str] = []
    for key, val in doc.items():
        if val is None:
            # Empty section in the export — nothing to emit.
            continue
        path = key.split("_")
        if isinstance(val, dict):
            out.append(f"config {' '.join(path)}")
            _render_block(val, "    ", out)
            out.append("end")
        elif isinstance(val, list):
            out.append(f"config {' '.join(path)}")
            for item in val:
                if not isinstance(item, dict) or len(item) != 1:
                    # Malformed object (expected {name: {props}}) — skip it.
                    continue
                name = next(iter(item))
                props = item[name]
                out.append(f"    edit {_quote(str(name))}")
                if isinstance(props, dict):
                    _render_block(props, "        ", out)
                out.append("    next")
            out.append("end")
    return "\n".join(out) + "\n"


def yaml_raw_to_conf(raw: str) -> str:
    """One-step: FortiGate YAML text -> FortiOS text config."""
    return yaml_to_conf(load_forti_yaml(raw))
