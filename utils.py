"""
utils.py — Shared helpers used across FortiDoc modules.
"""

import re


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


def js_name(name: str) -> str:
 """Return HTML-safe version of name for data-obj-name attribute."""
 return html_escape(str(name))

