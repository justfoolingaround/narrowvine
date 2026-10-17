"""Compiled regular expressions (via the :mod:`regex` package).

Compiling once at import keeps the parsers fast and keeps the patterns in one
place instead of scattering `re.compile` calls.
"""

from __future__ import annotations

import regex

# --- DASH -----------------------------------------------------------------
MPD_PSSH = regex.compile(r"<cenc:pssh[^>]*>([^<]+)</cenc:pssh>")
MPD_DEFAULT_KID = regex.compile(r'cenc:default_KID="([^"]+)"')
MPD_NUMBER = regex.compile(r"\$Number(?:%0(\d+)d)?\$")
MPD_REPRESENTATION = regex.compile(r"<Representation\b[^>]*>")
MPD_ATTRIBUTE = regex.compile(r'([A-Za-z_:][-\w:.]*)="([^"]*)"')

# --- HLS ------------------------------------------------------------------
HLS_MEDIA = regex.compile(r'#EXT-X-MEDIA:[^\n]*URI="([^"]+)"')
HLS_VARIANT = regex.compile(r"#EXT-X-STREAM-INF:[^\n]*\n([^\n#]+)")
HLS_KEY = regex.compile(
    r'#EXT-X-KEY:METHOD=(?P<method>[A-Z0-9-]+),URI="(?P<uri>[^"]+)"'
    r"(?:,IV=0x(?P<iv>[0-9A-Fa-f]+))?"
)

# --- PlayReady ------------------------------------------------------------
PR_KID = regex.compile(r"<KID>([^<]+)</KID>")
PR_LA_URL = regex.compile(r"<LA_URL>([^<]+)</LA_URL>")
PR_PROTECTION_HEADER = regex.compile(r"<ProtectionHeader[^>]*>([^<]+)</ProtectionHeader>")

__all__ = [
    "HLS_KEY",
    "HLS_MEDIA",
    "HLS_VARIANT",
    "MPD_ATTRIBUTE",
    "MPD_DEFAULT_KID",
    "MPD_NUMBER",
    "MPD_PSSH",
    "MPD_REPRESENTATION",
    "PR_KID",
    "PR_LA_URL",
    "PR_PROTECTION_HEADER",
]
