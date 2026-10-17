"""HTTP helpers.

The Bitmovin CDN sits behind Cloudflare and blocks datacenter IPv6 addresses and
non-browser user agents, so every request forces IPv4 and sends browser headers.
"""

from __future__ import annotations

import socket

import requests
import urllib3.util.connection as _connection

_connection.allowed_gai_family = lambda: socket.AF_INET

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    ),
    "Referer": "https://bitmovin.com/",
    "Accept": "*/*",
}


def get(url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", 60)
    response = requests.get(url, headers=BROWSER_HEADERS, **kwargs)
    response.raise_for_status()
    return response


def post_octet(
    url: str, data: bytes, headers: dict[str, str] | None = None
) -> requests.Response:
    merged = {**BROWSER_HEADERS, "Content-Type": "application/octet-stream", **(headers or {})}
    response = requests.post(url, data=data, headers=merged, timeout=60)
    response.raise_for_status()
    return response
