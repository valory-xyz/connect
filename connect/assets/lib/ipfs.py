# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

"""Check an ipfs:// URI resolves to a PNG, JPEG or WebP image."""

import http.client
import re
import typing as t
import urllib.request

import evm

IMAGE_MAX_BYTES = 5 * 1024 * 1024
TIMEOUT_S = 30
GATEWAYS = (
    "https://gateway.pinata.cloud/ipfs/",
    "https://ipfs.filebase.io/ipfs/",
    "https://ipfs.io/ipfs/",
    "https://dweb.link/ipfs/",
)
IPFS_URI = re.compile(r"^ipfs://([A-Za-z0-9]{46,100})(/[A-Za-z0-9._~-]+)*$")
IMAGE_TYPES = ("image/png", "image/jpeg", "image/webp")
JPEG_SOF = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}


def image_type(body: bytes) -> t.Optional[str]:
    """Return the accepted image type the magic bytes name, if any."""
    if body.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if body.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if body[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "image/webp"
    return None


def _jpeg_size(body: bytes) -> t.Optional[tuple[int, int]]:
    """Width and height from a JPEG's first start-of-frame segment."""
    i = 2
    while i + 9 <= len(body) and body[i] == 0xFF:
        marker = body[i + 1]
        if marker in JPEG_SOF:
            height = int.from_bytes(body[i + 5 : i + 7], "big")
            return int.from_bytes(body[i + 7 : i + 9], "big"), height
        i += 2 + int.from_bytes(body[i + 2 : i + 4], "big")
    return None


def _webp_size(body: bytes) -> t.Optional[tuple[int, int]]:
    """Width and height from a WebP's first chunk."""
    chunk = body[12:16]
    if chunk == b"VP8X" and len(body) >= 30:
        return (
            1 + int.from_bytes(body[24:27], "little"),
            1 + int.from_bytes(body[27:30], "little"),
        )
    if chunk == b"VP8 " and len(body) >= 30:
        return (
            int.from_bytes(body[26:28], "little") & 0x3FFF,
            int.from_bytes(body[28:30], "little") & 0x3FFF,
        )
    if chunk == b"VP8L" and len(body) >= 25:
        bits = int.from_bytes(body[21:25], "little")
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    return None


def image_size(kind: str, body: bytes) -> t.Optional[tuple[int, int]]:
    """Width and height read from the image's own header, when it is simple."""
    if kind == "image/png":
        if body[12:16] != b"IHDR":
            return None
        return int.from_bytes(body[16:20], "big"), int.from_bytes(body[20:24], "big")
    if kind == "image/jpeg":
        return _jpeg_size(body)
    return _webp_size(body)


def _fetch(url: str, user_agent: str) -> tuple[str, t.Optional[int], bytes]:
    """GET at most the image size limit, with the declared type and length."""
    request = urllib.request.Request(url, headers={"user-agent": user_agent})
    with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:  # nosec B310
        length = response.headers.get("content-length")
        declared = int(length) if length and length.isdigit() else None
        if declared is not None and declared >= IMAGE_MAX_BYTES:
            return response.headers.get_content_type(), declared, b""
        return (
            response.headers.get_content_type(),
            declared,
            response.read(IMAGE_MAX_BYTES),
        )


def check_image(uri: str, user_agent: str) -> dict[str, t.Any]:
    """Resolve an ipfs:// image through public gateways and check it is usable.

    Raises:
        SwapError: for a malformed URI, a file no gateway serves, or one
            that is not a PNG, JPEG or WebP under 5 MB.
    """
    match = IPFS_URI.match(uri)
    if match is None:
        raise evm.SwapError(
            f"{uri!r} is not an ipfs:// URI; upload the image to IPFS first"
        )
    path = uri[len("ipfs://") :]
    failures = []
    for gateway in GATEWAYS:
        url = gateway + path
        try:
            header_type, declared, body = _fetch(url, user_agent)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            failures.append(f"{gateway}: {type(exc).__name__}: {exc}")
            continue
        kind = image_type(body)
        size = declared if not body and declared else len(body)
        if size >= IMAGE_MAX_BYTES and (kind or header_type in IMAGE_TYPES):
            raise evm.SwapError(f"the image is {size} bytes; it must be under 5 MB")
        if kind is not None and header_type == kind:
            break
        failures.append(
            f"{gateway}: served {header_type} that looks like "
            f"{kind or 'something else'}"
        )
    else:
        raise evm.SwapError(
            f"no gateway served {uri} as a PNG, JPEG or WebP; is it pinned, and "
            f"is it one? ({'; '.join(failures)})"
        )
    dimensions = image_size(kind, body)
    return {
        "uri": uri,
        "url": url,
        "content_type": kind,
        "bytes": size,
        "width": dimensions[0] if dimensions else None,
        "height": dimensions[1] if dimensions else None,
        "square": None if dimensions is None else dimensions[0] == dimensions[1],
    }


__all__ = ["GATEWAYS", "IMAGE_MAX_BYTES", "check_image", "image_size", "image_type"]
