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

"""Reading what a web API or page answered."""

import html
import http.client
import re
import typing as t
import urllib.request


class Unavailable(RuntimeError):
    """A web endpoint could not be read, or answered in an unknown shape."""


def get(
    url: str, user_agent: str, timeout: float, accept: str = "application/json"
) -> bytes:
    """GET a URL's body.

    Raises:
        Unavailable: on a network error or any status other than 200.
    """
    request = urllib.request.Request(
        url, headers={"user-agent": user_agent, "accept": accept}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            if response.status != 200:
                raise Unavailable(f"{url} answered HTTP {response.status}")
            body: bytes = response.read()
            return body
    except (OSError, http.client.HTTPException) as exc:
        raise Unavailable(f"{url} unreachable ({type(exc).__name__}: {exc})") from exc


def check_json_type(
    doc: dict[str, t.Any],
    field: str,
    kinds: tuple[type, ...],
    error: type[Exception],
    label: str,
) -> None:
    """Check one JSON field's type, bools never passing as numbers.

    Raises:
        Exception: ``error``, when the field is missing or of another type.
    """
    value = doc.get(field, ...)
    if value is ... or (isinstance(value, bool) and bool not in kinds):
        raise error(f"{label} has no usable {field!r}")
    if not isinstance(value, kinds):
        raise error(f"{label} {field!r} is {type(value).__name__}")


def html_text(raw: bytes) -> str:
    """Visible text of an HTML page, whitespace collapsed and lower-cased."""
    text = re.sub(r"<[^>]+>", " ", raw.decode("utf-8", errors="replace"))
    return re.sub(r"\s+", " ", html.unescape(text)).strip().lower()


def page_text(url: str, user_agent: str, timeout: float) -> str:
    """Visible text of a web page, as ``html_text`` reads it.

    Raises:
        Unavailable: when the page cannot be read.
    """
    return html_text(get(url, user_agent, timeout, accept="text/html"))


__all__ = ["Unavailable", "check_json_type", "get", "html_text", "page_text"]
