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

"""What a mech request is, as its metadata and its replay fingerprint see it."""

import hashlib
import json
import uuid

from connect.mech_types import MechError


def canonical_context(request_context: dict | None) -> str:
    """Encode a context as the stamp, the metadata and the trail all read it.

    Sorted, so the fingerprint does not turn key order into a new question —
    which also refuses the mixed-type keys ``sorted()`` chokes on, before a
    payment rather than while logging the delivery it bought.
    """
    try:
        return json.dumps(request_context, sort_keys=True)
    except (TypeError, ValueError) as e:
        raise MechError(f"request_context could not be encoded: {e}") from e


def metadata_extras(request_context: dict | None) -> dict:
    """Build the metadata extras mech-client merges over prompt/tool/nonce."""
    extras: dict = {"nonce": str(uuid.uuid4())}
    if request_context is not None:
        extras["request_context"] = request_context
    return extras


def request_stamp(
    prompt: str,
    tool: str,
    *,
    chain: str,
    priority_mech: str | None,
    legacy_on_chain: bool,
    request_context: dict | None,
) -> str:
    """Fingerprint what a request asked.

    A ledger keyed on the caller's id alone would answer a new question with
    an old answer if that id were reused — and the caller acts on the answer,
    so the mistake would be silent and expensive.
    """
    context = canonical_context(request_context)
    raw = "\x1f".join(
        (
            prompt,
            tool,
            chain.lower(),
            (priority_mech or "").lower(),
            str(legacy_on_chain),
            context,
        )
    )
    return hashlib.sha256(raw.encode()).hexdigest()
