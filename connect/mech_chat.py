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

"""Chat tools over mech_request: messages in, completion and usage out.

The contract agreed with the mechs team: the prompt is an OpenAI-style
`messages` list as JSON, and the delivery carries the completion text plus
token usage. The parse order is pmini's `MechModel`'s: the delivery itself,
then a `response` or `result` field, then `content`, `text` or `completion`
(or an OpenAI `choices[0].message`). A native tool call the model returns
unrequested comes back as a fenced bash block in the completion, not dropped.
"""

import json
import typing as t

Usage = dict[str, int]


def is_chat_prompt(prompt: str) -> bool:
    """Whether the prompt is a JSON list of {role, content} messages."""
    try:
        messages = json.loads(prompt)
    except ValueError:
        return False
    return (
        isinstance(messages, list)
        and bool(messages)
        and all(isinstance(m, dict) and "role" in m for m in messages)
    )


def _parse(value: t.Any) -> t.Any:
    """Decode a JSON string, leaving anything else as it is."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _message(data: t.Any) -> t.Any:
    """Descend to the completion: response/result, then OpenAI choices."""
    data = _parse(data)
    for key in ("response", "result"):
        if isinstance(data, dict) and key in data:
            data = _parse(data[key])
            break
    if isinstance(data, dict) and isinstance(data.get("choices"), list):
        choices = data["choices"]
        first = choices[0] if choices else None
        message = first.get("message") if isinstance(first, dict) else None
        if isinstance(message, dict):  # an untrusted delivery: any shape
            return {**data, **message}
    return data


def _tool_call_block(call: t.Any) -> str:
    """Render one native tool call as a fenced bash block."""
    function = call.get("function") if isinstance(call, dict) else None
    function = function if isinstance(function, dict) else {}
    arguments = _parse(function.get("arguments", ""))
    if isinstance(arguments, dict) and isinstance(arguments.get("command"), str):
        body = arguments["command"]
    else:
        name = str(function.get("name") or "tool")
        body = f"{name} {json.dumps(arguments) if not isinstance(arguments, str) else arguments}"
    return f"```bash\n{body.strip()}\n```"


def chat_report(delivery: t.Any) -> dict | None:
    """Return {completion, usage} for a chat delivery, or None if it has neither."""
    message = _message(delivery)
    if isinstance(message, str):
        return {"completion": message, "usage": {}}
    if not isinstance(message, dict):
        return None
    text = next(
        (
            message[key]
            for key in ("content", "text", "completion")
            if isinstance(message.get(key), str)
        ),
        None,
    )
    calls = message.get("tool_calls")
    blocks = [_tool_call_block(c) for c in calls] if isinstance(calls, list) else []
    if text is None and not blocks:
        return None
    completion = "\n\n".join([p for p in [text or ""] if p] + blocks)
    usage = message.get("usage")
    return {
        "completion": completion,
        "usage": {
            key: int(usage[key])
            for key in ("prompt_tokens", "completion_tokens")
            if isinstance(usage, dict) and isinstance(usage.get(key), int)
        },
    }
