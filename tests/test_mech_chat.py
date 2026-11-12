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

"""Chat tools over mech_request."""

import json

from connect.mech_chat import chat_report, is_chat_prompt


def test_a_chat_prompt_is_a_json_list_of_messages() -> None:
    """Only a non-empty list of {role, ...} messages is a chat."""
    assert is_chat_prompt(json.dumps([{"role": "user", "content": "hi"}]))
    assert not is_chat_prompt("Will it rain?")
    assert not is_chat_prompt("[]")
    assert not is_chat_prompt(json.dumps([{"content": "no role"}]))
    assert not is_chat_prompt(json.dumps({"role": "user"}))


def test_the_completion_is_found_in_pminis_order() -> None:
    """The delivery itself, response/result, then content/text/completion."""
    assert chat_report("plain words") == {"completion": "plain words", "usage": {}}
    assert chat_report({"text": "a"}) == {"completion": "a", "usage": {}}
    assert chat_report({"response": {"completion": "b"}}) == {
        "completion": "b",
        "usage": {},
    }
    nested = {
        "result": json.dumps(
            {
                "choices": [{"message": {"content": "c"}}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 2, "x": "y"},
            }
        )
    }
    assert chat_report(nested) == {
        "completion": "c",
        "usage": {"prompt_tokens": 4, "completion_tokens": 2},
    }
    assert chat_report(json.dumps({"result": "d"})) == {"completion": "d", "usage": {}}


def test_an_unrequested_tool_call_comes_back_as_a_bash_block() -> None:
    """Not dropped: the command, or the call itself, in a fenced bash block."""
    report = chat_report(
        {
            "content": "Running it",
            "tool_calls": [
                {
                    "function": {
                        "name": "bash",
                        "arguments": json.dumps({"command": " ls "}),
                    }
                },
                {"function": {"name": "search", "arguments": {"q": "x"}}},
                {"function": {"name": "raw", "arguments": "--flag"}},
                "not a call",
            ],
        }
    )
    assert report is not None
    assert report["completion"] == (
        'Running it\n\n```bash\nls\n```\n\n```bash\nsearch {"q": "x"}\n```'
        "\n\n```bash\nraw --flag\n```\n\n```bash\ntool\n```"
    )
    only_call = chat_report(
        {"choices": [{"message": {"tool_calls": [{"function": {"name": "t"}}]}}]}
    )
    assert only_call == {"completion": "```bash\nt\n```", "usage": {}}


def test_a_delivery_without_a_completion_is_not_a_chat_report() -> None:
    """Nothing to report rather than a guess."""
    assert chat_report({"answer": "42"}) is None
    assert chat_report([1, 2]) is None
    assert chat_report({"choices": []}) is None


def test_a_malformed_choice_from_an_untrusted_delivery_is_no_crash() -> None:
    """A delivery is the mech's to shape: a string message or choice reports nothing."""
    assert chat_report({"choices": [{"message": "hi"}]}) is None
    assert chat_report({"choices": ["hi"]}) is None
