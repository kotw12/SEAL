"""Minimal OpenAI-compatible chat client (stdlib only).

Shared by the independent judge and the (optional) LLM orchestrator/mutator, so
each role can point at its own model via one plain HTTP call. Works against
OpenRouter directly or a LiteLLM proxy.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request


def _key(explicit: str | None = None) -> str:
    return (explicit or os.environ.get("SEAL_JUDGE_API_KEY", "")
            or os.environ.get("LITELLM_MASTER_KEY", "")
            or os.environ.get("OPENROUTER_API_KEY", ""))


def chat(*, model: str, system: str, user: str,
         url: str | None = None, api_key: str | None = None,
         timeout: int = 60, temperature: float = 0.0) -> str:
    """One chat completion; returns the assistant message text. Raises on error."""
    endpoint = (url or os.environ.get("SEAL_JUDGE_URL", "http://localhost:4000/v1")).rstrip("/")
    body = json.dumps({
        "model": model, "temperature": temperature,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
    }).encode("utf-8")
    req = urllib.request.Request(
        endpoint + "/chat/completions", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {_key(api_key)}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode("utf-8", "ignore"))
    return d["choices"][0]["message"]["content"]


def chat_json(**kwargs) -> dict:
    """chat() but parse the first JSON object out of the reply."""
    text = chat(**kwargs)
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object in LLM reply")
    return json.loads(m.group(0))
