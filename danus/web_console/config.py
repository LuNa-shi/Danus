"""Credential-safe Web Console configuration projections."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from typing import Any, Callable

from danus import codex
from danus.strategy.config import (
    load_claude_api_config,
    load_claude_code_config,
    load_config,
    resolve_transport,
)


def _worker_provider() -> tuple[str | None, str | None]:
    """Return the configured OpenAI-compatible provider URL and key, if any."""
    base_url = os.environ.get("OPENAI_BASE_URL") or os.environ.get("CODEX_API_BASE_URL")
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("DANUS_CODEX_API_KEY")
    return base_url, api_key


def _models_url(base_url: str) -> str:
    trimmed = base_url.rstrip("/")
    return trimmed if trimmed.endswith("/models") else f"{trimmed}/models"


def _selectable_worker_model(model_id: str) -> bool:
    lowered = model_id.lower()
    blocked = ("embedding", "moderation", "whisper", "tts", "audio", "image", "dall")
    return not any(token in lowered for token in blocked)


def _model_rows(payload: Any) -> list[dict[str, Any]]:
    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    rows: list[dict[str, Any]] = []
    if not isinstance(data, list):
        return rows
    for item in data:
        if isinstance(item, str):
            model_id = item
            source: dict[str, Any] = {}
        elif isinstance(item, dict):
            raw = item.get("id")
            if not isinstance(raw, str):
                continue
            model_id = raw
            source = item
        else:
            continue
        rows.append({
            "id": model_id,
            "selectable": _selectable_worker_model(model_id),
            "owned_by": source.get("owned_by") if isinstance(source.get("owned_by"), str) else None,
        })
    return rows


class ProviderModelCatalog:
    """Small in-memory cache for the configured OpenAI-compatible /models list."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 300.0,
        timeout_seconds: float = 5.0,
        opener: Callable[..., Any] | None = None,
        now: Callable[[], float] | None = None,
    ):
        self.ttl_seconds = ttl_seconds
        self.timeout_seconds = timeout_seconds
        self._opener = opener or urllib.request.urlopen
        self._now = now or time.time
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}

    @staticmethod
    def _with_default(rows: list[dict[str, Any]], default_worker_model: str) -> list[dict[str, Any]]:
        if default_worker_model and all(row.get("id") != default_worker_model for row in rows):
            return [{"id": default_worker_model, "selectable": True, "owned_by": None, "source": "configured_default"}, *rows]
        return rows

    def snapshot(self, *, default_worker_model: str | None = None) -> dict[str, Any]:
        default_model = default_worker_model or codex.model()
        base_url, api_key = _worker_provider()
        provider = {
            "type": "openai_compatible",
            "models_endpoint_configured": bool(base_url),
            "credential_configured": bool(api_key),
            "cache_ttl_seconds": self.ttl_seconds,
        }
        if not base_url:
            models = self._with_default([], default_model)
            return {"models": models, "provider": provider, "cached": False, "stale": False, "fetched_at": None}

        cache_key = f"{base_url.rstrip('/')}|credential:{bool(api_key)}"
        now = self._now()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and now - cached[0] < self.ttl_seconds:
                snapshot = dict(cached[1])
                snapshot.update({"cached": True, "stale": False})
                return snapshot

        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        request = urllib.request.Request(_models_url(base_url), headers=headers)
        try:
            with self._opener(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
            models = self._with_default(_model_rows(payload), default_model)
            fresh = {
                "models": models,
                "provider": {**provider, "models_endpoint_configured": True},
                "cached": False,
                "stale": False,
                "fetched_at": now,
            }
            with self._lock:
                self._cache[cache_key] = (now, fresh)
            return fresh
        except Exception as exc:
            with self._lock:
                cached = self._cache.get(cache_key)
            if cached:
                snapshot = dict(cached[1])
                snapshot.update({"cached": True, "stale": True, "error": exc.__class__.__name__})
                return snapshot
            return {
                "models": self._with_default([], default_model),
                "provider": provider,
                "cached": False,
                "stale": False,
                "fetched_at": None,
                "error": exc.__class__.__name__,
            }


def main_agent_metadata(main_agent: Any) -> dict[str, Any]:
    backend = getattr(main_agent, "backend", "codex")
    model = getattr(main_agent, "model", None)
    if backend == "codex" and not model:
        model = os.environ.get("DANUS_CODEX_MODEL") or os.environ.get("CODEX_API_MODEL")
    return {
        "backend": backend,
        "model": model,
        "effort": getattr(main_agent, "effort", None) or os.environ.get("DANUS_CODEX_EFFORT"),
        "provider_configured": bool(_worker_provider()[0]),
    }


def strategy_metadata() -> dict[str, Any]:
    transport = resolve_transport(None)
    if transport == "gpt_pro":
        cfg = load_config()
        return {
            "transport": transport,
            "model": cfg.model,
            "api_key_configured": cfg.has_key,
            "base_url_configured": bool(cfg.base_url),
            "background": cfg.background,
            "store": cfg.store,
        }
    if transport == "claude_api":
        cfg = load_claude_api_config()
        return {
            "transport": transport,
            "model": cfg.model,
            "api_key_configured": cfg.has_key,
            "base_url_configured": bool(cfg.base_url),
            "fallback_model": cfg.fallback_model,
        }
    if transport == "claude_code":
        cfg = load_claude_code_config()
        return {
            "transport": transport,
            "model": cfg.model,
            "api_key_configured": False,
            "subscription_backend": True,
        }
    return {"transport": "off", "model": None, "api_key_configured": False}
