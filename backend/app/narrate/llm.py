"""Local LLM abstraction layer.

Swappable provider (Ollama by default; the interface is provider-agnostic so a
different backend can be dropped in). Narratives are EXPLANATIONS over supplied
evidence — never free generation. See grounding.py for the anti-hallucination
guard that enforces this.
"""
from __future__ import annotations

import abc

import httpx

from app.config import settings


class LLMProvider(abc.ABC):
    @abc.abstractmethod
    def generate(self, system: str, prompt: str) -> str: ...


class OllamaProvider(LLMProvider):
    def __init__(self, url: str | None = None, model: str | None = None):
        self.url = (url or settings.ollama_url).rstrip("/")
        self.model = model or settings.ollama_model

    def generate(self, system: str, prompt: str) -> str:
        resp = httpx.post(
            f"{self.url}/api/generate",
            json={
                "model": self.model,
                "system": system,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2},   # low temp = less invention
            },
            timeout=settings.ollama_timeout,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()


class EchoProvider(LLMProvider):
    """Deterministic fallback used when no LLM is reachable (and in tests).
    Produces a templated, fully-grounded narrative from the evidence."""

    def generate(self, system: str, prompt: str) -> str:
        return prompt  # the prompt already contains the structured evidence summary


_provider: LLMProvider | None = None


def get_provider() -> LLMProvider:
    global _provider
    if _provider is None:
        _provider = OllamaProvider()
    return _provider


def set_provider(provider: LLMProvider) -> None:
    global _provider
    _provider = provider
