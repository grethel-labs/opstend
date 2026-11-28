"""Language of texts the server writes (job effects, insights, Zorec rules).

The API sets the language per request from the user's preference. Every
human-facing server text goes through `t(en, de)` so the UI never mixes
languages.
"""

from __future__ import annotations

from contextvars import ContextVar

LANGUAGES = ("de", "en")
current: ContextVar[str] = ContextVar("opstend_lang", default="de")


def t(en: str, de: str) -> str:
    return de if current.get() == "de" else en


def pick(accept_language: str | None, preferred: str | None = None) -> str:
    if preferred in LANGUAGES:
        return preferred
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in LANGUAGES:
            return code
    return "de"
