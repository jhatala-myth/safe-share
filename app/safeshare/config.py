"""Runtime configuration, read from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _int_list(name: str, default: str) -> list[int]:
    raw = os.environ.get(name, default)
    return sorted({int(x) for x in raw.split(",") if x.strip()})


@dataclass(frozen=True)
class Settings:
    redis_url: str = field(default_factory=lambda: os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    # Allowed TTL values in seconds (the UI offers exactly these).
    ttl_options: list[int] = field(
        default_factory=lambda: _int_list("TTL_OPTIONS", "300,3600,86400,259200,604800")
    )
    default_ttl: int = field(default_factory=lambda: _int("DEFAULT_TTL", 86400))
    # Max length of the base64url ciphertext accepted by the API (characters).
    # ~2.5M chars ≈ 1 MiB file after JSON+base64 wrapping and encryption.
    max_ciphertext_chars: int = field(default_factory=lambda: _int("MAX_CIPHERTEXT_CHARS", 2_500_000))
    # Max plaintext size enforced in the browser / CLI (bytes).
    max_plaintext_bytes: int = field(default_factory=lambda: _int("MAX_PLAINTEXT_BYTES", 1_048_576))
    key_prefix: str = field(default_factory=lambda: os.environ.get("REDIS_KEY_PREFIX", "safeshare:secret:"))


settings = Settings()
