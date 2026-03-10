from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    github_token: str
    webhook_secret: str
    base_url: str = "https://api.github.com"


def load_settings() -> Settings:
    github_token    = os.getenv("GITHUB_TOKEN", "").strip()
    webhook_secret  = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()
    base_url        = os.getenv("GITHUB_API_BASE_URL", "https://api.github.com").strip()

    missing = [name for name, val in [
        ("GITHUB_TOKEN", github_token),
        ("GITHUB_WEBHOOK_SECRET", webhook_secret),
    ] if not val]

    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    return Settings(
        github_token=github_token,
        webhook_secret=webhook_secret,
        base_url=base_url,
    )
