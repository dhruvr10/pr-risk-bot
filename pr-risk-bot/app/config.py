import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    github_token: str
    webhook_secret: str
    base_url: str = "https://api.github.com"

def load_settings() -> Settings:
    github_token = os.getenv("GITHUB_TOKEN", "").strip()
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()
    if not github_token:
        raise RuntimeError("Missing GITHUB_TOKEN")
    if not webhook_secret:
        raise RuntimeError("Missing GITHUB_WEBHOOK_SECRET")
    return Settings(github_token=github_token, webhook_secret=webhook_secret)
