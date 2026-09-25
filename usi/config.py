"""Config loading: env vars take priority over config.toml, which takes
priority over the built-in defaults below. Nothing here ever embeds a
real secret - config.toml is user-edited locally and gitignored;
config.example.toml (committed) has every value blank/disabled."""
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.toml"

_ENV_KEYS = {
    "safe_browsing": "USI_SAFE_BROWSING_API_KEY",
    "virustotal": "USI_VIRUSTOTAL_API_KEY",
    "urlscan": "USI_URLSCAN_API_KEY",
    "abuseipdb": "USI_ABUSEIPDB_API_KEY",
}


@dataclass
class ReputationConfig:
    enabled: bool = False
    api_key: str = ""


@dataclass
class Config:
    reputation_enabled: bool = False
    reputation: "dict[str, ReputationConfig]" = field(default_factory=dict)
    tor_enabled: bool = False
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    cache_ttl_hours: int = 24
    cache_path: str = str(PROJECT_ROOT / "cache" / "usi_cache.sqlite3")
    fetch_timeout_seconds: int = 20
    fetch_max_bytes: int = 2_097_152
    fetch_user_agent: str = "url-safety-investigator/0.1 (local research tool)"


def load_config(path: "Path | None" = None) -> Config:
    path = path or DEFAULT_CONFIG_PATH
    raw: dict = {}
    if path.exists():
        with open(path, "rb") as f:
            raw = tomllib.load(f)

    cfg = Config()
    rep_section = raw.get("reputation", {})
    cfg.reputation_enabled = bool(rep_section.get("enabled", False))
    for name, env_key in _ENV_KEYS.items():
        section = rep_section.get(name, {})
        api_key = os.environ.get(env_key) or section.get("api_key", "")
        enabled = bool(section.get("enabled", False)) or bool(os.environ.get(env_key))
        cfg.reputation[name] = ReputationConfig(enabled=enabled, api_key=api_key)

    tor_section = raw.get("tor", {})
    cfg.tor_enabled = bool(tor_section.get("enabled", False))
    cfg.tor_proxy = tor_section.get("proxy", cfg.tor_proxy)

    cache_section = raw.get("cache", {})
    cfg.cache_ttl_hours = int(cache_section.get("ttl_hours", cfg.cache_ttl_hours))
    # A relative cache path resolves against the project directory, not the
    # caller's working directory - otherwise running the tool from anywhere
    # else would silently create a second, separate cache there.
    cache_path = Path(cache_section.get("path", cfg.cache_path))
    cfg.cache_path = str(cache_path if cache_path.is_absolute() else PROJECT_ROOT / cache_path)

    fetch_section = raw.get("fetch", {})
    cfg.fetch_timeout_seconds = int(fetch_section.get("timeout_seconds", cfg.fetch_timeout_seconds))
    cfg.fetch_max_bytes = int(fetch_section.get("max_bytes", cfg.fetch_max_bytes))
    cfg.fetch_user_agent = fetch_section.get("user_agent", cfg.fetch_user_agent)

    return cfg
