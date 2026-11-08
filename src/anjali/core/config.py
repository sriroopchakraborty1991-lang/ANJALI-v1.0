"""Configuration + BYOK credential resolution.

Security posture
----------------
* Keys are read from, in order: explicit CLI/env override, ``ANJALI_HOME/keys.toml``
  (mode 0600), process environment, then ``.env`` in the working directory.
* Keys are **never** written to the audit trail, logs, or ``--json`` output. The
  ``redact`` helper is applied by every renderer as a second line of defence.
* ``anjali doctor`` reports *presence* of a key, never its value or length.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from anjali.core.errors import ConfigError
from anjali.core.util import atomic_write, read_json, slug, write_json

DEFAULT_HOME = Path(os.environ.get("ANJALI_HOME", Path.home() / ".anjali"))

PROVIDER_ENV = {
    "openai": ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
    "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
    "groq": ("GROQ_API_KEY", "GROQ_BASE_URL"),
    "mistral": ("MISTRAL_API_KEY", "MISTRAL_BASE_URL"),
    "ollama": ("OLLAMA_HOST", None),
    "openrouter": ("OPENROUTER_API_KEY", "OPENROUTER_BASE_URL"),
    "offline": (None, None),
}

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-5",
    "groq": "llama-3.3-70b-versatile",
    "mistral": "mistral-large-latest",
    "ollama": "llama3.1:8b",
    "openrouter": "anthropic/claude-sonnet-4.5",
    "offline": "anjali-offline-analyst",
}

DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "mistral": "https://api.mistral.ai/v1",
    "ollama": "http://localhost:11434",
    "openrouter": "https://openrouter.ai/api/v1",
}

EMBEDDING_MODELS = {
    "openai": "text-embedding-3-small",
    "mistral": "mistral-embed",
    "ollama": "nomic-embed-text",
}


@dataclass
class ProviderConfig:
    name: str = "offline"
    model: str = DEFAULT_MODELS["offline"]
    base_url: str | None = None
    api_key: str | None = None
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout_s: float = 120.0
    max_retries: int = 2

    @property
    def is_offline(self) -> bool:
        return self.name == "offline"


@dataclass
class RagConfig:
    top_k: int = 8
    candidate_k: int = 40
    embedder: Literal["local", "api"] = "local"
    hybrid: bool = True
    mmr_lambda: float = 0.72
    min_score: float = 0.005
    as_of: str | None = None  # ISO date; defaults to today


@dataclass
class RiskConfig:
    weights: dict[str, float] = field(
        default_factory=lambda: {
            "geographic": 0.22,
            "product": 0.16,
            "customer": 0.18,
            "behavioral": 0.30,
            "channel": 0.14,
        }
    )
    band_cutoffs: dict[str, float] = field(
        default_factory=lambda: {"critical": 80, "high": 60, "medium": 35}
    )


@dataclass
class Settings:
    home: Path = DEFAULT_HOME
    provider: ProviderConfig = field(default_factory=ProviderConfig)
    rag: RagConfig = field(default_factory=RagConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    default_jurisdictions: list[str] = field(default_factory=lambda: ["US", "EU", "UK", "FATF"])
    require_citations: bool = True
    max_agent_steps: int = 8
    audit_enabled: bool = True

    # ---- paths ---------------------------------------------------------- #
    @property
    def config_file(self) -> Path:
        return self.home / "config.json"

    @property
    def keys_file(self) -> Path:
        return self.home / "keys.toml"

    @property
    def db_path(self) -> Path:
        return self.home / "anjali.db"

    @property
    def audit_path(self) -> Path:
        return self.home / "audit.jsonl"

    @property
    def cache_dir(self) -> Path:
        return self.home / "cache"

    def ensure_home(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ---- persistence ---------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": {
                "name": self.provider.name,
                "model": self.provider.model,
                "base_url": self.provider.base_url,
                "temperature": self.provider.temperature,
                "max_tokens": self.provider.max_tokens,
            },
            "rag": {
                "top_k": self.rag.top_k,
                "candidate_k": self.rag.candidate_k,
                "embedder": self.rag.embedder,
                "hybrid": self.rag.hybrid,
                "mmr_lambda": self.rag.mmr_lambda,
                "as_of": self.rag.as_of,
            },
            "risk": {"weights": self.risk.weights, "band_cutoffs": self.risk.band_cutoffs},
            "default_jurisdictions": self.default_jurisdictions,
            "require_citations": self.require_citations,
            "max_agent_steps": self.max_agent_steps,
            "audit_enabled": self.audit_enabled,
        }

    def save(self) -> None:
        self.ensure_home()
        write_json(self.config_file, self.to_dict())


def _load_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip("'\"")
    return out


def load_credentials(home: Path | None = None) -> dict[str, dict[str, str]]:
    """Return ``{provider: {"api_key": ..., "base_url": ...}}`` without any logging."""
    home = home or DEFAULT_HOME
    creds: dict[str, dict[str, str]] = {}
    keys_file = home / "keys.toml"
    if keys_file.exists():
        try:
            data = tomllib.loads(keys_file.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            data = {}
        for provider, values in data.items():
            if isinstance(values, dict):
                creds[provider] = {k: str(v) for k, v in values.items()}

    env_file = _load_env_file(Path.cwd() / ".env")
    for provider, (key_env, url_env) in PROVIDER_ENV.items():
        entry = creds.setdefault(provider, {})
        if key_env and not entry.get("api_key"):
            val = os.environ.get(key_env) or env_file.get(key_env)
            if val:
                entry["api_key"] = val
        if url_env:
            val = os.environ.get(url_env) or env_file.get(url_env)
            if val and not entry.get("base_url"):
                entry["base_url"] = val
    return creds


def store_key(provider: str, api_key: str, home: Path | None = None) -> Path:
    home = home or DEFAULT_HOME
    home.mkdir(parents=True, exist_ok=True)
    path = home / "keys.toml"
    existing: dict[str, Any] = {}
    if path.exists():
        try:
            existing = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            existing = {}
    existing.setdefault(provider, {})["api_key"] = api_key
    lines = [
        "# ANJALI-AI BYOK credentials. Mode 0600. Never commit this file.",
        "# Prefer environment variables in CI/CD.",
        "",
    ]
    for prov, values in existing.items():
        lines.append(f"[{prov}]")
        for k, v in values.items():
            escaped = str(v).replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{k} = "{escaped}"')
        lines.append("")
    atomic_write(path, "\n".join(lines), mode=0o600)
    return path


def clear_key(provider: str, home: Path | None = None) -> bool:
    home = home or DEFAULT_HOME
    path = home / "keys.toml"
    if not path.exists():
        return False
    try:
        existing = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return False
    if provider not in existing:
        return False
    existing.pop(provider)
    lines = ["# ANJALI-AI BYOK credentials. Mode 0600. Never commit this file.", ""]
    for prov, values in existing.items():
        lines.append(f"[{prov}]")
        for k, v in values.items():
            lines.append(f'{k} = "{v}"')
        lines.append("")
    atomic_write(path, "\n".join(lines), mode=0o600)
    return True


def load_settings(home: Path | None = None) -> Settings:
    home = home or DEFAULT_HOME
    settings = Settings(home=home)
    if settings.config_file.exists():
        try:
            data = read_json(settings.config_file)
        except (ValueError, OSError) as exc:  # pragma: no cover - corrupt config
            raise ConfigError(f"Cannot parse {settings.config_file}: {exc}") from exc
        prov = data.get("provider", {})
        settings.provider = ProviderConfig(
            name=prov.get("name", "offline"),
            model=prov.get("model", DEFAULT_MODELS.get(prov.get("name", "offline"), "")),
            base_url=prov.get("base_url"),
            temperature=float(prov.get("temperature", 0.1)),
            max_tokens=int(prov.get("max_tokens", 2048)),
        )
        rag = data.get("rag", {})
        settings.rag = RagConfig(
            top_k=int(rag.get("top_k", 8)),
            candidate_k=int(rag.get("candidate_k", 40)),
            embedder=rag.get("embedder", "local"),
            hybrid=bool(rag.get("hybrid", True)),
            mmr_lambda=float(rag.get("mmr_lambda", 0.72)),
            as_of=rag.get("as_of"),
        )
        risk = data.get("risk", {})
        if risk.get("weights"):
            settings.risk.weights = {k: float(v) for k, v in risk["weights"].items()}
        if risk.get("band_cutoffs"):
            settings.risk.band_cutoffs = risk["band_cutoffs"]
        settings.default_jurisdictions = data.get(
            "default_jurisdictions", settings.default_jurisdictions
        )
        settings.require_citations = bool(data.get("require_citations", True))
        settings.max_agent_steps = int(data.get("max_agent_steps", 8))
        settings.audit_enabled = bool(data.get("audit_enabled", True))

    overrides_json = os.environ.get("ANJALI_CONFIG_OVERRIDES")
    if overrides_json:
        import json as _json

        try:
            overrides = _json.loads(overrides_json)
        except _json.JSONDecodeError:
            overrides = {}
        for path, value in overrides.items():
            target: Any = settings
            parts = path.split(".")
            for part in parts[:-1]:
                target = getattr(target, part)
            setattr(target, parts[-1], value)

    creds = load_credentials(home)
    entry = creds.get(settings.provider.name, {})
    settings.provider.api_key = entry.get("api_key") or settings.provider.api_key
    settings.provider.base_url = (
        settings.provider.base_url
        or entry.get("base_url")
        or DEFAULT_BASE_URLS.get(settings.provider.name)
    )
    if not settings.provider.model:
        settings.provider.model = DEFAULT_MODELS.get(settings.provider.name, "")
    return settings


def available_providers(home: Path | None = None) -> list[dict[str, Any]]:
    creds = load_credentials(home)
    rows = []
    for name, (key_env, _) in PROVIDER_ENV.items():
        entry = creds.get(name, {})
        has_key = bool(entry.get("api_key"))
        reachable_hint = name == "ollama"
        rows.append(
            {
                "provider": name,
                "model": DEFAULT_MODELS.get(name, ""),
                "key_present": has_key,
                "env_var": key_env,
                "local": reachable_hint,
                "ready": has_key or name == "offline" or reachable_hint,
            }
        )
    return rows


_SECRET_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9_\-]{8,})"),
    re.compile(r"(gsk_[A-Za-z0-9]{8,})"),
    re.compile(r"(AKIA[0-9A-Z]{12,})"),
    re.compile(r"(?i)(api[_-]?key\"?\s*[:=]\s*\"?)([A-Za-z0-9_\-]{8,})"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)(\S+)"),
]


def redact(text: str) -> str:
    """Best-effort scrubbing applied before anything is printed or logged."""
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        if pat.groups == 2:
            out = pat.sub(lambda m: f"{m.group(1)}[REDACTED]", out)
        else:
            out = pat.sub("[REDACTED]", out)
    return out


def resolve_provider(name: str, settings: Settings) -> ProviderConfig:
    """Build a ProviderConfig for ``name`` inheriting model/base-url defaults."""
    if name not in DEFAULT_MODELS:
        raise ConfigError(
            f"Unknown provider '{name}'. Choose from: {', '.join(DEFAULT_MODELS)}",
            hint="Run `anjali providers` to see availability.",
        )
    creds = load_credentials(settings.home).get(name, {})
    model = DEFAULT_MODELS.get(name, "")
    if name == settings.provider.name and settings.provider.model:
        model = settings.provider.model
    return ProviderConfig(
        name=name,
        model=model,
        base_url=creds.get("base_url") or DEFAULT_BASE_URLS.get(name),
        api_key=creds.get("api_key"),
        temperature=settings.provider.temperature,
        max_tokens=settings.provider.max_tokens,
    )


def case_dir(settings: Settings, case_id: str) -> Path:
    return settings.home / "cases" / slug(case_id)
