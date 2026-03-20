"""Configuration loading and validation helpers."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from core.models import ToolkitConfig


class ConfigError(Exception):
    """Raised when config loading or validation fails."""


def load_config(config_path: str | Path) -> ToolkitConfig:
    """Load and validate YAML configuration into typed models.

    Args:
        config_path: Path to YAML config file.

    Returns:
        Validated toolkit configuration.

    Raises:
        ConfigError: If file can't be loaded or schema validation fails.
    """

    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        raw_data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in config file {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Unable to read config file {path}: {exc}") from exc

    try:
        config = ToolkitConfig.model_validate(raw_data)
    except ValidationError as exc:
        raise ConfigError(f"Configuration validation failed: {exc}") from exc

    output_dir = Path(config.general.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if config.general.request_timeout <= 0:
        raise ConfigError("general.request_timeout must be greater than 0")
    if config.general.max_concurrent_requests <= 0:
        raise ConfigError("general.max_concurrent_requests must be greater than 0")
    if config.rate_limits.dns_concurrent <= 0:
        raise ConfigError("rate_limits.dns_concurrent must be greater than 0")

    return config
