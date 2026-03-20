from pathlib import Path

import pytest

from core.config_loader import ConfigError, load_config


def test_config_loader_valid(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        """
general:
  output_dir: ./output
  log_level: INFO
  request_timeout: 10
  max_concurrent_requests: 5
api_keys:
  securitytrails: ""
  shodan: ""
  virustotal: ""
modules:
  subdomain_enum: true
  dns_analysis: true
  whois_asn: true
  ssl_tls: true
  tech_detection: true
  header_audit: true
  surface_mapper: true
  wayback: true
  attack_graph: true
rate_limits:
  crtsh_delay: 1.0
  wayback_delay: 0.5
  dns_concurrent: 10
""",
        encoding="utf-8",
    )

    loaded = load_config(config)
    assert loaded.general.request_timeout == 10


def test_config_loader_invalid(tmp_path: Path) -> None:
    config = tmp_path / "invalid.yaml"
    config.write_text("general: {request_timeout: 0}\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(config)
