"""Centralized logging helpers for console and file outputs."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler


def setup_logger(log_level: str = "INFO", log_dir: str = "./output") -> logging.Logger:
    """Configure and return a toolkit logger.

    Args:
        log_level: Logging verbosity as standard logging level.
        log_dir: Directory where runtime log file is saved.

    Returns:
        Configured logger instance.
    """

    logger = logging.getLogger("recon_toolkit")
    if logger.handlers:
        return logger

    level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(level)

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path / "recon_toolkit.log", encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    rich_handler = RichHandler(rich_tracebacks=True, show_time=False)
    rich_handler.setLevel(level)
    rich_handler.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(rich_handler)
    logger.propagate = False

    return logger
