"""
Specter-OS — Logger
Rich-colored structured logger for all agents and services.
"""

import logging
from rich.logging import RichHandler
from rich.console import Console

console = Console()

_loggers: dict[str, logging.Logger] = {}

def get_logger(name: str) -> logging.Logger:
    """Get or create a named Rich logger."""
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(f"specter.{name}")
    if not logger.handlers:
        handler = RichHandler(
            console=console,
            show_time=True,
            show_level=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

    _loggers[name] = logger
    return logger
