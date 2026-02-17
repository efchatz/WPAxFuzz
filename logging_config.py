"""
Logging configuration for WPAxFuzz with Rich console output and file logging.
"""

import logging
import logging.config
from rich.logging import RichHandler

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(message)s"
        }
    },
    "handlers": {
        "rich": {
            "class": "rich.logging.RichHandler",
            "formatter": "default",
            "rich_tracebacks": True
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "wpa_fuzzer.log",
            "formatter": "default"
        }
    },
    "root": {
        "handlers": ["rich", "file"],
        "level": "INFO"
    }
}


def setup_logging():
    """Configure logging with Rich console output and file output."""
    logging.config.dictConfig(LOGGING_CONFIG)
