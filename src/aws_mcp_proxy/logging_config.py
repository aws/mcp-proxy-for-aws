"""Logging configuration for AWS MCP Proxy."""

import logging
import sys
from typing import Optional


def configure_logging(level: Optional[str] = None) -> None:
    """Configure logging with a standard format and optional level.

    Args:
        level: Optional logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
               If not provided, defaults to INFO.
    """
    # Set default level to INFO if not provided
    log_level = getattr(logging, level.upper()) if level else logging.INFO

    # Configure logging format
    log_format = '%(asctime)s | %(levelname)s | %(name)s | %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # Create console handler with formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(log_format, date_format))

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove any existing handlers and add our console handler
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)

    # Set httpx logging to WARNING by default to reduce noise
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('httpcore').setLevel(logging.WARNING)
