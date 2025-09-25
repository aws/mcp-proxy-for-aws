"""Tests for logging configuration."""

import logging
import pytest
from src.aws_mcp_proxy.logging_config import configure_logging


def test_configure_logging_default_level():
    """Test logging configuration with default level."""
    # Configure logging
    configure_logging()

    # Check root logger level
    assert logging.getLogger().level == logging.INFO

    # Check handler configuration
    root_logger = logging.getLogger()
    assert len(root_logger.handlers) == 1
    assert isinstance(root_logger.handlers[0], logging.StreamHandler)


def test_configure_logging_custom_level():
    """Test logging configuration with custom level."""
    # Configure logging with DEBUG level
    configure_logging('DEBUG')

    # Check root logger level
    assert logging.getLogger().level == logging.DEBUG


def test_configure_logging_invalid_level():
    """Test logging configuration with invalid level."""
    with pytest.raises(AttributeError):
        configure_logging('INVALID_LEVEL')


def test_httpx_logging_level():
    """Test that httpx logging is set to WARNING."""
    # Configure logging
    configure_logging()

    # Check httpx logger level
    assert logging.getLogger('httpx').level == logging.WARNING
    assert logging.getLogger('httpcore').level == logging.WARNING
