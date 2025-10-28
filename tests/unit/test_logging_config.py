# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for logging configuration."""

import logging
import pytest
from mcp_proxy_for_aws.logging_config import configure_logging


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
