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

"""Logging configuration for MCP Proxy for AWS."""

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
    console_handler = logging.StreamHandler(sys.stderr)
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
