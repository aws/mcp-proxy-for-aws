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

"""Configuration file loading for MCP Proxy for AWS."""

import logging
import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


class Config:
    """Configuration container for MCP Proxy."""

    def __init__(
        self,
        endpoint: str,
        service: Optional[str] = None,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        read_only: bool = False,
        log_level: str = 'INFO',
        retries: int = 0,
        timeout: float = 180.0,
        connect_timeout: float = 60.0,
        read_timeout: float = 120.0,
        write_timeout: float = 180.0,
    ):
        """Initialize configuration.

        Args:
            endpoint: SigV4 MCP endpoint URL
            service: AWS service name for SigV4 signing
            profile: AWS profile to use
            region: AWS region to use
            read_only: Disable tools which may require write permissions
            log_level: Logging level
            retries: Number of retries when calling endpoint
            timeout: Timeout when connecting to endpoint
            connect_timeout: Connection timeout
            read_timeout: Read timeout
            write_timeout: Write timeout
        """
        self.endpoint = endpoint
        self.service = service
        self.profile = profile
        self.region = region
        self.read_only = read_only
        self.log_level = log_level
        self.retries = retries
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.write_timeout = write_timeout


def load_config_file(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to YAML configuration file

    Returns:
        Dictionary containing configuration values

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
        ValueError: If config file has invalid structure
    """
    path = Path(config_path).expanduser()

    if not path.exists():
        raise FileNotFoundError(f'Configuration file not found: {config_path}')

    logger.info('Loading configuration from: %s', config_path)

    with open(path, 'r') as f:
        try:
            config_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f'Invalid YAML in configuration file: {e}')

    if not isinstance(config_data, dict):
        raise ValueError('Configuration file must contain a YAML dictionary')

    return config_data


def merge_config(file_config: Optional[Dict[str, Any]], cli_args: Any) -> Config:
    """Merge configuration from file and CLI arguments.

    CLI arguments take precedence over file configuration.

    Args:
        file_config: Configuration loaded from file (or None)
        cli_args: Parsed command-line arguments

    Returns:
        Config object with merged configuration
    """
    # Start with file config or empty dict
    config_dict = file_config.copy() if file_config else {}

    # CLI args override file config (only if explicitly provided)
    if hasattr(cli_args, 'endpoint') and cli_args.endpoint:
        config_dict['endpoint'] = cli_args.endpoint

    if hasattr(cli_args, 'service') and cli_args.service:
        config_dict['service'] = cli_args.service

    if hasattr(cli_args, 'profile') and cli_args.profile:
        config_dict['profile'] = cli_args.profile

    if hasattr(cli_args, 'region') and cli_args.region:
        config_dict['region'] = cli_args.region

    if hasattr(cli_args, 'read_only') and cli_args.read_only:
        config_dict['read_only'] = cli_args.read_only

    if hasattr(cli_args, 'log_level') and cli_args.log_level:
        config_dict['log_level'] = cli_args.log_level

    if hasattr(cli_args, 'retries') and cli_args.retries is not None:
        config_dict['retries'] = cli_args.retries

    if hasattr(cli_args, 'timeout') and cli_args.timeout is not None:
        config_dict['timeout'] = cli_args.timeout

    if hasattr(cli_args, 'connect_timeout') and cli_args.connect_timeout is not None:
        config_dict['connect_timeout'] = cli_args.connect_timeout

    if hasattr(cli_args, 'read_timeout') and cli_args.read_timeout is not None:
        config_dict['read_timeout'] = cli_args.read_timeout

    if hasattr(cli_args, 'write_timeout') and cli_args.write_timeout is not None:
        config_dict['write_timeout'] = cli_args.write_timeout

    # Validate required fields
    if 'endpoint' not in config_dict:
        raise ValueError('endpoint is required (provide via CLI or config file)')

    # Apply environment variable defaults if not set
    if 'profile' not in config_dict:
        config_dict['profile'] = os.getenv('AWS_PROFILE')

    return Config(**config_dict)
