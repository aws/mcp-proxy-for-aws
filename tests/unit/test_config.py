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

"""Tests for configuration file loading."""

import argparse
import os
import pytest
import tempfile
import yaml
from mcp_proxy_for_aws.config import Config, load_config_file, merge_config
from pathlib import Path


class TestLoadConfigFile:
    """Tests for load_config_file function."""

    def test_load_valid_config(self):
        """Test loading a valid YAML configuration file."""
        config_data = {
            'endpoint': 'https://example.com/mcp',
            'service': 'test-service',
            'profile': 'test-profile',
            'region': 'us-west-2',
            'read_only': True,
            'log_level': 'DEBUG',
            'retries': 3,
            'timeout': 200.0,
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            loaded_config = load_config_file(config_path)
            assert loaded_config == config_data
        finally:
            os.unlink(config_path)

    def test_load_nonexistent_file(self):
        """Test loading a non-existent configuration file."""
        with pytest.raises(FileNotFoundError):
            load_config_file('/nonexistent/config.yaml')

    def test_load_invalid_yaml(self):
        """Test loading an invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('invalid: yaml: content:\n  - broken')
            config_path = f.name

        try:
            with pytest.raises(yaml.YAMLError):
                load_config_file(config_path)
        finally:
            os.unlink(config_path)

    def test_load_non_dict_yaml(self):
        """Test loading a YAML file that doesn't contain a dictionary."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(['list', 'of', 'items'], f)
            config_path = f.name

        try:
            with pytest.raises(ValueError, match='must contain a YAML dictionary'):
                load_config_file(config_path)
        finally:
            os.unlink(config_path)

    def test_load_with_tilde_expansion(self):
        """Test loading a config file with ~ in path."""
        config_data = {'endpoint': 'https://example.com/mcp'}

        # Create temp file in home directory
        home = Path.home()
        config_path = home / '.mcp-proxy-test-config.yaml'

        try:
            with open(config_path, 'w') as f:
                yaml.dump(config_data, f)

            # Load using ~ notation
            loaded_config = load_config_file(f'~/{config_path.name}')
            assert loaded_config == config_data
        finally:
            if config_path.exists():
                config_path.unlink()


class TestMergeConfig:
    """Tests for merge_config function."""

    def test_merge_with_no_file_config(self):
        """Test merging when no file config is provided."""
        cli_args = argparse.Namespace(
            endpoint='https://cli.example.com/mcp',
            service='cli-service',
            profile='cli-profile',
            region='us-east-1',
            read_only=True,
            log_level='INFO',
            retries=2,
            timeout=150.0,
            connect_timeout=50.0,
            read_timeout=100.0,
            write_timeout=150.0,
        )

        config = merge_config(None, cli_args)

        assert config.endpoint == 'https://cli.example.com/mcp'
        assert config.service == 'cli-service'
        assert config.profile == 'cli-profile'
        assert config.region == 'us-east-1'
        assert config.read_only is True
        assert config.log_level == 'INFO'
        assert config.retries == 2

    def test_merge_cli_overrides_file(self):
        """Test that CLI arguments override file configuration."""
        file_config = {
            'endpoint': 'https://file.example.com/mcp',
            'service': 'file-service',
            'profile': 'file-profile',
            'region': 'us-west-2',
            'read_only': False,
            'log_level': 'WARNING',
            'retries': 1,
        }

        cli_args = argparse.Namespace(
            endpoint='https://cli.example.com/mcp',
            service='cli-service',
            profile=None,
            region=None,
            read_only=True,
            log_level='DEBUG',
            retries=None,
            timeout=None,
            connect_timeout=None,
            read_timeout=None,
            write_timeout=None,
        )

        config = merge_config(file_config, cli_args)

        # CLI overrides
        assert config.endpoint == 'https://cli.example.com/mcp'
        assert config.service == 'cli-service'
        assert config.read_only is True
        assert config.log_level == 'DEBUG'

        # File values preserved
        assert config.profile == 'file-profile'
        assert config.region == 'us-west-2'
        assert config.retries == 1

    def test_merge_with_environment_variables(self, monkeypatch):
        """Test that environment variables are used as defaults."""
        monkeypatch.setenv('AWS_PROFILE', 'env-profile')

        file_config = {
            'endpoint': 'https://file.example.com/mcp',
        }

        cli_args = argparse.Namespace(
            endpoint=None,
            service=None,
            profile=None,
            region=None,
            read_only=False,
            log_level='INFO',
            retries=0,
            timeout=180.0,
            connect_timeout=60.0,
            read_timeout=120.0,
            write_timeout=180.0,
        )

        config = merge_config(file_config, cli_args)

        assert config.endpoint == 'https://file.example.com/mcp'
        assert config.profile == 'env-profile'

    def test_merge_missing_required_endpoint(self):
        """Test that missing endpoint raises ValueError."""
        cli_args = argparse.Namespace(
            endpoint=None,
            service=None,
            profile=None,
            region=None,
            read_only=False,
            log_level='INFO',
            retries=0,
            timeout=180.0,
            connect_timeout=60.0,
            read_timeout=120.0,
            write_timeout=180.0,
        )

        with pytest.raises(ValueError, match='endpoint is required'):
            merge_config({}, cli_args)


class TestConfig:
    """Tests for Config class."""

    def test_config_initialization(self):
        """Test Config object initialization."""
        config = Config(
            endpoint='https://example.com/mcp',
            service='test-service',
            profile='test-profile',
            region='us-east-1',
            read_only=True,
            log_level='DEBUG',
            retries=3,
            timeout=200.0,
            connect_timeout=70.0,
            read_timeout=130.0,
            write_timeout=200.0,
        )

        assert config.endpoint == 'https://example.com/mcp'
        assert config.service == 'test-service'
        assert config.profile == 'test-profile'
        assert config.region == 'us-east-1'
        assert config.read_only is True
        assert config.log_level == 'DEBUG'
        assert config.retries == 3
        assert config.timeout == 200.0
        assert config.connect_timeout == 70.0
        assert config.read_timeout == 130.0
        assert config.write_timeout == 200.0

    def test_config_with_defaults(self):
        """Test Config object with default values."""
        config = Config(endpoint='https://example.com/mcp')

        assert config.endpoint == 'https://example.com/mcp'
        assert config.service is None
        assert config.profile is None
        assert config.region is None
        assert config.read_only is False
        assert config.log_level == 'INFO'
        assert config.retries == 0
        assert config.timeout == 180.0
        assert config.connect_timeout == 60.0
        assert config.read_timeout == 120.0
        assert config.write_timeout == 180.0
