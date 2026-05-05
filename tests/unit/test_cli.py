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

"""Tests for CLI argument parsing."""

import pytest
from mcp_proxy_for_aws.cli import parse_args
from unittest.mock import patch


class TestParseArgs:
    """Tests for parse_args function."""

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com'])
    def test_parse_args_minimal(self):
        """Test parsing with minimal required arguments."""
        args = parse_args()

        assert args.endpoint == 'https://test.example.com'
        assert args.service is None
        assert args.profile is None
        assert args.region is None
        assert args.read_only is False
        assert args.log_level == 'ERROR'
        assert args.retries == 0
        assert args.timeout == 180.0
        assert args.connect_timeout == 60.0
        assert args.read_timeout == 120.0
        assert args.write_timeout == 180.0
        assert args.tool_timeout == 300.0
        assert args.disable_telemetry is False

    @patch(
        'sys.argv',
        [
            'mcp-proxy-for-aws',
            'https://test.example.com',
            '--service',
            'lambda',
            '--profile',
            'prod',
            '--region',
            'eu-west-1',
            '--read-only',
            '--log-level',
            'WARNING',
            '--retries',
            '3',
            '--timeout',
            '300',
            '--connect-timeout',
            '30',
            '--read-timeout',
            '90',
            '--write-timeout',
            '120',
        ],
    )
    def test_parse_args_with_all_options(self):
        """Test parsing with all options to verify no conflicts."""
        args = parse_args()

        assert args.endpoint == 'https://test.example.com'
        assert args.service == 'lambda'
        assert args.profile == 'prod'
        assert args.region == 'eu-west-1'
        assert args.read_only is True
        assert args.log_level == 'WARNING'
        assert args.retries == 3
        assert args.timeout == 300.0
        assert args.connect_timeout == 30.0
        assert args.read_timeout == 90.0
        assert args.write_timeout == 120.0

    @patch('sys.argv', ['mcp-proxy-for-aws'])
    def test_parse_args_missing_endpoint(self):
        """Test parsing fails when endpoint is missing."""
        with pytest.raises(SystemExit):
            parse_args()

    @patch.dict('os.environ', {'AWS_PROFILE': 'env-profile'})
    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com'])
    def test_parse_args_profile_from_env(self):
        """Test that profile is read from AWS_PROFILE environment variable."""
        args = parse_args()

        assert args.endpoint == 'https://test.example.com'
        assert args.profile == 'env-profile'

    @patch.dict('os.environ', {'AWS_PROFILE': 'env-profile'})
    @patch(
        'sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--profile', 'cli-profile']
    )
    def test_parse_args_profile_cli_overrides_env(self):
        """Test that CLI profile argument overrides environment variable."""
        args = parse_args()

        assert args.endpoint == 'https://test.example.com'
        assert args.profile == 'cli-profile'

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--retries', '0'])
    def test_parse_args_retries_minimum(self):
        """Test parsing with minimum valid retries value (boundary)."""
        args = parse_args()

        assert args.endpoint == 'https://test.example.com'
        assert args.retries == 0

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--retries', '10'])
    def test_parse_args_retries_maximum(self):
        """Test parsing with maximum valid retries value (boundary)."""
        args = parse_args()

        assert args.endpoint == 'https://test.example.com'
        assert args.retries == 10

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--retries', '11'])
    def test_parse_args_invalid_retries(self):
        """Test parsing fails with retries value above maximum (boundary)."""
        with pytest.raises(SystemExit):
            parse_args()

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--log-level', 'INVALID'])
    def test_parse_args_invalid_log_level(self):
        """Test parsing fails with invalid log level (choices validation)."""
        with pytest.raises(SystemExit):
            parse_args()

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--timeout', '-1'])
    def test_parse_args_negative_timeout(self):
        """Test parsing fails with negative timeout (within_range validation)."""
        with pytest.raises(SystemExit):
            parse_args()

    @patch(
        'sys.argv',
        ['mcp-proxy-for-aws', 'https://example.com', '--metadata', 'KEY1=value1', 'KEY2=value2'],
    )
    def test_parse_metadata_argument(self):
        """Test parsing metadata key=value pairs."""
        args = parse_args()
        assert args.metadata == {'KEY1': 'value1', 'KEY2': 'value2'}

    @patch(
        'sys.argv',
        ['mcp-proxy-for-aws', 'https://example.com', '--metadata', 'AWS_REGION=us-west-2'],
    )
    def test_parse_metadata_single_pair(self):
        """Test parsing single metadata key=value pair."""
        args = parse_args()
        assert args.metadata == {'AWS_REGION': 'us-west-2'}

    @patch(
        'sys.argv',
        ['mcp-proxy-for-aws', 'https://example.com', '--metadata', 'KEY=value with spaces'],
    )
    def test_parse_metadata_with_spaces_in_value(self):
        """Test parsing metadata with spaces in value."""
        args = parse_args()
        assert args.metadata == {'KEY': 'value with spaces'}

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://example.com', '--metadata'])
    def test_parse_metadata_no_values(self):
        """Test parsing --metadata flag with no values results in empty dict."""
        args = parse_args()
        # When --metadata is provided with no values (nargs='*'), it should be empty dict
        # This is handled by KeyValueAction which sets an empty dict when values is None
        assert args.metadata == {} or args.metadata is None, (
            f'Expected empty dict or None, got {args.metadata}'
        )

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://example.com', '--metadata', 'INVALID'])
    def test_parse_metadata_invalid_format(self):
        """Test that invalid metadata format raises an error."""
        import argparse

        with pytest.raises((SystemExit, argparse.ArgumentTypeError)):
            # argparse may call sys.exit or raise ArgumentTypeError
            parse_args()

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--disable-telemetry'])
    def test_parse_args_disable_telemetry_flag(self):
        """Test that --disable-telemetry flag sets disable_telemetry to True."""
        args = parse_args()

        assert args.disable_telemetry is True

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com'])
    def test_parse_args_disable_telemetry_default(self):
        """Test that disable_telemetry defaults to False when flag is not provided."""
        args = parse_args()

        assert args.disable_telemetry is False

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com'])
    def test_parse_args_transport_default_stdio(self):
        """Test that transport defaults to stdio."""
        args = parse_args()

        assert args.transport == 'stdio'

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--transport', 'streamable-http'])
    def test_parse_args_transport_streamable_http(self):
        """Test that transport can be set to streamable-http."""
        args = parse_args()

        assert args.transport == 'streamable-http'

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com'])
    def test_parse_args_host_default(self):
        """Test that host defaults to 127.0.0.1."""
        args = parse_args()

        assert args.host == '127.0.0.1'

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--host', '0.0.0.0'])
    def test_parse_args_host_custom(self):
        """Test that host can be customized."""
        args = parse_args()

        assert args.host == '0.0.0.0'

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com'])
    def test_parse_args_port_default(self):
        """Test that port defaults to 8080."""
        args = parse_args()

        assert args.port == 8080

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--port', '3000'])
    def test_parse_args_port_custom(self):
        """Test that port can be customized."""
        args = parse_args()

        assert args.port == 3000

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com'])
    def test_parse_args_path_default(self):
        """Test that path defaults to /mcp."""
        args = parse_args()

        assert args.path == '/mcp'

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--path', '/custom'])
    def test_parse_args_path_custom(self):
        """Test that path can be customized."""
        args = parse_args()

        assert args.path == '/custom'

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com'])
    def test_parse_args_health_path_default(self):
        """Test that health_path defaults to /health."""
        args = parse_args()

        assert args.health_path == '/health'

    @patch('sys.argv', ['mcp-proxy-for-aws', 'https://test.example.com', '--health-path', '/ping'])
    def test_parse_args_health_path_custom(self):
        """Test that health_path can be customized."""
        args = parse_args()

        assert args.health_path == '/ping'
