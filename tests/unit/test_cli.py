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
        assert args.log_level == 'INFO'
        assert args.retries == 0
        assert args.timeout == 180.0
        assert args.connect_timeout == 60.0
        assert args.read_timeout == 120.0
        assert args.write_timeout == 180.0

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
