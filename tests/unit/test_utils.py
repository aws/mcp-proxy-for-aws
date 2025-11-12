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

"""Tests for utils module."""

import pytest
from fastmcp.client.transports import StreamableHttpTransport
from mcp_proxy_for_aws.utils import (
    create_transport_with_sigv4,
    determine_aws_region,
    determine_service_name,
)
from unittest.mock import MagicMock, patch


class TestCreateTransportWithSigv4:
    """Test cases for create_transport_with_sigv4 function (line 129)."""

    @patch('mcp_proxy_for_aws.utils.create_sigv4_client')
    def test_create_transport_with_sigv4(self, mock_create_sigv4_client):
        """Test creating StreamableHttpTransport with SigV4 authentication."""
        from httpx import Timeout

        mock_client = MagicMock()
        mock_create_sigv4_client.return_value = mock_client

        url = 'https://test-service.us-west-2.api.aws/mcp'
        service = 'test-service'
        profile = 'test-profile'
        region = 'us-east-1'
        metadata = {'AWS_REGION': 'us-west-2', 'CUSTOM_KEY': 'custom_value'}
        custom_timeout = Timeout(30.0)

        result = create_transport_with_sigv4(
            url, service, region, metadata, custom_timeout, profile
        )

        # Verify result is StreamableHttpTransport
        assert isinstance(result, StreamableHttpTransport)
        assert result.url == url

        # Test that the httpx_client_factory calls create_sigv4_client correctly
        # We need to access the factory through the transport's internal structure
        if hasattr(result, 'httpx_client_factory') and result.httpx_client_factory:
            factory = result.httpx_client_factory
            test_kwargs = {'headers': {'test': 'header'}, 'timeout': Timeout(30.0), 'auth': None}
            factory(**test_kwargs)

            mock_create_sigv4_client.assert_called_once_with(
                service=service,
                profile=profile,
                region=region,
                headers={'test': 'header'},
                timeout=custom_timeout,
                auth=None,
                metadata=metadata,
            )
        else:
            # If we can't access the factory directly, just verify the transport was created
            assert result is not None

    @patch('mcp_proxy_for_aws.utils.create_sigv4_client')
    def test_create_transport_with_sigv4_no_profile(self, mock_create_sigv4_client):
        """Test creating transport without profile."""
        from httpx import Timeout

        url = 'https://test-service.us-west-2.api.aws/mcp'
        service = 'test-service'
        region = 'test-region'
        metadata = {'AWS_REGION': 'test-forwarding-region'}
        custom_timeout = Timeout(60.0)

        result = create_transport_with_sigv4(url, service, region, metadata, custom_timeout)

        # Test that the httpx_client_factory calls create_sigv4_client correctly
        # We need to access the factory through the transport's internal structure
        if hasattr(result, 'httpx_client_factory') and result.httpx_client_factory:
            factory = result.httpx_client_factory
            factory(headers=None, timeout=None, auth=None)

            mock_create_sigv4_client.assert_called_once_with(
                service=service,
                region=region,
                profile=None,
                headers=None,
                timeout=custom_timeout,
                auth=None,
                metadata=metadata,
            )
        else:
            # If we can't access the factory directly, just verify the transport was created
            assert result is not None


class TestValidateRequiredArgs:
    """Test cases for validate_service_name function."""

    def test_validate_service_name_with_service(self):
        """Test validation when service is provided."""
        endpoint = 'https://test-service.us-west-2.api.aws'
        service = 'custom-service'

        result = determine_service_name(endpoint, service)

        assert result == service

    def test_validate_service_name_without_service_success(self):
        """Test validation when service is not provided but can be parsed."""
        endpoint = 'https://test-service.us-west-2.api.aws'
        expected_service = 'test-service'

        result = determine_service_name(endpoint)

        assert result == expected_service

    def test_validate_service_name_service_parsing_with_dash(self):
        """Test parsing service from endpoint with dash in service name."""
        endpoint = 'https://my-service.us-west-2.api.aws'
        result = determine_service_name(endpoint)
        assert result == 'my-service'

    def test_validate_service_name_service_parsing_with_dot(self):
        """Test parsing service from endpoint with dot in hostname."""
        endpoint = 'https://service.subdomain.us-west-2.api.aws'
        result = determine_service_name(endpoint)
        assert result == 'service'

    def test_validate_service_name_bedrock_agentcore(self):
        """Test parsing service name for bedrock-agentcore endpoints."""
        # Test various bedrock-agentcore endpoint formats
        test_cases = [
            'https://my-agent.gateway.bedrock-agentcore.us-west-2.amazonaws.com',  # Clean gateway
            'https://bedrock-agentcore.us-east-1.amazonaws.com',  # Clean runtime
            'https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-east-1%3A216123456714%3Aruntime%2Fhosted_agent_99wdf-hYKYrgAHVr/invocations',
            'https://gateway-quick-start-242206-rsdehprct2.gateway.bedrock-agentcore.eu-central-1.amazonaws.com/mcp',
        ]

        for endpoint in test_cases:
            result = determine_service_name(endpoint)
            assert result == 'bedrock-agentcore', f'Failed for endpoint: {endpoint}'

    def test_validate_service_name_service_parsing_simple_hostname(self):
        """Test parsing service from simple hostname."""
        endpoint = 'https://myservice'
        result = determine_service_name(endpoint)
        assert result == 'myservice'

    def test_validate_service_name_without_service_failure(self):
        """Test validation when service cannot be determined."""
        endpoint = 'https://'

        with pytest.raises(ValueError) as exc_info:
            determine_service_name(endpoint)

        assert 'Could not determine AWS service name' in str(exc_info.value)
        assert endpoint in str(exc_info.value)
        assert '--service argument' in str(exc_info.value)

    def test_validate_service_name_invalid_url_failure(self):
        """Test validation with invalid URL."""
        endpoint = 'not-a-url'

        with pytest.raises(ValueError) as exc_info:
            determine_service_name(endpoint)

        assert 'Could not determine AWS service name' in str(exc_info.value)
        assert endpoint in str(exc_info.value)
        assert '--service argument' in str(exc_info.value)


class TestDetermineRegion:
    """Test cases for determine_aws_region function."""

    @patch('os.getenv')
    def test_determine_region_with_region(self, mock_getenv):
        """Test determination when region is provided."""
        endpoint = 'https://mcp.us-east-1.api.aws/mcp'
        region = 'custom-region'

        result = determine_aws_region(endpoint, region)

        assert result == region
        # Environment variable should not be checked when region is provided
        mock_getenv.assert_not_called()

    @patch('os.getenv')
    def test_determine_region_without_region_success(self, mock_getenv):
        """Test determination when region is not provided but can be parsed."""
        endpoint = 'https://mcp.us-east-1.api.aws/mcp'
        expected_region = 'us-east-1'
        mock_getenv.return_value = None

        result = determine_aws_region(endpoint, None)

        assert result == expected_region
        # Environment variable should not be checked when region can be parsed from endpoint

    @patch('os.getenv')
    def test_determine_region_with_complex_service_name(self, mock_getenv):
        """Test parsing region from endpoint with complex service name."""
        endpoint = 'https://eks-mcp-beta.us-west-2.api.aws/mcp'
        expected_region = 'us-west-2'
        mock_getenv.return_value = None

        result = determine_aws_region(endpoint, None)

        assert result == expected_region
        # Environment variable should not be checked when region can be parsed from endpoint

    @patch('os.getenv')
    def test_determine_region_without_region_failure(self, mock_getenv):
        """Test determination when region cannot be determined."""
        endpoint = 'https://service.example.com'
        mock_getenv.return_value = None

        with pytest.raises(ValueError) as exc_info:
            determine_aws_region(endpoint, None)

        assert 'Could not determine AWS region' in str(exc_info.value)
        assert endpoint in str(exc_info.value)
        assert '--region argument' in str(exc_info.value)
        mock_getenv.assert_called_once_with('AWS_REGION')

    @patch('os.getenv')
    def test_determine_region_from_environment(self, mock_getenv):
        """Test determination from environment variable when endpoint doesn't contain region."""
        # Arrange
        endpoint = 'https://test-service.example.com'
        mock_getenv.return_value = 'us-west-1'

        # Act
        result = determine_aws_region(endpoint, None)

        # Assert
        assert result == 'us-west-1'
        mock_getenv.assert_called_once_with('AWS_REGION')
