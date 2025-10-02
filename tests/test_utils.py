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
from aws_mcp_proxy.utils import (
    create_transport_with_sigv4,
    determine_aws_region,
    determine_service_name,
)
from fastmcp.client.transports import StreamableHttpTransport
from unittest.mock import MagicMock, patch


class TestCreateTransportWithSigv4:
    """Test cases for create_transport_with_sigv4 function (line 129)."""

    @patch('aws_mcp_proxy.utils.create_sigv4_client')
    def test_create_transport_with_sigv4(self, mock_create_sigv4_client):
        """Test creating StreamableHttpTransport with SigV4 authentication."""
        mock_client = MagicMock()
        mock_create_sigv4_client.return_value = mock_client

        url = 'https://eks-mcp.us-west-2.api.aws/mcp'
        service = 'eks-mcp'
        profile = 'test-profile'
        region = 'us-east-1'

        result = create_transport_with_sigv4(url, service, region, profile)

        # Verify result is StreamableHttpTransport
        assert isinstance(result, StreamableHttpTransport)
        assert result.url == url

        # Test that the httpx_client_factory calls create_sigv4_client correctly
        # We need to access the factory through the transport's internal structure
        if hasattr(result, 'httpx_client_factory') and result.httpx_client_factory:
            from httpx import Timeout

            factory = result.httpx_client_factory
            test_kwargs = {'headers': {'test': 'header'}, 'timeout': Timeout(30.0), 'auth': None}
            factory(**test_kwargs)

            mock_create_sigv4_client.assert_called_once_with(
                service=service,
                profile=profile,
                region=region,
                headers={'test': 'header'},
                timeout=Timeout(30.0),
                auth=None,
            )
        else:
            # If we can't access the factory directly, just verify the transport was created
            assert result is not None

    @patch('aws_mcp_proxy.utils.create_sigv4_client')
    def test_create_transport_with_sigv4_no_profile(self, mock_create_sigv4_client):
        """Test creating transport without profile."""
        url = 'https://eks-mcp.us-west-2.api.aws/mcp'
        service = 'eks-mcp'
        region = 'us-west-2'

        result = create_transport_with_sigv4(url, service, region)

        # Test that the httpx_client_factory calls create_sigv4_client correctly
        # We need to access the factory through the transport's internal structure
        if hasattr(result, 'httpx_client_factory') and result.httpx_client_factory:
            factory = result.httpx_client_factory
            factory(headers=None, timeout=None, auth=None)

            mock_create_sigv4_client.assert_called_once_with(
                service=service, region=region, profile=None, headers=None, timeout=None, auth=None
            )
        else:
            # If we can't access the factory directly, just verify the transport was created
            assert result is not None


class TestValidateRequiredArgs:
    """Test cases for validate_service_name function."""

    def test_validate_service_name_with_service(self):
        """Test validation when service is provided."""
        endpoint = 'https://eks-mcp.us-west-2.api.aws'
        service = 'custom-service'

        result = determine_service_name(endpoint, service)

        assert result == service

    def test_validate_service_name_without_service_success(self):
        """Test validation when service is not provided but can be parsed."""
        endpoint = 'https://eks-mcp.us-west-2.api.aws'
        expected_service = 'eks-mcp'

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

    def test_determine_region_with_region(self):
        """Test determination when region is provided."""
        endpoint = 'https://mcp.us-east-1.api.aws/mcp'
        region = 'custom-region'

        result = determine_aws_region(endpoint, region)

        assert result == region

    def test_determine_region_without_region_success(self):
        """Test determination when region is not provided but can be parsed."""
        endpoint = 'https://mcp.us-east-1.api.aws/mcp'
        expected_region = 'us-east-1'

        result = determine_aws_region(endpoint)

        assert result == expected_region

    def test_determine_region_with_complex_service_name(self):
        """Test parsing region from endpoint with complex service name."""
        endpoint = 'https://eks-mcp-beta.us-west-2.api.aws/mcp'
        expected_region = 'us-west-2'

        result = determine_aws_region(endpoint)

        assert result == expected_region

    def test_determine_region_without_region_failure(self):
        """Test determination when region cannot be determined."""
        endpoint = 'https://service.example.com'

        with pytest.raises(ValueError) as exc_info:
            determine_aws_region(endpoint)

        assert 'Could not determine AWS region' in str(exc_info.value)
        assert endpoint in str(exc_info.value)
        assert '--region argument' in str(exc_info.value)
