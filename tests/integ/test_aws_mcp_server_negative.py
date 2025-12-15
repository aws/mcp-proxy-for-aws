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

"""Negative integration tests for AWS MCP Server at https://aws-mcp.us-east-1.api.aws/mcp."""

import boto3
import fastmcp
import logging
import pytest
from fastmcp.client import StdioTransport


logger = logging.getLogger(__name__)


@pytest.mark.asyncio(loop_scope='module')
async def test_expired_credentials():
    """Test that expired credentials are properly rejected.

    This test uses real AWS credentials but modifies the session token to simulate
    an expired token, which should result in an 'expired token' error message.

    This test will:
    - PASS when expired credentials are rejected with appropriate error
    - FAIL if the modified credentials somehow work
    """
    # Get real credentials from boto3
    session = boto3.Session()
    creds = session.get_credentials()

    # Use real access key and secret, but modify the token to simulate expiration by changing a few characters
    expired_token = 'EXPIRED_TOKEN_12345'

    expired_client = fastmcp.Client(
        StdioTransport(
            command='mcp-proxy-for-aws',
            args=[
                'https://aws-mcp.us-east-1.api.aws/mcp',
                '--log-level',
                'DEBUG',
                '--region',
                'us-east-1',
            ],
            env={
                'AWS_REGION': 'us-east-1',
                'AWS_ACCESS_KEY_ID': creds.access_key,
                'AWS_SECRET_ACCESS_KEY': creds.secret_key,
                'AWS_SESSION_TOKEN': expired_token,
            },
        ),
        timeout=30.0,
    )

    exception_raised = False
    exception_message = ''

    try:
        async with expired_client:
            response = await expired_client.call_tool('aws___list_regions')
            logger.info('Tool call completed without exception. Response: %s', response)
    except Exception as e:
        exception_raised = True
        exception_message = str(e)
        logger.info('Exception raised as expected: %s: %s', type(e).__name__, exception_message)

    # Assert that an exception was raised (credentials are invalid)
    assert exception_raised, (
        'Expected authentication exception with invalid credentials, but tool call succeeded.'
    )

    # Verify the exception is related to authentication/credentials
    error_message_lower = exception_message.lower()
    auth_error_patterns = [
        'credential',
        'authentication',
        'authorization',
        'access denied',
        'unauthorized',
        'invalid',
        'expired',
        'signature',
        '401',
    ]

    assert any(pattern in error_message_lower for pattern in auth_error_patterns), (
        f"Exception was raised but doesn't appear to be authentication-related. "
        f'Expected one of {auth_error_patterns}, but got: {exception_message[:200]}'
    )

    logger.info('Test passed: Invalid credentials correctly rejected')
