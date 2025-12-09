"""Negative integration tests for AWS MCP Server at https://aws-mcp.us-east-1.api.aws/mcp."""

import fastmcp
import logging
import pytest
import boto3
from fastmcp.client import StdioTransport
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@pytest.mark.asyncio(loop_scope="module")
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
    expired_token = creds.token[:-20] + "EXPIRED_TOKEN_12345"

    expired_client = fastmcp.Client(
        StdioTransport(
            command="mcp-proxy-for-aws",
            args=[
                "https://aws-mcp.us-east-1.api.aws/mcp",
                "--log-level",
                "DEBUG",
                "--region",
                "us-east-1",
            ],
            env={
                "AWS_REGION": "us-east-1",
                "AWS_ACCESS_KEY_ID": creds.access_key,
                "AWS_SECRET_ACCESS_KEY": creds.secret_key,
                "AWS_SESSION_TOKEN": expired_token,
            },
        ),
        timeout=30.0,
    )

    exception_raised = False
    exception_message = None

    try:
        async with expired_client:
            response = await expired_client.call_tool("aws___list_regions")
            logger.info(f"Tool call completed without exception: is_error={response.is_error}")
    except Exception as e:
        exception_raised = True
        exception_message = str(e)
        logger.info(f"Exception raised as expected: {type(e).__name__}: {exception_message}")

    # Assert that an exception was raised (credentials are invalid)
    assert exception_raised, (
        f"Expected authentication exception with invalid credentials, " f"but tool call succeeded."
    )

    # Verify the exception is related to authentication/credentials
    error_message_lower = exception_message.lower()
    auth_error_patterns = [
        "credential",
        "authentication",
        "authorization",
        "access denied",
        "unauthorized",
        "invalid",
        "expired",
        "signature",
        "401",
    ]

    assert any(pattern in error_message_lower for pattern in auth_error_patterns), (
        f"Exception was raised but doesn't appear to be authentication-related. "
        f"Expected one of {auth_error_patterns}, but got: {exception_message[:200]}"
    )

    logger.info(f"Test passed: Invalid credentials correctly rejected")
