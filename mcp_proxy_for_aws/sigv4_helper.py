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

"""SigV4 Helper for AWS request signing functionality."""

import boto3
import httpx
import json
import logging
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from functools import partial
from typing import Any, Dict, Generator, Optional


logger = logging.getLogger(__name__)


class SigV4HTTPXAuth(httpx.Auth):
    """HTTPX Auth class that signs requests with AWS SigV4."""

    def __init__(
        self,
        credentials: Credentials,
        service: str,
        region: str,
    ):
        """Initialize SigV4HTTPXAuth.

        Args:
            credentials: AWS credentials to use for signing
            service: AWS service name to sign requests for
            region: AWS region to sign requests for
        """
        self.credentials = credentials
        self.service = service
        self.region = region
        self.signer = SigV4Auth(credentials, service, region)

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        """Signs the request with SigV4 and adds the signature to the request headers."""
        # Create an AWS request
        headers = dict(request.headers)
        # Header 'connection' = 'keep-alive' is not used in calculating the request
        # signature on the server-side, and results in a signature mismatch if included
        headers.pop('connection', None)  # Remove if present, ignore if not

        aws_request = AWSRequest(
            method=request.method,
            url=str(request.url),
            data=request.content,
            headers=headers,
        )

        # Sign the request with SigV4
        self.signer.add_auth(aws_request)

        # Add the signature header to the original request
        request.headers.update(dict(aws_request.headers))

        yield request


def create_aws_session(profile: Optional[str] = None) -> boto3.Session:
    """Create an AWS session with optional profile.

    Args:
        profile: AWS profile to use (optional)

    Returns:
        boto3.Session instance

    Raises:
        ValueError: If session creation fails or no credentials found
    """
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    except Exception as e:
        raise ValueError(f"Failed to create AWS session with profile '{profile}': {e}")

    # Verify credentials are available
    credentials = session.get_credentials()
    if not credentials:
        profile_msg = f" with profile '{profile}'" if profile else ''
        raise ValueError(
            f'No AWS credentials found{profile_msg}. '
            "Please configure your AWS credentials using 'aws configure' or environment variables."
        )

    return session


def create_sigv4_client(
    service: str,
    region: str,
    timeout: Optional[httpx.Timeout] = None,
    profile: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with SigV4 authentication.

    Args:
        service: AWS service name for SigV4 signing
        profile: AWS profile to use (optional)
        region: AWS region (optional, defaults to AWS_REGION env var or us-east-1)
        timeout: Timeout configuration for the HTTP client
        headers: Headers to include in requests
        metadata: Metadata to inject into MCP _meta field
        **kwargs: Additional arguments to pass to httpx.AsyncClient

    Returns:
        httpx.AsyncClient with SigV4 authentication
    """
    # Create a copy of kwargs to avoid modifying the passed dict
    client_kwargs = {
        'follow_redirects': True,
        'timeout': timeout,
        'limits': httpx.Limits(max_keepalive_connections=1, max_connections=5),
        **kwargs,
    }

    # Add headers if provided
    default_headers = {'Accept': 'application/json, text/event-stream'}
    if headers is not None:
        default_headers.update(headers)
    client_kwargs['headers'] = default_headers

    logger.info(
        'Creating httpx.AsyncClient with custom headers: %s', client_kwargs.get('headers', {})
    )

    logger.info("Creating httpx.AsyncClient with SigV4 request hooks for service '%s'", service)

    return httpx.AsyncClient(
        **client_kwargs,
        event_hooks={
            'response': [_handle_error_response],
            'request': [
                partial(_inject_metadata_hook, metadata or {}),
                partial(_sign_request_hook, region, service, profile),
            ],
        },
    )


async def _handle_error_response(response: httpx.Response) -> None:
    """Event hook to handle HTTP error responses and extract details.

    This function is called for every HTTP response to check for errors
    and provide more detailed error information when requests fail.

    Args:
        response: The HTTP response object

    Raises:
        No raises. let the mcp http client handle the errors.
    """
    if response.is_error:
        # warning only because the SDK logs error
        log_level = logging.WARNING
        if (
            # The server MAY respond 405 to GET (SSE) and DELETE (session).
            response.status_code == 405 and response.request.method in ('GET', 'DELETE')
        ) or (
            # The server MAY terminate the session at any time, after which it MUST
            # respond to requests containing that session ID with HTTP 404 Not Found.
            response.status_code == 404 and response.request.method == 'POST'
        ):
            log_level = logging.DEBUG

        try:
            # read the content and settle the response content. required to get body (.json(), .text)
            await response.aread()
        except Exception as e:
            logger.debug('Failed to read response: %s', e)
            # do nothing and let the client and SDK handle the error
            return

        # Try to extract error details with fallbacks
        try:
            # Try to parse JSON error details
            error_details = response.json()
            logger.log(log_level, 'HTTP %d Error Details: %s', response.status_code, error_details)
        except Exception:
            # If JSON parsing fails, use response text or status code
            try:
                response_text = response.text
                logger.log(log_level, 'HTTP %d Error: %s', response.status_code, response_text)
            except Exception:
                # Fallback to just status code and URL
                logger.log(
                    log_level, 'HTTP %d Error for url %s', response.status_code, response.url
                )


async def _sign_request_hook(
    region: str,
    service: str,
    profile: Optional[str],
    request: httpx.Request,
) -> None:
    """Request hook to sign HTTP requests with AWS SigV4.

    This hook signs the request with AWS SigV4 credentials and adds signature headers.

    This should be the last hook called to ensure the signature includes any modifications.

    Args:
        region: AWS region for SigV4 signing
        service: AWS service name for SigV4 signing
        profile: AWS profile to use (optional)
        request: The HTTP request object to sign (modified in-place)
    """
    # Set Content-Length for signing
    request.headers['Content-Length'] = str(len(request.content))

    # Get AWS credentials
    session = create_aws_session(profile)
    credentials = session.get_credentials()
    logger.info('Signing request with credentials for access key: %s', credentials.access_key)

    # Create SigV4 auth and use its signing logic
    auth = SigV4HTTPXAuth(credentials, service, region)

    # Call auth_flow to sign the request (it modifies request in-place)
    auth_flow = auth.auth_flow(request)
    next(auth_flow)  # Execute the generator to perform signing

    logger.debug('Request headers after signing: %s', request.headers)


async def _inject_metadata_hook(metadata: Dict[str, Any], request: httpx.Request) -> None:
    """Request hook to inject metadata into MCP calls.

    Args:
        metadata: Dictionary of metadata to inject into _meta field
        request: The HTTP request object
    """
    logger.debug('=== Outgoing Request ===')
    logger.debug('URL: %s', request.url)
    logger.debug('Method: %s', request.method)

    # Try to inject metadata if it's a JSON-RPC/MCP request
    if request.content and metadata:
        try:
            # Parse the request body
            body = json.loads(await request.aread())

            # Check if it's a JSON-RPC request
            if isinstance(body, dict) and 'jsonrpc' in body:
                # Ensure _meta exists in params
                if '_meta' not in body['params']:
                    body['params']['_meta'] = {}

                # Get existing metadata
                existing_meta = body['params']['_meta']

                # Merge metadata (existing takes precedence)
                if isinstance(existing_meta, dict):
                    # Check for conflicting keys before merge
                    conflicting_keys = set(metadata.keys()) & set(existing_meta.keys())
                    if conflicting_keys:
                        for key in conflicting_keys:
                            logger.warning(
                                'Metadata key "%s" already exists in _meta. '
                                'Keeping existing value "%s", ignoring injected value "%s"',
                                key,
                                existing_meta[key],
                                metadata[key],
                            )
                    body['params']['_meta'] = {**metadata, **existing_meta}
                else:
                    logger.debug('Overwriting _meta value with injected metadata')
                    body['params']['_meta'] = metadata

                # Create new content with updated metadata
                new_content = json.dumps(body).encode('utf-8')

                # Update the request with new content
                request.stream = httpx.ByteStream(new_content)
                request._content = new_content

                logger.info('Injected metadata into _meta: %s', body['params']['_meta'])

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Not a JSON request or invalid format, skip metadata injection
            logger.debug('Skipping metadata injection: %s', e)
