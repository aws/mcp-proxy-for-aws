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
from httpx._content import ByteStream
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


async def _handle_error_response(response: httpx.Response) -> None:
    """Event hook to handle HTTP error responses and extract details.

    This function is called for every HTTP response to check for errors
    and provide more detailed error information when requests fail.

    Args:
        response: The HTTP response object

    Raises:
        httpx.HTTPStatusError: With enhanced error message containing response details
    """
    if response.is_error:
        try:
            # Read response content to extract error details
            await response.aread()
        except Exception as e:
            logger.error('Failed to read response: %s', e)

        # Try to extract error details with fallbacks
        error_msg = ''
        try:
            # Try to parse JSON error details
            error_details = response.json()
            logger.error('HTTP %d Error Details: %s', response.status_code, error_details)
            error_msg = f'HTTP {response.status_code}: {error_details} for url {response.url}'
        except Exception:
            # If JSON parsing fails, use response text or status code
            try:
                response_text = response.text
                logger.error('HTTP %d Error: %s', response.status_code, response_text)
                error_msg = f'HTTP {response.status_code}: {response_text} for url {response.url}'
            except Exception:
                # Fallback to just status code and URL
                logger.error('HTTP %d Error for url %s', response.status_code, response.url)
                error_msg = f'HTTP {response.status_code} Error for url {response.url}'

        # Raise the status error with enhanced message
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            # Replace the error message and throw HTTP error
            if error_msg:
                raise httpx.HTTPStatusError(
                    message=error_msg, request=e.request, response=e.response
                )
            raise e


async def _inject_metadata_hook(metadata: Dict[str, Any], request: httpx.Request) -> None:
    """Request hook to inject metadata into MCP calls.

    Args:
        metadata: Dictionary of metadata to inject into _meta field
        request: The HTTP request object
    """
    logger.info('=== Outgoing Request ===')
    logger.info('URL: %s', request.url)
    logger.info('Method: %s', request.method)

    # Try to inject metadata if it's a JSON-RPC/MCP request
    if request.content and metadata:
        try:
            # Parse the request body
            body = json.loads(await request.aread())

            # Check if it's a JSON-RPC request
            if isinstance(body, dict) and 'jsonrpc' in body:
                # Ensure params exists
                # if 'params' not in body:
                #     body['params'] = {}

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
                    logger.info('Replacing non-dict _meta value with injected metadata')
                    body['params']['_meta'] = metadata

                # Create new content
                del request._content
                new_content = json.dumps(body).encode('utf-8')

                request.stream = ByteStream(new_content)
                request.headers['Content-Length'] = str(len(new_content))

                logger.info('Injected metadata into _meta: %s', body['params']['_meta'])

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Not a JSON request or invalid format, skip metadata injection
            logger.error('Skipping metadata injection: %s', e)


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


def create_sigv4_auth(service: str, region: str, profile: Optional[str] = None) -> SigV4HTTPXAuth:
    """Create SigV4 authentication for AWS requests.

    Args:
        service: AWS service name for SigV4 signing
        profile: AWS profile to use (optional)
        region: AWS region (defaults to AWS_REGION env var or us-east-1)

    Returns:
        SigV4HTTPXAuth instance

    Raises:
        ValueError: If credentials cannot be obtained
    """
    # Create session and get credentials
    session = create_aws_session(profile)
    credentials = session.get_credentials()

    # Create SigV4Auth with explicit credentials
    sigv4_auth = SigV4HTTPXAuth(
        credentials=credentials,
        service=service,
        region=region,
    )

    logger.info("Created SigV4 authentication for service '%s' in region '%s'", service, region)
    return sigv4_auth


def create_sigv4_client(
    service: str,
    region: str,
    timeout: Optional[httpx.Timeout] = None,
    profile: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    auth: Optional[httpx.Auth] = None,
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
        auth: Auth parameter (ignored as we provide our own)
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

    # Create SigV4 auth
    sigv4_auth = create_sigv4_auth(service, region, profile)

    # Create the client with SigV4 auth and error handling event hook
    logger.info("Creating httpx.AsyncClient with SigV4 authentication for service '%s'", service)

    return httpx.AsyncClient(
        auth=sigv4_auth,
        **client_kwargs,
        event_hooks={
            'response': [_handle_error_response],
            'request': [partial(_inject_metadata_hook, metadata or {})],
        },
    )
