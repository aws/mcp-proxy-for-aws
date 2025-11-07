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
import logging
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from typing import Any, Dict, Generator, Optional

logger = logging.getLogger(__name__)

try:
    from botocore.auth import SigV4Auth as SigV4AAuth
    SIGV4A_AVAILABLE = True
except ImportError:
    SIGV4A_AVAILABLE = False
    logger.warning(
        "SigV4A auto-detection disabled: botocore >= 1.31.0 required. "
        "Install with: pip install --upgrade botocore"
    )


class SigV4HTTPXAuth(httpx.Auth):
    """HTTPX Auth class that signs requests with AWS SigV4 with automatic SigV4A fallback.
    
    This class automatically detects when an endpoint requires SigV4A and retries with
    the appropriate signing method. This provides seamless support for both regional
    and global AWS endpoints without requiring explicit configuration.
    """

    def __init__(
        self,
        credentials: Credentials,
        service: str,
        region: str,
    ):
        """Initialize SigV4HTTPXAuth with auto-detection support.

        Args:
            credentials: AWS credentials to use for signing
            service: AWS service name to sign requests for
            region: AWS region to sign requests for
        """
        self.credentials = credentials
        self.service = service
        self.region = region
        self.use_sigv4a = False  # Start with SigV4, upgrade to SigV4A if needed
        self.sigv4_signer = SigV4Auth(credentials, service, region)
        self.sigv4a_signer = None  # Lazy initialization

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        """Signs the request with SigV4 and automatically retries with SigV4A if needed."""
        # Try with current signer (SigV4 or SigV4A)
        signer = self.sigv4a_signer if self.use_sigv4a else self.sigv4_signer

        # Sign and send request
        signed_request = self._sign_request(request, signer)
        response = yield signed_request

        # Check if we need to retry with SigV4A
        if not self.use_sigv4a and self._requires_sigv4a(response):
            logger.info(
                'Endpoint %s requires SigV4A (detected from %s response), retrying with SigV4A authentication',
                request.url,
                response.status_code
            )
            self.use_sigv4a = True

            # Initialize SigV4A signer if needed
            if self.sigv4a_signer is None:
                if not SIGV4A_AVAILABLE:
                    logger.error(
                        'Authentication failed: Cannot retry with SigV4A for endpoint %s. '
                        'SigV4A requires botocore >= 1.31.0. '
                        'Install with: pip install --upgrade botocore',
                        request.url
                    )
                    return
                self.sigv4a_signer = SigV4AAuth(self.credentials, self.service, '*')

            # Retry with SigV4A
            signed_request = self._sign_request(request, self.sigv4a_signer)
            response = yield signed_request
            
            # Check if SigV4A retry also failed
            if response.is_error and response.status_code in (401, 403):
                logger.error(
                    'Authentication failed for endpoint %s with both SigV4 and SigV4A (status: %s). '
                    'Check credentials and endpoint configuration.',
                    request.url,
                    response.status_code
                )
        elif self.use_sigv4a and response.is_error and response.status_code in (401, 403):
            # Already using SigV4A and still failing
            logger.error(
                'Authentication failed for endpoint %s with SigV4A (status: %s). '
                'Check credentials and endpoint configuration.',
                request.url,
                response.status_code
            )

    def _requires_sigv4a(self, response: httpx.Response) -> bool:
        """Check if response indicates SigV4A is required.

        Args:
            response: The HTTP response to check

        Returns:
            True if response indicates SigV4A is required, False otherwise
        """
        # Check for specific error codes/messages that indicate SigV4A requirement
        if response.status_code == 403:
            try:
                error_body = response.json()
                # Check for AWS error codes that indicate SigV4A requirement
                error_code = error_body.get('__type', '') or error_body.get('Code', '')
                if 'SignatureDoesNotMatch' in error_code or 'InvalidSignature' in error_code:
                    # Additional heuristic: check error message for SigV4A hints
                    message = error_body.get('message', '') or error_body.get('Message', '')
                    if 'sigv4a' in message.lower() or 'multi-region' in message.lower():
                        return True
            except Exception:
                pass
        return False

    def _sign_request(self, request: httpx.Request, signer) -> httpx.Request:
        """Sign request with given signer.

        Args:
            request: The HTTP request to sign
            signer: The AWS signer to use (SigV4Auth or SigV4AAuth)

        Returns:
            The signed HTTP request
        """
        headers = dict(request.headers)
        # Header 'connection' = 'keep-alive' is not used in calculating the request
        # signature on the server-side, and results in a signature mismatch if included
        headers.pop('connection', None)

        aws_request = AWSRequest(
            method=request.method,
            url=str(request.url),
            data=request.content,
            headers=headers,
        )

        signer.add_auth(aws_request)
        request.headers.update(dict(aws_request.headers))
        return request


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

        # Determine signing method from Authorization header
        signing_method = "Unknown"
        auth_header = response.request.headers.get('Authorization', '')
        if 'AWS4-ECDSA-P256-SHA256' in auth_header:
            signing_method = "SigV4A"
        elif 'AWS4-HMAC-SHA256' in auth_header:
            signing_method = "SigV4"

        # Try to extract error details with fallbacks
        try:
            # Try to parse JSON error details
            error_details = response.json()
            logger.log(
                log_level,
                'HTTP %d Error Details (signing method: %s): %s',
                response.status_code,
                signing_method,
                error_details
            )
        except Exception:
            # If JSON parsing fails, use response text or status code
            try:
                response_text = response.text
                logger.log(
                    log_level,
                    'HTTP %d Error (signing method: %s): %s',
                    response.status_code,
                    signing_method,
                    response_text
                )
            except Exception:
                # Fallback to just status code and URL
                logger.log(
                    log_level,
                    'HTTP %d Error for url %s (signing method: %s)',
                    response.status_code,
                    response.url,
                    signing_method
                )


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


def create_sigv4_auth(
    service: str,
    region: str,
    profile: Optional[str] = None,
) -> httpx.Auth:
    """Create SigV4 authentication for AWS requests with SigV4A auto-detection enabled by default.

    Args:
        service: AWS service name for SigV4 signing
        region: AWS region
        profile: AWS profile to use (optional)

    Returns:
        SigV4HTTPXAuth instance with auto-detection enabled

    Raises:
        ValueError: If credentials cannot be obtained
    """
    # Create session and get credentials
    session = create_aws_session(profile)
    credentials = session.get_credentials()

    # Always create SigV4HTTPXAuth which includes auto-detection logic
    auth = SigV4HTTPXAuth(
        credentials=credentials,
        service=service,
        region=region,
    )
    
    if not SIGV4A_AVAILABLE:
        logger.info(
            "Created SigV4 authentication for service '%s' in region '%s' "
            "(SigV4A auto-detection unavailable - install botocore >= 1.31.0 for full support)",
            service,
            region,
        )
    else:
        logger.info(
            "Created SigV4 authentication with SigV4A auto-detection for service '%s' in region '%s'",
            service,
            region,
        )

    return auth


def create_sigv4_client(
    service: str,
    region: str,
    timeout: Optional[httpx.Timeout] = None,
    profile: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    auth: Optional[httpx.Auth] = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with SigV4 authentication and SigV4A auto-detection enabled by default.

    Args:
        service: AWS service name for SigV4 signing
        region: AWS region
        timeout: Timeout configuration for the HTTP client
        profile: AWS profile to use (optional)
        headers: Headers to include in requests
        auth: Auth parameter (ignored as we provide our own)
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

    # Create SigV4 auth with auto-detection enabled by default
    sigv4_auth = create_sigv4_auth(service, region, profile)

    # Create the client with SigV4 auth and error handling event hook
    logger.info(
        "Creating httpx.AsyncClient with SigV4 authentication (auto-detection enabled) for service '%s'",
        service,
    )

    return httpx.AsyncClient(
        auth=sigv4_auth,
        **client_kwargs,
        event_hooks={'response': [_handle_error_response]},
    )
