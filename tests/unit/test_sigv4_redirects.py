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

"""SigV4 must read request streams before signing and after safe redirects."""

import hmac
import http.server
import httpx2
import pytest
import re
import threading
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from mcp.shared._httpx_utils import stream_within_origin
from mcp_proxy_for_aws.sigv4_helper import SigV4HTTPXAuth


@pytest.fixture
def recording_endpoint():
    """Serve safe local redirects and record the actual request body."""
    records: list[tuple[str, bytes, bool]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        """Receive one bounded body on an isolated loopback endpoint."""

        def do_POST(self) -> None:
            """Redirect once or return an empty success response."""
            body = self.rfile.read(int(self.headers.get('content-length', '0')))
            authorization = self.headers['Authorization']
            signed_names = authorization.split('SignedHeaders=')[1].split(',')[0].split(';')
            request = AWSRequest(
                method='POST',
                url=f'http://{self.headers["Host"]}{self.path}',
                data=body,
                headers={name: self.headers[name] for name in signed_names},
            )
            request.context['timestamp'] = self.headers['X-Amz-Date']
            signer = SigV4Auth(
                Credentials('synthetic', 'synthetic-secret'), 'execute-api', 'us-east-1'
            )
            expected = signer.signature(
                signer.string_to_sign(request, signer.canonical_request(request)), request
            )
            signature = re.search(r'Signature=([a-f0-9]+)', authorization)
            assert signature is not None
            records.append((self.path, body, hmac.compare_digest(expected, signature[1])))
            status = int(self.path[1:]) if self.path in {'/307', '/308'} else 200
            self.send_response(status)
            if status != 200:
                self.send_header('Location', '/target')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            """Keep the synthetic fixture quiet."""

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize('status', [200, 307, 308])
async def test_signed_requests_survive_same_origin_redirects(
    recording_endpoint, status: int
) -> None:
    """The SDK's permitted redirects preserve the signed POST body."""
    endpoint, records = recording_endpoint
    auth = SigV4HTTPXAuth(Credentials('synthetic', 'synthetic-secret'), 'execute-api', 'us-east-1')
    async with httpx2.AsyncClient(auth=auth, trust_env=False) as client:
        async with stream_within_origin(
            client, 'POST', f'{endpoint}/{status}', content=b'synthetic-body'
        ) as response:
            assert response.status_code == 200
    expected_paths = [f'/{status}'] if status == 200 else [f'/{status}', '/target']
    assert records == [(path, b'synthetic-body', True) for path in expected_paths]
