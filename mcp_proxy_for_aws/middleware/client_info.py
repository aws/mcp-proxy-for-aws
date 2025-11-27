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

import logging
from collections.abc import Awaitable, Callable
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp import types as mt
from mcp_proxy_for_aws.context import set_client_info


logger = logging.getLogger(__name__)


class ClientInfoMiddleware(Middleware):
    """Middleware to capture client_info from initialize method."""

    async def on_initialize(
        self,
        context: MiddlewareContext[mt.InitializeRequest],
        call_next: Callable[[MiddlewareContext[mt.InitializeRequest]], Awaitable[None]],
    ) -> None:
        """Capture client_info from initialize request."""
        if context.message.params and context.message.params.clientInfo:
            info = context.message.params.clientInfo
            set_client_info(info)
            logger.info('Captured client_info: name=%s, version=%s', info.name, info.version)

        await call_next(context)
