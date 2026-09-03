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

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools import Tool


logger = logging.getLogger(__name__)


class EmptyToolsRetryMiddleware(Middleware):
    """Retry transient empty tools/list responses when retries are enabled."""

    def __init__(
        self,
        retries: int,
        backoff_seconds: float = 1.0,
        logger: logging.Logger | None = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            retries: Number of retries for empty tools/list responses.
            backoff_seconds: Base delay between retry attempts.
            logger: Logger used for warnings.
        """
        self.retries = retries
        self.backoff_seconds = backoff_seconds
        self.logger = logger or logging.getLogger(__name__)

    async def on_list_tools(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Sequence[Tool]]],
    ) -> Sequence[Tool]:
        """Retry tools/list when upstream returns an empty list."""
        attempt = 0
        while True:
            tools = await call_next(context)
            if len(tools) > 0 or attempt >= self.retries:
                if len(tools) == 0:
                    self.logger.warning(
                        'tools/list returned no tools after %s attempt(s)',
                        attempt + 1,
                    )
                return tools

            attempt += 1
            self.logger.warning(
                'tools/list returned no tools; retrying (%s/%s)',
                attempt,
                self.retries,
            )
            await asyncio.sleep(self.backoff_seconds * attempt)
