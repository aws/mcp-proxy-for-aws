# Change Spec: Deferred Auth Support in mcp-proxy-for-aws

## Problem
HTTP 401 responses and WWW-Authenticate headers from the upstream AWS MCP server
are not surfaced to MCP clients. Clients see generic "Connection closed" or timeout errors.

The upstream AWS MCP server implements deferred (step-up) auth:
- Public tools work without auth
- Authenticated tools (call_aws, run_script) return HTTP 401 + `WWW-Authenticate: Bearer resource_metadata="/.well-known/oauth-protected-resource", scope="aws.sigv4"` when credentials are missing/invalid

The proxy currently swallows these 401s at multiple layers.

## Changes

### 1. proxy.py — Connection-time 401 handling
In `AWSMCPProxyClient._connect()`, add specific handling for HTTP 401 responses
**before** the existing generic JSON-RPC error parsing. When a 401 is received,
extract the `WWW-Authenticate` header and raise an `McpError` with code `-32001`
and a data payload containing `status_code` and `www_authenticate`. This uses the
same error code the upstream server uses for authentication failures.

### 2. proxy.py — Runtime tool-call 401 handling
Override `call_tool()` in `AWSProxyToolManager` to catch `McpError` and
`httpx.HTTPStatusError` exceptions from upstream tool calls. When a 401-related
error is detected (either an `httpx.HTTPStatusError` with status 401, or an
`McpError` with `status_code: 401` in its data), convert it to a `ToolError`
containing the `WWW-Authenticate` value. This prevents 401s from crashing the
MCP SDK transport task and instead returns a structured tool error to the client.

### 3. sigv4_helper.py — Improved 401 logging
In `_handle_error_response()`, add specific 401 handling before the generic error
logging. When a 401 is received, log at WARNING level with the `WWW-Authenticate`
header value. This provides better observability for auth failures.

## Testing
- All existing unit tests pass without modification
- New unit tests added for:
  - `_connect()` with 401 response (with and without WWW-Authenticate header)
  - `call_tool()` with McpError containing 401 data
  - `call_tool()` with httpx.HTTPStatusError 401
  - `call_tool()` re-raising non-401 errors unchanged
  - `_handle_error_response()` with 401 response

## Backward Compatibility
- All changes are additive — existing error handling paths remain unchanged
- Non-401 HTTP errors continue through the existing JSON-RPC parsing logic
- Valid auth flows are unaffected (no changes to the success path)
- The `-32001` error code is already used by the upstream server for auth failures
- The `ToolError` is a standard FastMCP exception that the SDK handles gracefully
