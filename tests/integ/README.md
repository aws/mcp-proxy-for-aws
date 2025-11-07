## Integration tests

This folder contains the Integration tests for the mcp-proxy-for-aws. To help with testing, we have also created a simple MCP Server and MCP Client to mimic a real scenario.

* `mcp/simple_mcp_server/mcp_server.py` - A simple MCP Server which supports different features to mimic the Customers remote MCP Server
* `mcp/simple_mcp_client.py` - A simple MCP Client which uses the proxy to connect to a remote HTTP MCP Server
* `test_proxy_simple_mcp_server.py` - Actual tests which uses the above to validate the Proxy is working correctly

## How to use?

These tests can be run against two types of Remote MCP Servers

1. Hosted in Bedrock AgentCore Runtime
1. Against a Remote URL endpoint

#### Hosted in Bedrock AgentCore Runtime

The Simple MCP Server is ready to easily install on AgentCore Bedrock. It is recommended to follow this testing path to ensure sigv4 is working correctly.

The following instructions to install the Simple MCP Server came from [[Deploy MCP servers in AgentCore Runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp.html#runtime-mcp-create-server)].

```bash
# Update Simple MCP Server to use stateless-http
# - Edit mcp/simple_mcp_server/mcp_server.py
# - Change "stateless_http=False" to "stateless_http=True"

# Install AgentCore CLI
pip install bedrock-agentcore-starter-toolkit

# CD into simple_mcp_server folder
cd integ/mcp/simple_mcp_server

# Create ECR image from simple server
# The default options will work (OAuth is not required)
agentcore configure -e mcp_server.py --protocol MCP

# Upload ECR image and host MCP Server
agentcore launch --auto-update-on-conflict

# Set the ARN which was posted to the Terminal
export AGENTCORE_RUNTIME_ARN={newly-created-mcp-server}
```

Run test against the AgentCore hosted MCP Server

```bash
uv run pytest -m integ
```


#### Against a Remote URL endpoint

To make testing locally faster, you can also run tests against a remote URL. Since this endpoint might not be hosted on AWS, the sigv4 code path might not be fully tested.

Only use this testing path to ensure the MCP Features are working correctly.

```bash
# Run MCP Server locally
uv run tests/integ/mcp/simple_mcp_server/mcp_server.py

# Set endpoint to test against
export REMOTE_ENDPOINT_URL=http://127.0.0.1:8000/mcp
```

```bash
uv run pytest -m integ
```
