# MCP Proxy for AWS

## Overview

The **MCP Proxy for AWS** package provides two ways to connect AI applications to MCP servers on AWS:

1. **Using it as a proxy** - It becomes a lightweight, client-side bridge between MCP clients (AI assistants like Claude Desktop, Amazon Q Developer CLI) and MCP servers on AWS. (See [MCP Proxy](#mcp-proxy))
2. **Using it as a library** - Programmatically connect popular AI agent frameworks (LangChain, LlamaIndex, Strands Agents, etc.) to MCP servers on AWS. (See [Programmatic Access](#programmatic-access))


### When Do You Need This Package?

- You want to connect to **MCP servers on AWS** (e.g., using Amazon Bedrock AgentCore) that use AWS IAM authentication (SigV4) instead of OAuth
- You're using MCP clients (like Claude Desktop, Amazon Q Developer CLI) that don't natively support AWS IAM authentication
- You're building AI agents with popular frameworks like LangChain, Strands Agents, LlamaIndex, etc., that need to connect to MCP servers on AWS
- You want to avoid building custom SigV4 request signing logic yourself

### How This Package Helps

**The Problem:** The official MCP specification supports OAuth-based authentication, but MCP servers on AWS can also use AWS IAM authentication (SigV4). Standard MCP clients don't know how to sign requests with AWS credentials.

**The Solution:** This package bridges that gap by:
- **Handling SigV4 authentication automatically** - Uses your local AWS credentials (from AWS CLI, environment variables, or IAM roles) to sign all MCP requests using [SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)
- **Supporting global endpoints with SigV4A** - Automatically detects and upgrades to [SigV4A](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html) for multi-region and global AWS endpoints
- **Providing seamless integration** - Works with existing MCP clients and frameworks
- **Eliminating custom code** - No need to build your own MCP client with SigV4 signing logic

### SigV4A Auto-Detection for Global Endpoints

This package automatically handles authentication for both regional and global AWS endpoints:

**Regional Endpoints (SigV4):**
- Standard AWS endpoints tied to a specific region (e.g., `https://service.us-east-1.api.aws/mcp`)
- Uses AWS Signature Version 4 (SigV4) for authentication
- Region is extracted from the endpoint URL or specified explicitly

**Global Endpoints (SigV4A):**
- AWS endpoints that operate across multiple regions or globally (e.g., `https://service.global.api.aws/mcp`)
- Automatically detected based on URL patterns (`.global.`, `global.` subdomain, or `.api.aws` without region)
- Starts with SigV4 for compatibility, then automatically upgrades to SigV4A if the endpoint requires it
- No configuration changes needed when services transition from regional to global

**How Auto-Detection Works:**

1. **Endpoint Detection** - The proxy analyzes the endpoint URL to determine if it's a global endpoint
2. **Initial Request** - For global endpoints, starts with SigV4 signing (region defaults to `us-east-1`)
3. **Automatic Upgrade** - If the endpoint returns an error indicating SigV4A is required, automatically retries with SigV4A
4. **Subsequent Requests** - Once SigV4A is detected, all future requests use SigV4A signing

This approach ensures seamless compatibility as AWS services evolve from regional to global endpoints without requiring configuration updates.

## Which Feature Should I Use?

**Use as a proxy if you want to:**
- Connect MCP clients like Claude Desktop or Amazon Q Developer CLI to MCP servers on AWS with IAM credentials
- Add MCP servers on AWS to your AI assistant's configuration
- Use a command-line tool that runs as a bridge between your MCP client and AWS

**Use as a library if you want to:**
- Build AI agents programmatically using popular frameworks like LangChain, Strands Agents, or LlamaIndex
- Integrate AWS IAM-secured MCP servers directly into your Python applications
- Have fine-grained control over the MCP session lifecycle in your code

## Prerequisites

* [Install Python 3.10+](https://www.python.org/downloads/release/python-3100/)
* [Install the `uv` package manager](https://docs.astral.sh/uv/getting-started/installation/)
* AWS credentials configured (via [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html), environment variables, or IAM roles)
* (Optional, for docker users) [Install Docker Desktop](https://www.docker.com/products/docker-desktop)

---

## MCP Proxy

The MCP Proxy serves as a lightweight, client-side bridge between MCP clients (AI assistants and developer tools) and IAM-secured MCP servers on AWS. The proxy handles SigV4 authentication using local AWS credentials and provides dynamic tool discovery.

### Installation

#### Using PyPi

```bash
# Run the server
uvx mcp-proxy-for-aws@latest <SigV4 MCP endpoint URL>
```

#### Using a local repository

```bash
git clone https://github.com/aws/mcp-proxy-for-aws.git
cd mcp-proxy-for-aws
uv run mcp_proxy_for_aws/server.py <SigV4 MCP endpoint URL>
```

#### Using Docker

```bash
# Build the Docker image
docker build -t mcp-proxy-for-aws .
```

### Configuration Parameters

| Parameter	           | Description	                                                                                                                                                                                                                            | Default	                                                                    |Required	|
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|---	|
| `endpoint`	          | MCP endpoint URL (e.g., `https://your-service.us-east-1.amazonaws.com/mcp`)	                                                                                                                                                            | N/A	                                                                        |Yes	|
| ---	                 | ---	                                                                                                                                                                                                                                    | ---	                                                                        |---	|
| `--service`	         | AWS service name for SigV4 signing	                                                                                                                                                                                                     | Inferred from endpoint if not provided	                                     |No	|
| `--profile`	         | AWS profile for AWS credentials to use	                                                                                                                                                                                                 | Uses `AWS_PROFILE` environment variable if not set                          |No	|
| `--region`	          | AWS region to use	                                                                                                                                                                                                                      | Uses `AWS_REGION` environment variable if not set, defaults to `us-east-1`	 |No	|
| `--read-only`	       | Disable tools which may require write permissions (tools which DO NOT require write permissions are annotated with [`readOnlyHint=true`](https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations-readonlyhint)) | `False`	                                                                    |No	|
| `--retries`          | Configures number of retries done when calling upstream services, setting this to 0 disables retries.                                                                                                                                   | 0                                                                           |No |
| `--log-level`	       | Set the logging level (`DEBUG/INFO/WARNING/ERROR/CRITICAL`)	                                                                                                                                                                            | `INFO`	                                                                     |No	|
| `--timeout`	         | Set desired timeout in seconds across all operations	                                                                                                                                                                                   | 180	                                                                        |No	|
| `--connect-timeout`	 | Set desired connect timeout in seconds	                                                                                                                                                                                                 | 60	                                                                         |No	|
| `--read-timeout`	    | Set desired read timeout in seconds	                                                                                                                                                                                                    | 120	                                                                        |No	|
| `--write-timeout`	   | Set desired write timeout in seconds	                                                                                                                                                                                                   | 180	                                                                        |No	|

### Optional Environment Variables

Set the environment variables for the MCP Proxy for AWS:

```bash
# Credentials through profile
export AWS_PROFILE=<aws_profile>

# Credentials through parameters
export AWS_ACCESS_KEY_ID=<access_key_id>
export AWS_SECRET_ACCESS_KEY=<secret_access_key>
export AWS_SESSION_TOKEN=<session_token>

# AWS Region
export AWS_REGION=<aws_region>
```

### Setup Examples

Add the following configuration to your MCP client config file (e.g., for Amazon Q Developer CLI, edit `~/.aws/amazonq/mcp.json`):
**Note** Add your own endpoint by replacing  `<SigV4 MCP endpoint URL>`

#### Running from local - using uv

```json
{
  "mcpServers": {
    "<mcp server name>": {
      "disabled": false,
      "type": "stdio",
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/mcp_proxy_for_aws",
        "run",
        "server.py",
        "<SigV4 MCP endpoint URL>",
        "--service",
        "<your service code>",
        "--profile",
        "default",
        "--region",
        "us-east-1",
        "--read-only",
        "--log-level",
        "INFO",
      ]
    }
  }
}
```

#### Using Docker

```json
{
  "mcpServers": {
    "<mcp server name>": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "--volume",
        "/full/path/to/.aws:/app/.aws:ro",
        "mcp-proxy-for-aws",
        "<SigV4 MCP endpoint URL>"
      ],
      "env": {}
    }
  }
}
```

### Usage Examples

#### Example 1: Global Endpoint with Auto-Detection

For global AWS endpoints, the proxy automatically detects the endpoint type and handles authentication:

```json
{
  "mcpServers": {
    "global-mcp-server": {
      "command": "uv",
      "args": [
        "run",
        "mcp-proxy-for-aws",
        "https://service.global.api.aws/mcp",
        "--service",
        "my-service",
        "--profile",
        "default"
      ]
    }
  }
}
```

**What happens:**
- The proxy detects `.global.` in the URL and identifies it as a global endpoint
- Region defaults to `us-east-1` for the initial request
- Starts with SigV4 signing for compatibility
- If the endpoint requires SigV4A, automatically retries with SigV4A
- All subsequent requests use the detected signing method

#### Example 2: Regional Endpoint

For regional endpoints, the proxy uses standard SigV4 signing:

```json
{
  "mcpServers": {
    "regional-mcp-server": {
      "command": "uv",
      "args": [
        "run",
        "mcp-proxy-for-aws",
        "https://service.us-west-2.api.aws/mcp",
        "--service",
        "my-service",
        "--region",
        "us-west-2",
        "--profile",
        "default"
      ]
    }
  }
}
```

**What happens:**
- The proxy extracts `us-west-2` from the URL
- Uses SigV4 signing with the specified region
- No auto-detection needed for regional endpoints

#### Example 3: Explicit Region Override

You can explicitly specify a region even for global endpoints:

```json
{
  "mcpServers": {
    "global-mcp-server-explicit": {
      "command": "uv",
      "args": [
        "run",
        "mcp-proxy-for-aws",
        "https://service.global.api.aws/mcp",
        "--service",
        "my-service",
        "--region",
        "eu-west-1",
        "--profile",
        "default"
      ]
    }
  }
}
```

**What happens:**
- The explicit `--region` parameter takes precedence
- Uses `eu-west-1` for the initial SigV4 request
- Auto-detection still works if SigV4A is required

### Global Endpoint URL Patterns

The proxy automatically detects global endpoints based on these URL patterns:

| Pattern | Example | Detection |
|---------|---------|-----------|
| Contains `.global.` | `https://service.global.api.aws/mcp` | ✅ Global endpoint |
| Starts with `global.` | `https://global.service.api.aws/mcp` | ✅ Global endpoint |
| Ends with `.api.aws` (no region) | `https://service.api.aws/mcp` | ✅ Global endpoint |
| Contains region pattern | `https://service.us-east-1.api.aws/mcp` | ❌ Regional endpoint |

**Region Defaulting Behavior:**
- **Global endpoints**: Default to `us-east-1` region for initial SigV4 request
- **Regional endpoints**: Extract region from URL (e.g., `us-west-2` from `service.us-west-2.api.aws`)
- **Explicit region**: The `--region` parameter always takes precedence over auto-detection

**Auto-Detection and Retry Logic:**
1. **First Request**: Proxy attempts authentication with SigV4 using the determined region
2. **Error Detection**: If the endpoint returns a 403 error with signature mismatch indicating SigV4A is required
3. **Automatic Retry**: Proxy automatically retries the same request with SigV4A signing (region set to `*` for global)
4. **Caching**: Once SigV4A is detected, all subsequent requests use SigV4A without retry
5. **Logging**: Auto-detection events are logged at INFO level for visibility

**Note:** Auto-detection adds minimal overhead (one retry on first request only) and ensures compatibility as AWS services evolve from regional to global endpoints.

---

## Programmatic Access

The MCP Proxy for AWS enables programmatic integration of IAM-secured MCP servers into AI agent frameworks. The library provides authenticated transport layers that work with popular Python AI frameworks.

### Integration Patterns

The library supports two integration patterns depending on your framework:

#### Pattern 1: Client Factory Integration

**Use with:** Frameworks that accept a factory function that returns an MCP client, e.g. Strands Agents, Microsoft Agent Framework. The `aws_iam_streamablehttp_client` is passed as a factory to the framework, which handles the connection lifecycle internally.

**Example - Strands Agents:**
```python
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client

mcp_client_factory = lambda: aws_iam_streamablehttp_client(
    endpoint=mcp_url,    # The URL of the MCP server
    aws_region=region,   # The region of the MCP server
    aws_service=service  # The underlying AWS service, e.g. "bedrock-agentcore"
)

with MCPClient(mcp_client_factory) as mcp_client:
    mcp_tools = mcp_client.list_tools_sync()
    agent = Agent(tools=mcp_tools, ...)
```

**Example - Microsoft Agent Framework:**
```python
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client

mcp_client_factory = lambda: aws_iam_streamablehttp_client(
    endpoint=mcp_url,    # The URL of the MCP server
    aws_region=region,   # The region of the MCP server
    aws_service=service  # The underlying AWS service, e.g. "bedrock-agentcore"
)

mcp_tools = MCPStreamableHTTPTool(name="MCP Tools", url=mcp_url)
mcp_tools.get_mcp_client = mcp_client_factory

async with mcp_tools:
    agent = ChatAgent(tools=[mcp_tools], ...)
```

#### Pattern 2: Direct MCP Session Integration

**Use with:** Frameworks that require direct access to the MCP sessions, e.g. LangChain, LlamaIndex. The `aws_iam_streamablehttp_client` provides the authenticated transport streams, which are then used to create an MCP `ClientSession`.

**Example - LangChain:**
```python
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client

mcp_client = aws_iam_streamablehttp_client(
    endpoint=mcp_url,    # The URL of the MCP server
    aws_region=region,   # The region of the MCP server
    aws_service=service  # The underlying AWS service, e.g. "bedrock-agentcore"
)

async with mcp_client as (read, write, session_id_callback):
    async with ClientSession(read, write) as session:
        mcp_tools = await load_mcp_tools(session)
        agent = create_langchain_agent(tools=mcp_tools, ...)
```

**Example - LlamaIndex:**
```python
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client

mcp_client = aws_iam_streamablehttp_client(
    endpoint=mcp_url,    # The URL of the MCP server
    aws_region=region,   # The region of the MCP server
    aws_service=service  # The underlying AWS service, e.g. "bedrock-agentcore"
)

async with mcp_client as (read, write, session_id_callback):
    async with ClientSession(read, write) as session:
        mcp_tools = await McpToolSpec(client=session).to_tool_list_async()
        agent = ReActAgent(tools=mcp_tools, ...)
```

### Programmatic Usage Examples

#### Example 1: Global Endpoint with Auto-Detection

For global AWS endpoints, the client automatically handles SigV4A detection:

```python
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client

# Global endpoint - region auto-detected as us-east-1, SigV4A auto-detected if needed
mcp_client = aws_iam_streamablehttp_client(
    endpoint="https://service.global.api.aws/mcp",
    aws_service="my-service",
    aws_profile="default"
)

async with mcp_client as (read, write, session_id_callback):
    async with ClientSession(read, write) as session:
        # Use the session with your framework
        tools = await session.list_tools()
```

**What happens:**
- The client detects `.global.` in the endpoint URL
- Defaults to `us-east-1` region for initial request
- Starts with SigV4, automatically upgrades to SigV4A if needed
- No configuration changes required

#### Example 2: Regional Endpoint

For regional endpoints, standard SigV4 signing is used:

```python
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client

# Regional endpoint - uses specified region with SigV4
mcp_client = aws_iam_streamablehttp_client(
    endpoint="https://service.us-west-2.api.aws/mcp",
    aws_service="my-service",
    aws_region="us-west-2",
    aws_profile="default"
)

async with mcp_client as (read, write, session_id_callback):
    async with ClientSession(read, write) as session:
        # Use the session with your framework
        tools = await session.list_tools()
```

**What happens:**
- The client uses the specified `us-west-2` region
- Uses SigV4 signing for regional endpoint
- No auto-detection needed

#### Example 3: Disabling Auto-Detection

For performance-critical applications with known regional endpoints, you can disable auto-detection:

```python
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client

# Disable auto-detection for performance optimization
mcp_client = aws_iam_streamablehttp_client(
    endpoint="https://service.us-west-2.api.aws/mcp",
    aws_service="my-service",
    aws_region="us-west-2",
    aws_profile="default",
    auto_detect_sigv4a=False  # Disable auto-detection
)

async with mcp_client as (read, write, session_id_callback):
    async with ClientSession(read, write) as session:
        # Use the session with your framework
        tools = await session.list_tools()
```

**When to disable auto-detection:**
- You know the endpoint only requires SigV4 (regional endpoint)
- You want to avoid the potential one-time retry overhead
- You're optimizing for performance in high-throughput scenarios

**Note:** Auto-detection is enabled by default and recommended for most use cases to ensure compatibility as services evolve.

### Running Examples

Explore complete working examples for different frameworks in the [`./examples/mcp-client`](./examples/mcp-client) directory:

**Available examples:**
- **[LangChain](./examples/mcp-client/langchain/)**
- **[LlamaIndex](./examples/mcp-client/llamaindex/)**
- **[Microsoft Agent Framework](./examples/mcp-client/agent-framework/)**
- **[Strands Agents SDK](./examples/mcp-client/strands/)**

Run examples individually:
```bash
cd examples/mcp-client/[framework]  # e.g. examples/mcp-client/strands
uv run main.py
```

### Installation

The client library is included when you install the package:

```bash
pip install mcp-proxy-for-aws
```

For development:
```bash
git clone https://github.com/aws/mcp-proxy-for-aws.git
cd mcp-proxy-for-aws
uv sync
```

---

## Understanding SigV4 vs SigV4A

### What is SigV4?

AWS Signature Version 4 (SigV4) is the standard authentication protocol for AWS services. It signs requests with your AWS credentials to verify your identity and authorize access to AWS resources. SigV4 signatures are region-specific, meaning a request signed for `us-east-1` is only valid in that region.

**Use SigV4 when:**
- Connecting to regional AWS endpoints (e.g., `service.us-west-2.api.aws`)
- Your MCP server operates in a single, specific AWS region
- You want the most straightforward authentication setup

### What is SigV4A?

AWS Signature Version 4A (SigV4A) is an extension of SigV4 that supports multi-region signing. A SigV4A signature can be valid across multiple AWS regions simultaneously, which is essential for global or multi-region AWS services.

**Use SigV4A when:**
- Connecting to global AWS endpoints (e.g., `service.global.api.aws`)
- Your MCP server operates across multiple regions
- The AWS service requires multi-region authentication

### When to Use Each

| Scenario | Recommended | Why |
|----------|-------------|-----|
| Regional MCP server | SigV4 | Simpler, region-specific authentication |
| Global MCP server | SigV4A | Required for multi-region services |
| Unknown endpoint type | Auto-detection | Automatically uses the correct method |
| Service transitioning to global | Auto-detection | Seamless upgrade without config changes |

### Auto-Detection Benefits

The MCP Proxy for AWS uses intelligent auto-detection to choose the right signing method:

1. **Zero Configuration** - No need to specify which signing method to use
2. **Future-Proof** - Automatically adapts when services transition from regional to global
3. **Backward Compatible** - Works with both SigV4 and SigV4A endpoints
4. **Minimal Overhead** - Only one retry on first request if upgrade is needed
5. **Transparent** - Logs detection events for visibility and debugging

### Requirements

- **SigV4**: Available in all versions of botocore
- **SigV4A**: Requires botocore >= 1.31.0 (automatically installed with this package)

---

## Development & Contributing

For development setup, testing, and contribution guidelines, see:

* [DEVELOPMENT.md](DEVELOPMENT.md) - Development environment setup and testing
* [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute to this project

Resources to understand SigV4:

- SigV4 User Guide: <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html>
- SigV4 Signers: <https://github.com/boto/botocore/blob/develop/botocore/signers.py>
- SigV4a: <https://github.com/aws-samples/sigv4a-signing-examples/blob/main/python/sigv4a_sign.py>

## License

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License").

## Disclaimer

LLMs are non-deterministic and they make mistakes, we advise you to always thoroughly test and follow the best practices of your organization before using these tools on customer facing accounts. Users of this package are solely responsible for implementing proper security controls and MUST use AWS Identity and Access Management (IAM) to manage access to AWS resources. You are responsible for configuring appropriate IAM policies, roles, and permissions, and any security vulnerabilities resulting from improper IAM configuration are your sole responsibility. By using this package, you acknowledge that you have read and understood this disclaimer and agree to use the package at your own risk.
