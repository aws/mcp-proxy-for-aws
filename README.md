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
- **Providing seamless integration** - Works with existing MCP clients and frameworks
- **Eliminating custom code** - No need to build your own MCP client with SigV4 signing logic

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
| `--service`	         | AWS service name for SigV4 signing, if omitted we try to infer this from the url	                                                                                                                                                       | Inferred from endpoint if not provided	                                     |No	|
| `--profile`	         | AWS profile for AWS credentials to use	                                                                                                                                                                                                 | Uses `AWS_PROFILE` environment variable if not set                          |No	|
| `--region`	          | AWS region to use	                                                                                                                                                                                                                      | Uses `AWS_REGION` environment variable if not set, defaults to `us-east-1`	 |No	|
| `--metadata`	        | Metadata to inject into MCP requests as key=value pairs (e.g., `--metadata KEY1=value1 KEY2=value2`)                                                                                                                                    | `AWS_REGION` is automatically injected based on `--region` if not provided    |No	|
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

## Troubleshooting

### Handling `Authentication error - Invalid credentials`
We try to autodetect the service from the url, sometimes this fails, ensure that `--service` is set correctly to the
service you are attempting to connect to.
Otherwise the SigV4 signing will not be able to be verified by the service you connect to, resulting in this error.
Also ensure that you have valid IAM credentials on your machine before retrying.


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
