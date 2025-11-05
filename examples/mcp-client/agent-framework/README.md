# Example: Microsoft Agent Framework

This example demonstrates how to use `aws_iam_streamablehttp_client` from `mcp-proxy-for-aws` to connect a [Microsoft Agent Framework](https://learn.microsoft.com/en-us/agent-framework/) agent to an MCP server using AWS IAM authentication.

**Note:** Microsoft Agent Framework accepts a factory function that returns an MCP client. The `aws_iam_streamablehttp_client` is passed as a factory to the framework's `MCPStreamableHTTPTool`, which handles the connection lifecycle internally.

## Prerequisites

- [Python 3.10+](https://www.python.org/downloads) and [uv](https://docs.astral.sh/uv/getting-started/installation/) installed
- AWS credentials configured (via [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html), environment variables, or IAM roles)
- An [OpenAI API key](https://platform.openai.com/api-keys) for the language model

## Setup

Create a `.env` file or set the following environment variables:

```bash
# MCP server details
MCP_SERVER_URL=https://example.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp
MCP_SERVER_AWS_SERVICE=bedrock-agentcore
MCP_SERVER_REGION=us-west-2

# OpenAI API key for the agent's LLM
OPENAI_API_KEY=sk-...
```

All four environment variables are required.

## Usage

Run the example:

```bash
uv run main.py
```

The agent will connect to the MCP server and list its available tools.

## How It Works

1. **Loads configuration** from environment variables or `.env` file
3. **Creates an AWS IAM-authenticated MCP client** using `aws_iam_streamablehttp_client()`
4. **Integrates with Agent Framework** by configuring `MCPStreamableHTTPTool.get_mcp_client`
5. **Creates an agent** with access to the MCP server tools
6. **Runs the agent** to demonstrate tool discovery and usage

## Example MCP Server URL Formats

**AgentCore Runtime URL:**

```text
https://bedrock-agentcore.[AWS_REGION].amazonaws.com/runtimes/[RUNTIME_ID]/invocations?qualifier=DEFAULT&accountId=[AWS_ACCOUNT_ID]
```

**AgentCore Gateway URL:**

```text
https://[GATEWAY_ID].gateway.bedrock-agentcore.[AWS_REGION].amazonaws.com/mcp
```

## Troubleshooting

### Common Issues

#### No AWS credentials available

- Verify AWS credentials are configured ([AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html), environment variables, or IAM roles)
- Test with `aws sts get-caller-identity`

#### Missing environment variables

- Ensure all required variables are set: `MCP_SERVER_URL`, `MCP_SERVER_REGION`, `MCP_SERVER_AWS_SERVICE`, and `OPENAI_API_KEY`
- Check your `.env` file or environment variable configuration

#### Connection errors

- Verify your MCP server details are correct
- Ensure the MCP server is running and accessible
- Verify your AWS credentials have the necessary permissions to access the MCP server
