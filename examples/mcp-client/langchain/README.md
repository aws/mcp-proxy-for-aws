# Example: LangChain

This example demonstrates how to use `aws_iam_streamablehttp_client` from `mcp-proxy-for-aws` to connect a [LangChain](https://www.langchain.com/) AI agent to an MCP server using AWS IAM authentication.

**Note:** LangChain requires direct access to MCP sessions. The `aws_iam_streamablehttp_client` provides the authenticated transport streams, which are then used to create an MCP ClientSession.

## Prerequisites

- [Python 3.10+](https://www.python.org/downloads) and [uv](https://docs.astral.sh/uv/getting-started/installation/) installed
- AWS credentials configured (via [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html), environment variables, or IAM roles)
- Access to Anthropic Claude on [Amazon Bedrock](https://aws.amazon.com/bedrock/)

## Setup

Create a `.env` file or set the following environment variables:

```bash
# MCP server details
MCP_SERVER_URL=https://example.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp
MCP_SERVER_AWS_SERVICE=bedrock-agentcore
MCP_SERVER_REGION=us-west-2
```

All three environment variables are required.

## Usage

Run the example:

```bash
uv run main.py
```

The agent will connect to the MCP server and list its available tools.

## How It Works

1. **Loads configuration** from environment variables or `.env` file
2. **Creates an AWS IAM-authenticated MCP client** using `aws_iam_streamablehttp_client()`
3. **Extracts transport streams** from the client context manager
4. **Creates an MCP ClientSession** with the authenticated transport streams
5. **Loads MCP tools** using LangChain's MCP tools adapter
6. **Creates an agent** with access to the MCP server tools
7. **Runs the agent** to demonstrate tool discovery and usage

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

- Ensure all required variables are set: `MCP_SERVER_URL`, `MCP_SERVER_REGION`, and `MCP_SERVER_AWS_SERVICE`
- Check your `.env` file or environment variable configuration

#### Connection errors

- Verify your MCP server details are correct
- Ensure the MCP server is running and accessible
- Verify your AWS credentials have the necessary permissions to access the MCP server
