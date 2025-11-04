# Example: LangChain

This example demonstrates how to use the MCP Client Library from `mcp-proxy-for-aws` to connect a [LangChain](https://www.langchain.com/) AI agent to an MCP Server on AWS, e.g. using [Amazon Bedrock AgentCore](https://aws.amazon.com/bedrock/agentcore/) Runtime or Gateway, using AWS IAM authentication.

## Prerequisites

- Python 3.10+ and uv installed
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- Access to Anthropic Claude models on Amazon Bedrock

## Usage

Run the example:
```bash
uv run main.py
```

## How It Works

1. Creates an MCP client for the IAM-authenticated connection
2. Connects to an MCP server on Amazon Bedrock AgentCore Runtime or Gateway
3. Creates a Langchain agent with access to MCP tools
4. Runs the agent to discover and use available tools


## Configuration

Update `MCP_SERVER_URL`, `MCP_SERVER_REGION`, and `MCP_SERVER_AWS_SERVICE` in `main.py` with your MCP server details.

**Runtime URL format:**
```
https://bedrock-agentcore.[AWS_REGION].amazonaws.com/runtimes/[RUNTIME_ID]/invocations?qualifier=DEFAULT&accountId=[AWS_ACCOUNT_ID]
```

**Gateway URL format:**
```
https://[GATEWAY_ID].gateway.bedrock-agentcore.[AWS_REGION].amazonaws.com/mcp
```

## Troubleshooting

### Common Issues

**No AWS credentials available**
- Verify AWS credentials are configured (CLI, environment variables, or IAM roles)
- Test with `aws sts get-caller-identity`

**Connection errors**
- Verify `MCP_SERVER_URL`, `MCP_SERVER_REGION`, and `MCP_SERVER_AWS_SERVICE` are correct in `main.py`
- Ensure the MCP server is running and accessible
- Verify your AWS credentials have the necessary permissions