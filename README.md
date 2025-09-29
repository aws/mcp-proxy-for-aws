# AWS  aws-mcp-proxy MCP Server

AWS  MCP Proxy Server

## Overview

The AWS MCP Proxy serves as a lightweight, client-side bridge between MCP clients (AI assistants and developer tools) and backend AWS services.

- **MCP Mode (Default)**: Direct connection to a single MCP backend server using JSON-RPC protocol

The proxy handles SigV4 authentication using local AWS credentials and provides dynamic tool discovery, making it ideal for developers who want direct service access without complex gateway setups.

## Prerequisites

* [Install Python 3.10+](https://www.python.org/downloads/release/python-3100/)
* [Install the `uv` package manager](https://docs.astral.sh/uv/getting-started/installation/)
* [Install and configure the AWS CLI with credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)

## Getting Started

### Quick start

```bash
uv run aws_mcp_proxy/server.py <a sigv4 mcp>
```

#### Details

MCP mode provides a streamlined connection to a single backend MCP server.

#### 1. Configure MCP Client

Add this to your MCP client configuration, replacing env variables to match the AWS credentials and region you want to use:

Optional arguments you can add:
- `--service`: AWS service name for SigV4 signing (inferred from endpoint if not provided)
- `--profile`: AWS profile to use (uses AWS_PROFILE environment variable if not provided)
- `--allow-write`: Allow tools that require write permissions to be enabled (by default, only tools with the `readOnlyHint` annotation are enabled)

NOTE: `remote-server-url` should be your remote mcp server's URL (including the `/mcp` part). `service-code` should be the service code for your own mcp service, such as `eks-mcp`.

Example with all options
```json
{
  "mcpServers": {
    "aws.aws-mcp-proxy": {
      "disabled": false,
      "type": "stdio",
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/aws_mcp_proxy",
        "run",
        "aws_mcp_proxy/server.py",
        "<remote-server-url>",
        "--service",
        "<service-code>",
        "--profile",
        "default",
        "--allow-write"
      ]
    }
  }
}
```

#### 2. Backend Server Configuration

In MCP mode, the backend server is configured directly through command-line arguments:

* `endpoint`: The MCP endpoint URL (required, first positional argument)
* `--service`: AWS service name for SigV4 signing (optional, inferred from endpoint if not provided)
* `--profile`: AWS profile to use (optional, uses AWS_PROFILE environment variable if not provided)

The proxy will automatically connect to the specified backend MCP server and discover available tools.

### Tool Discovery and Updates

The proxy automatically manages tool discovery and updates:

1. **MCP Mode**: Connects directly to the backend MCP server and discovers available tools
3. **Dynamic Updates**: Automatically checks for tool updates when tools are called - Currently not implemented for MCP (default) mode.
4. **Validation**: Ensures tool parameters match the current specification

**Note**: Currently, a limited number of MCP clients (such as Amazon Q CLI) support automatic refresh of tool lists. In most cases, clients do not handle the `notifications/tools/list_changed` message by making a new `tools/list` call to refresh the tool list. The server needs to be refreshed manually in order for them to pick up changes.

## TODO (REMOVE AFTER COMPLETING)

* [ ] Add your own tool(s) following the [DESIGN_GUIDELINES.md](https://github.com/aws/mcp/blob/main/DESIGN_GUIDELINES.md)
* [ ] Keep test coverage at or above the `main` branch - NOTE: GitHub Actions run this command for CodeCov metrics `uv run --frozen pytest --cov --cov-branch --cov-report=term-missing`
* [ ] Document the MCP Server in this "README.md"
* [ ] Add a section for this aws-mcp-proxy MCP Server at the top level of this repository "../../README.md"
* [ ] Create the "../../doc/servers/aws-mcp-proxy.md" file with these contents:

    ```markdown
    ---
    title: aws-mcp-proxy MCP Server
    ---

    {% include "../../src/aws-mcp-proxy/README.md" %}
    ```

* [ ] Reference within the "../../doc/index.md" like this:

    ```markdown
    ### aws-mcp-proxy MCP Server

    AWS MCP Proxy Server

    **Features:**

    - Feature one
    - Feature two
    - ...

    Instructions for using this aws-mcp-proxy MCP server. This can be used by clients to improve the LLM's understanding of available tools, resources, etc. It can be thought of like a 'hint' to the model. For example, this information MAY be added to the system prompt. Important to be clear, direct, and detailed.

    [Learn more about the aws-mcp-proxy MCP Server](servers/aws-mcp-proxy.md)
    ```

* [ ] Submit a PR and pass all the checks
