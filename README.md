# AWS MCP Proxy

This README provides an overview and configuration information for the AWS MCP Proxy Server. You can use this project to set up and deploy to a configured AWS MCP Proxy Server.

## Overview

The AWS MCP Proxy serves as a lightweight, client-side bridge between MCP clients (AI assistants and developer tools) and backend AWS MCP servers.

The proxy handles [SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html) authentication using local AWS credentials and provides dynamic tool discovery, making it ideal for developers who want access to AWS Hosted SigV4 secured MCP Servers without complex gateway setups.

## Prerequisites

* [Install Python 3.10+](https://www.python.org/downloads/release/python-3100/)
* [Install the `uv` package manager](https://docs.astral.sh/uv/getting-started/installation/)
* [Install and configure the AWS CLI with credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
* (Optional, for docker users) [Install Docker Desktop](https://www.docker.com/products/docker-desktop)

## Installation

### Using PyPi

*Note: The following command should run successfully after first publishing to PyPi.*

```
# Run the server
uvx aws-mcp-proxy@latest <SigV4 MCP endpoint URL>
```

### Using Local Repository

```
git clone https://github.com/aws/aws-mcp-proxy.git
cd aws-mcp-proxy
uv run aws_mcp_proxy/server.py <SigV4 MCP endpoint URL>
```

### Using Docker

```
# Build the Docker image
docker build -t aws-mcp-proxy .
```

## Configuration Parameters

|Parameter	|Description	|Default	|Required	|
|---	|---	|---	|---	|
|`endpoint`	|MCP endpoint URL (e.g., `https://your-service.us-east-1.amazonaws.com/mcp`)	|N/A	|Yes	|
|---	|---	|---	|---	|
|`--service`	|AWS service name for SigV4 signing	|Inferred from endpoint if not provided	|No	|
|`--profile`	|AWS profile for AWS credentials to use	|Uses `AWS_PROFILE` environment variable if not set|No	|
|`--region`	|AWS region to use	|Uses `AWS_REGION` environment variable if not set, defaults to `us-east-1`	|No	|
|`--read-only`	|Disable tools which may require write permissions (tools which DO NOT require write permissions are annotated with [`readOnlyHint=true`](https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations-readonlyhint))|`False`	|No	|
| `--retries` |Configures number of retries done when calling upstream services, setting this to 0 disables retries. | 0 |No |
|`--log-level`	|Set the logging level (`DEBUG/INFO/WARNING/ERROR/CRITICAL`)	|`INFO`	|No	|

## Optional Environment Variables

Set the environment variables for the AWS MCP Proxy:

```
# Credentials through profile
export AWS_PROFILE=<aws_profile>

# Credentials through parameters
export AWS_ACCESS_KEY_ID=<access_key_id>
export AWS_SECRET_ACCESS_KEY=<secret_access_key>
export AWS_SESSION_TOKEN=<session_token>

# AWS Region
export AWS_REGION=<aws_region>
```

## Setup Examples

Add the following configuration to your MCP client config file (e.g., for Amazon Q Developer CLI, edit `~/.aws/amazonq/mcp.json`):
**Note** Add your own endpoint by replacing  `<SigV4 MCP endpoint URL>`

### Running from local - using uv

```
{
  "mcpServers": {
    "<mcp server name>": {
      "disabled": false,
      "type": "stdio",
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/aws_mcp_proxy",
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

### Using Docker

```
{
  "mcpServers": {
    "<mcp server name>": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "--volume",
        "/full/path/to/.aws:/app/.aws:ro",
        "aws-mcp-proxy",
        "<SigV4 MCP endpoint URL>"
      ],
      "env": {}
    }
  }
}
```

## Development & Contributing

For development setup, testing, and contribution guidelines, see:

* [DEVELOPMENT.md](DEVELOPMENT.md) - Development environment setup and testing
* [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute to this project

Resources to understand SigV4:

- <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html>
- SigV4: <https://github.com/boto/botocore/blob/develop/botocore/signers.py>
- SigV4a: <https://github.com/aws-samples/sigv4a-signing-examples/blob/main/python/sigv4a_sign.py>

## License

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License").

## Disclaimer

This aws-mcp-proxy package is provided "as is" without warranty of any kind, express or implied, and is intended for development, testing, and evaluation purposes only. We do not provide any guarantee on the quality, performance, or reliability of this package. LLMs are non-deterministic and they make mistakes, we advise you to always thoroughly test and follow the best practices of your organization before using these tools on customer facing accounts. Users of this package are solely responsible for implementing proper security controls and MUST use AWS Identity and Access Management (IAM) to manage access to AWS resources. You are responsible for configuring appropriate IAM policies, roles, and permissions, and any security vulnerabilities resulting from improper IAM configuration are your sole responsibility. By using this package, you acknowledge that you have read and understood this disclaimer and agree to use the package at your own risk.
