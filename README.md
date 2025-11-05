# MCP Proxy for AWS

## Overview

The MCP Proxy for AWS serves as a lightweight, client-side bridge between MCP clients (AI assistants and developer tools) and backend AWS MCP servers.

The proxy handles [SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html) authentication using local AWS credentials and provides dynamic tool discovery, making it ideal for developers who want access to AWS Hosted SigV4 secured MCP Servers without complex gateway setups.

## Prerequisites

* [Install Python 3.10+](https://www.python.org/downloads/release/python-3100/)
* [Install the `uv` package manager](https://docs.astral.sh/uv/getting-started/installation/)
* [Install and configure the AWS CLI with credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
* (Optional, for docker users) [Install Docker Desktop](https://www.docker.com/products/docker-desktop)

## Installation

### Using PyPi


```
# Run the server
uvx mcp-proxy-for-aws@latest <SigV4 MCP endpoint URL>
```

### Using Local Repository

```
git clone https://github.com/aws/mcp-proxy-for-aws.git
cd mcp-proxy-for-aws
uv run mcp_proxy_for_aws/server.py <SigV4 MCP endpoint URL>
```

### Using Docker

```
# Build the Docker image
docker build -t mcp-proxy-for-aws .
```

## Configuration

### Using Command Line Arguments

| Parameter	           | Description	                                                                                                                                                                                                                            | Default	                                                                    |Required	|
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|---	|
| `endpoint`	          | MCP endpoint URL (e.g., `https://your-service.us-east-1.amazonaws.com/mcp`)	                                                                                                                                                            | N/A	                                                                        |Yes*	|
| `--config`	          | Path to YAML configuration file	                                                                                                                                                                                                        | N/A	                                                                        |No	|
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

*Required unless using `--config`

### Using Configuration File

You can use a YAML configuration file instead of command line arguments:

```bash
# Copy the example configuration
cp config.example.yaml config.yaml

# Edit config.yaml with your settings
# Then run with the config file
uvx mcp-proxy-for-aws@latest --config config.yaml
```

Example `config.yaml`:

```yaml
endpoint: "https://your-service.us-east-1.amazonaws.com/mcp"
service: "your-service"
profile: "default"
region: "us-east-1"
read_only: false
log_level: "INFO"
retries: 0
timeout: 180.0
connect_timeout: 60.0
read_timeout: 120.0
write_timeout: 180.0
```

Command line arguments override configuration file settings.


## Optional Environment Variables

Set the environment variables for the MCP Proxy for AWS:

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

With command line arguments:

```
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

Or with a configuration file:

```
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
        "--config",
        "/path/to/config.yaml"
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
        "mcp-proxy-for-aws",
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

LLMs are non-deterministic and they make mistakes, we advise you to always thoroughly test and follow the best practices of your organization before using these tools on customer facing accounts. Users of this package are solely responsible for implementing proper security controls and MUST use AWS Identity and Access Management (IAM) to manage access to AWS resources. You are responsible for configuring appropriate IAM policies, roles, and permissions, and any security vulnerabilities resulting from improper IAM configuration are your sole responsibility. By using this package, you acknowledge that you have read and understood this disclaimer and agree to use the package at your own risk.
