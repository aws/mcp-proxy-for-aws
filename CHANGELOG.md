# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v1.1.5 (2025-12-15)

### Fix

- Pin FastMCP version (#129)
- reuse the boto3 session to sign request (#122)

## v1.1.4 (2025-12-04)

### Fix

- do not call initialize for q dev cli / kiro cli
- patch fastmcp lowlevel session method
- connect remote mcp client immediately in the initialize middleware

## v1.1.3 (2025-12-04)

### Fix

- avoid infinite recursion (#111)
- init client and show errors in all clients (#108)
- set the fastmcp log level to be the same as the proxy (#101)

## v1.1.2 (2025-11-27)

### Fix

- do not write result to stdout (#98)
- use factory to refresh session once it is finished (#97)
- write initialize error to stdout (#95)

## v1.1.1 (2025-11-19)

### Fix

- pass connected client to proxy to reuse session (#88)

## v1.1.0 (2025-11-13)

### Feat

- Add Automated PyPI Publishing Workflow (#83)
- allow iam mcp client to take a botocore credentials object (#84)
- AWS IAM MCP client with SigV4 auth (#65)

### Fix

- **sigv4_helper.py**: reduce severity of log levels (#86)
- **mcp_proxy_for_aws/utils.py**: add override for bedrock-agentcore service name detection (#79)
- set default log level to ERROR (#73)
- do not raise errors and let mcp sdk handle the http errors (#66)
- correct log_level type annotation from int to str in add_logging_middleware (#68)
- f-strings formatting in logging (#67)

### Refactor

- **cli**: extract argument parsing to separate module (#70)

## v1.0.0 (2025-10-29)

### Feat

- Initial release
