# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
