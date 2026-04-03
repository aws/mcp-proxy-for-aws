# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- Simplify error middleware and suggest long-lived AWS credentials on auth errors (#216)

### Added

- Build and publish container image (#126)

### Fixed

- Add URL scheme validation to prevent credential interception (#169)
- Prevent credential exposure in logs (#167)
- Replace failing integ test (#178)
- retrieve_agent_sop test (#197)

## v1.1.6 (2026-01-29)

Include MCP ownership information in package README to be used for MCP registry owner verification.

## v1.1.5 (2025-12-15)

### Fixed

- Pin FastMCP version (#129)
- Reuse the boto3 session to sign request (#122)

## v1.1.4 (2025-12-04)

### Fixed

- Do not call initialize for q dev cli / kiro cli
- Patch fastmcp lowlevel session method
- Connect remote mcp client immediately in the initialize middleware

## v1.1.3 (2025-12-04)

### Fixed

- Avoid infinite recursion (#111)
- Init client and show errors in all clients (#108)
- Set the fastmcp log level to be the same as the proxy (#101)

## v1.1.2 (2025-11-27)

### Fixed

- Do not write result to stdout (#98)
- Use factory to refresh session once it is finished (#97)
- Write initialize error to stdout (#95)

## v1.1.1 (2025-11-19)

### Fixed

- Pass connected client to proxy to reuse session (#88)

## v1.1.0 (2025-11-13)

### Added

- Add Automated PyPI Publishing Workflow (#83)
- Allow iam mcp client to take a botocore credentials object (#84)
- AWS IAM MCP client with SigV4 auth (#65)

### Fixed

- Reduce severity of log levels (#86)
- Add override for bedrock-agentcore service name detection (#79)
- Set default log level to ERROR (#73)
- Do not raise errors and let mcp sdk handle the http errors (#66)
- Correct log_level type annotation from int to str in add_logging_middleware (#68)
- F-strings formatting in logging (#67)

### Changed

- Extract argument parsing to separate module (#70)

## v1.0.0 (2025-10-29)

### Added

- Initial release
