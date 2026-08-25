# MCP Proxy for AWS (version-pinned distribution)

This is a thin, metadata-only wrapper that pins
[`mcp-proxy-for-aws`](https://pypi.org/project/mcp-proxy-for-aws/) and its entire runtime
dependency tree to exact versions, intended for CLI and `uvx` use. It contains no code of its
own; the implementation lives in `mcp-proxy-for-aws`.

> **Not currently published.** This pinned distribution is not available on PyPI yet. For CLI
> and `uvx` use today, install [`mcp-proxy-for-aws`](https://pypi.org/project/mcp-proxy-for-aws/)
> and see the [project README](https://github.com/aws/mcp-proxy-for-aws/blob/main/README.md) for
> configuration, authentication, and usage.

The import name is `mcp_proxy_for_aws`. The pins are derived at build time from the `uv.lock`
committed at the release tag, so they are reproducible from the repository.

> **Scope of the guarantee:** this is *version pinning, not hash verification*. It prevents
> automatic adoption of a newer (possibly compromised) release; it does not cryptographically
> verify the installed artifacts.

## License

Apache-2.0. See [LICENSE](https://github.com/aws/mcp-proxy-for-aws/blob/main/LICENSE).
