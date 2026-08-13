# MCP Proxy for AWS (version-pinned distribution)

`mcp-proxy-for-aws` is the distribution to install for **CLI and `uvx` use**. It contains no
code of its own: it is a thin wrapper that depends on
[`mcp-proxy-for-aws-lib`](https://pypi.org/project/mcp-proxy-for-aws-lib/) — which owns the
implementation — and pins that library **plus its entire runtime dependency tree** to exact
versions.

```bash
uvx mcp-proxy-for-aws@latest <SigV4 MCP endpoint URL>
```

Because every transitive dependency is pinned with `==`, a given release always installs the
same tree and cannot silently pick up a newer release of a transitive dependency.

> **Scope of the guarantee:** this is *version pinning, not hash verification*. It prevents
> automatic adoption of a newer (possibly compromised) release; it does not cryptographically
> verify the installed artifacts.

## Which package should I install?

| Use case | Install | Dependencies |
|---|---|---|
| CLI / `uvx` / MCP client config | `mcp-proxy-for-aws` | Exact `==` pins (frozen tree) |
| Importing from your own application | `mcp-proxy-for-aws-lib` | Loose ranges, co-resolvable |

Install `mcp-proxy-for-aws-lib` if you import `mcp_proxy_for_aws` in your own project, so that
its dependencies can resolve alongside yours. The import name is `mcp_proxy_for_aws` for both
distributions.

The pins shipped here are derived at build time from the `uv.lock` committed at the release
tag, so they are reproducible from the repository.

## Documentation

See the [project README](https://github.com/aws/mcp-proxy-for-aws/blob/main/README.md) for
configuration, authentication, and usage.

## License

Apache-2.0. See [LICENSE](https://github.com/aws/mcp-proxy-for-aws/blob/main/LICENSE).
