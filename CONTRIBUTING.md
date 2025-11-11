# Contributing to MCP Proxy for AWS

Thank you for your interest in contributing to the MCP Proxy for AWS! We welcome contributions from the community.

## Quick Start

> [!NOTE]
> Before implementing new features, please create an issue first to ensure your contribution aligns with the project roadmap.

1. **Fork the repository** on GitHub
2. **Set up your development environment** - see [DEVELOPMENT.md](DEVELOPMENT.md) for detailed setup instructions
3. **Create a feature branch** from `main`
4. **Make your changes** following our coding standards
5. **Run tests and quality checks** to ensure everything works
6. **Submit a pull request** with a clear description

For detailed technical information, development workflow, and troubleshooting, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Ways to Contribute

### 🐛 Reporting Bugs
- Use GitHub Issues to report bugs
- Include steps to reproduce, expected vs actual behavior
- Provide AWS region, Python version, and relevant logs
- Check existing issues to avoid duplicates

### 💡 Suggesting Features
- Open a GitHub Issue with the "enhancement" label
- Describe the use case and expected behavior
- Consider MCP specification compatibility
- Discuss design before implementing large changes

### 🔧 Code Contributions
- Follow the development workflow in [DEVELOPMENT.md](DEVELOPMENT.md)
- Ensure tests pass: `uv run pytest --cov`
- Follow code quality standards: `uv run pre-commit run --all-files`
- Use conventional commit messages (enforced by pre-commit hooks)

### 📚 Documentation
- Improve README.md, DEVELOPMENT.md, or code documentation
- Add examples or clarify existing instructions
- Fix typos or broken links

## Code of Conduct
> See [CODE_OF_CONDUCT.md](https://github.com/aws/mcp-proxy-for-aws/blob/main/CODE_OF_CONDUCT.md)

- **Be respectful and inclusive** in all interactions
- **Focus on constructive feedback** during code reviews
- **Help others learn** - explain reasoning behind suggestions
- **Follow professional standards** appropriate for AWS projects

## Pull Request Guidelines

### Before Submitting
- [ ] Read [DEVELOPMENT.md](DEVELOPMENT.md) and set up your environment
- [ ] Create tests for new functionality
- [ ] Ensure all tests pass locally
- [ ] Follow [integ/README.md](https://github.com/aws/mcp-proxy-for-aws/blob/main/tests/integ/README.md) to run integration tests
- [ ] Run code quality tools (`ruff`, `pyright`, `pre-commit`)
- [ ] Update documentation if needed

### PR Description Should Include
- **What**: Brief description of changes
- **Why**: Reason for the change (issue reference, use case)
- **How**: Technical approach if complex
- **Testing**: How you verified the changes work

### Example PR Title
```
feat(auth): add support for custom SigV4 signing profiles
```

## Development Standards

- **Python**: 3.10+ with type hints
- **Code Style**: Follow `ruff` configuration (99 char line limit)
- **Testing**: Maintain 80%+ test coverage
- **Commits**: Use [Conventional Commits](https://www.conventionalcommits.org/) format
- **Documentation**: Update relevant docs with changes

## Getting Help

- **Technical Issues**: See troubleshooting in [DEVELOPMENT.md](DEVELOPMENT.md)
- **Questions**: Open a GitHub Discussion or Issue
- **MCP Specification**: Refer to [Model Context Protocol](https://spec.modelcontextprotocol.io/)

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License that covers this project.

---

**New to the project?** Start with [DEVELOPMENT.md](DEVELOPMENT.md) for complete setup and development instructions.
