# Development Guide

This guide covers the development workflow for the AWS MCP Proxy Server.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Environment Setup](#development-environment-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Running and Testing](#running-and-testing)
- [Code Quality](#code-quality)
- [Contributing Guidelines](#contributing-guidelines)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before you begin development, ensure you have the following installed:

- **Python 3.10+**: [Download Python](https://www.python.org/downloads/release/python-3100/)
- **uv package manager**: [Install uv](https://docs.astral.sh/uv/getting-started/installation/)
- **AWS CLI**: [Install and configure AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
- **Git**: For version control
- **Pre-commit**: Will be installed automatically with dev dependencies

## Development Environment Setup

### 1. Clone and Setup the Project

```bash
# Clone the repository
git clone git@github.com:aws/aws-mcp-proxy.git
cd aws-mcp-proxy

# Install dependencies including dev dependencies
uv sync --group dev

# Install pre-commit hooks
uv run pre-commit install
```

### 2. Verify Installation

```bash
# Check that the server can start
uv run aws_mcp_proxy/server.py --help

# Run tests to ensure everything is working
uv run pytest
```

## Project Structure

```
aws_mcp_proxy/
├── __init__.py              # Package initialization
├── server.py                # Main MCP server implementation
├── mcp_proxy_manager.py     # MCP proxy management logic
├── sigv4_helper.py          # AWS SigV4 authentication helper
├── logging_config.py        # Logging configuration
└── utils.py                 # Utility functions

tests/
├── test_init.py             # Package tests
├── test_server.py           # Server tests
├── test_mcp_proxy_manager.py # Proxy manager tests
├── test_sigv4_helper.py     # SigV4 helper tests
├── test_logging_config.py   # Logging tests
├── test_utils.py            # Utility tests
└── test_main.py             # Main integration tests

pyproject.toml               # Project configuration
.pre-commit-config.yaml      # Pre-commit hooks configuration
README.md                    # Project documentation
DEVELOPMENT.md               # This file
```

## Development Workflow

### 1. Creating a Feature Branch

```bash
# Create and switch to a new feature branch
git checkout -b feature/your-feature-name

# Make your changes
# ...

# Commit your changes
git add .
git commit -m "feat: add new feature description"
```

### 2. Running the Server Locally

#### Basic Local Execution
```bash
# Run the server directly
uv run aws_mcp_proxy/server.py --endpoint <your-endpoint>
```

#### With MCP Inspector (for debugging)
```bash
# Run with MCP inspector for interactive debugging
npx @modelcontextprotocol/inspector uv run \
  aws_mcp_proxy/server.py \
  --endpoint <your-endpoint>
```
A browser window will open automatically outside of your terminal window. Navigate to the browser window. Then click "Connect" in the opened browser window to interact with the server.

#### Advanced Options
```bash
# Run with specific AWS profile and write permissions
uv run aws_mcp_proxy/server.py \
  --endpoint <your-endpoint> \
  --service <aws-service> \
  --profile <aws-profile> \
  --allow-write
```

## Running and Testing

### Running Tests

```bash
# Run all tests
uv run pytest

# Run tests with coverage
uv run pytest --cov --cov-branch --cov-report=term-missing

# Run tests in verbose mode
uv run pytest -v

# Run specific test file
uv run pytest tests/test_server.py

# Run tests with specific marker (if any)
uv run pytest -m "not live"
```

### Test Coverage Requirements

The project maintains high test coverage standards:
- **Minimum Coverage**: 80% (target: 90%+)
- **Branch Coverage**: Required
- **Coverage Report**: Generated with `--cov-report=term-missing`

## Code Quality

### Linting and Formatting

The project uses several tools for code quality:

```bash
# Run ruff linting
uv run ruff check

# Fix auto-fixable ruff issues
uv run ruff check --fix

# Format code with ruff
uv run ruff format

# Run type checking with pyright
uv run pyright

# Run all pre-commit hooks manually
uv run pre-commit run --all-files
```

### Code Style Guidelines

- **Line Length**: 99 characters (configured in `pyproject.toml`)
- **Quote Style**: Single quotes preferred
- **Import Organization**: Handled by `ruff` (isort profile)
- **Docstrings**: Google style convention
- **Type Hints**: Required for all public functions

### Pre-commit Hooks

The project uses pre-commit hooks that run automatically before each commit:

- **File Validation**: JSON, YAML, TOML syntax checking
- **Security**: Detect private keys and AWS credentials
- **Code Quality**: Ruff linting and formatting
- **Conventional Commits**: Enforces commit message format

## Contributing Guidelines

### Commit Message Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```bash
git commit -m "feat(auth): add SigV4 authentication support"
git commit -m "fix(server): handle connection timeouts gracefully"
git commit -m "docs: update development setup instructions"
```

### Code Review Process

### Using Commitizen

This project uses [Commitizen](https://commitizen-tools.github.io/commitizen/) to enforce conventional commit messages and automate version management. Commitizen is integrated into the pre-commit hooks and provides several useful features.

#### When to Use Commitizen

**Use `cz commit` when:**
- You want guided commit message creation
- You're unsure about conventional commit format
- You want to ensure your commit follows the project standards
- You're making your first commits to the project

**Use regular `git commit` when:**
- You're comfortable with conventional commit format
- You want faster commit workflow
- You're making quick fixes or documentation updates

#### Interactive Commit Creation

```bash
# Use Commitizen interactive mode for guided commit creation
uv run cz commit

# Alternative shorter command
uv run cz c
```

This will guide you through:
1. **Type selection**: Choose from feat, fix, docs, style, refactor, test, chore, etc.
2. **Scope** (optional): Specify what part of the codebase is affected
3. **Description**: Write a concise description of the change
4. **Body** (optional): Add detailed explanation if needed
5. **Breaking changes** (optional): Describe any breaking changes
6. **Footer** (optional): Reference issues, etc.

#### Version Management and Releases

Commitizen automates version bumping and changelog generation:

```bash
# Bump version automatically based on conventional commits
uv run cz bump

# Preview what the next version would be (dry run)
uv run cz bump --dry-run

# Bump to a specific version type
uv run cz bump --increment PATCH   # 0.1.0 -> 0.1.1
uv run cz bump --increment MINOR   # 0.1.0 -> 0.2.0
uv run cz bump --increment MAJOR   # 0.1.0 -> 1.0.0

# Generate changelog without bumping version
uv run cz changelog
```

#### Pre-commit Integration

Commitizen runs automatically through pre-commit hooks:
- **`commitizen` hook**: Validates commit message format
- **`commitizen-branch` hook**: Runs on pre-push to ensure branch is ready

If your commit message doesn't follow conventional format, the pre-commit hook will fail with guidance.

#### Configuration

Commitizen is configured in `pyproject.toml`:
- **Version files**: Automatically updates version in `pyproject.toml` and `aws_mcp_proxy/__init__.py`
- **Tag format**: Creates git tags in `v{version}` format (e.g., `v0.1.0`)
- **Changelog**: Automatically generates `CHANGELOG.md` when bumping versions

#### Common Commitizen Workflow

```bash
# Make your changes
git add .

# Create commit with Commitizen (interactive)
uv run cz commit

# OR use regular git commit if you know the format
git commit -m "feat(auth): add SigV4 request signing"

# Before release, bump version and generate changelog
uv run cz bump

# Push changes and tags
git push && git push --tags
```

#### Troubleshooting Commitizen

```bash
# Check current version
uv run cz version

# Validate commit message format
echo "your commit message" | uv run cz check

# Check what commits would be included in next bump
uv run cz bump --dry-run --changelog

# Fix version if it gets out of sync
uv run cz bump --increment PATCH --yes
```

### Code Review Process

1. **Create Feature Branch**: Branch from `main` on your own fork
2. **Implement Changes**: Follow coding standards
3. **Write Tests**: Ensure adequate test coverage
4. **Run Quality Checks**: All linting and tests must pass
5. **Create Pull Request**: Include clear description and context
6. **Address Feedback**: Respond to review comments
7. **Merge**: Once approved and CI passes

### Adding New Features

When adding new features:

1. **Design First**: Consider the MCP specification and AWS service integration
2. **Add Tests**: Write tests before or alongside implementation
3. **Update Documentation**: Update README.md and relevant docs
4. **Error Handling**: Implement proper error handling and logging
5. **AWS Integration**: Follow AWS SDK best practices for authentication and retries

### Dependencies

- **Adding Dependencies**: Add to `dependencies` in `pyproject.toml`
- **Dev Dependencies**: Add to `dev` dependency group
- **Security**: Regularly update dependencies for security patches

## Troubleshooting

### Common Issues

#### UV Package Manager Issues
```bash
# Clear uv cache
uv cache clean

# Reinstall dependencies
rm uv.lock
uv sync --group dev
```

#### Test Failures
```bash
# Run tests in verbose mode for more details
uv run pytest -v -s

# Run specific failing test
uv run pytest tests/test_specific.py::test_function_name -v
```

### Debug Mode

Enable debug logging for troubleshooting:
```bash
# Set logging level to debug
export LOG_LEVEL=DEBUG
uv run aws_mcp_proxy/server.py --endpoint <endpoint>
```

## Additional Resources

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [FastMCP Documentation](https://fastmcp.readthedocs.io/)
- [AWS SDK for Python (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Project README](README.md)

---

For questions or issues not covered in this guide, please:
1. Check existing [GitHub Issues](https://github.com/aws/aws-mcp-proxy/issues)
2. Review the [MCP Specification](https://spec.modelcontextprotocol.io/)
3. Create a new issue with detailed information about your problem
