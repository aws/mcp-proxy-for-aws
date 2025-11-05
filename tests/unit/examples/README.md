# MCP Client Example Tests

## Overview

Validates MCP client examples by extracting framework API usage and testing it in isolated environments.

## Test Structure

- `test_mcp_client_examples.py` - Main test that auto-discovers all framework examples
- `example_validator.py` - Utility for extracting and validating framework APIs

## Running Tests

```bash
uv run pytest tests/unit/examples/
```

## How It Works

1. **Auto-Discovery**: Automatically finds all framework examples in `examples/mcp-client/`
2. **AST Parsing**: Extracts imports, classes, and method calls from each example's `main.py`
3. **Filtering**: Ignores standard library modules to focus on framework APIs
4. **Validation**: Generates and runs test scripts in each framework's isolated environment

## What Gets Tested

### Per Framework Example:
- **Import Validation**: All framework imports can be loaded
- **Class Validation**: Framework classes have `__init__` methods
- **Method Call Tracking**: Logs which methods are called on framework objects

### Example Output:
```
Validated 3 classes: ['Agent', 'ChatAgent', 'MCPClient']
Validated 5 method calls: ['agent.run()', 'client.connect()', 'session.initialize()']
```

## What These Tests Catch

1. **Breaking API changes**: If framework classes or methods are renamed/removed
2. **Import issues**: If module structure changes break imports
3. **Missing dependencies**: If required packages aren't available in framework environments
4. **Integration patterns**: If example code uses deprecated or invalid patterns

## Framework Coverage

Currently validates examples for:
- LangChain
- LlamaIndex
- Microsoft Agent Framework
- Strands Agents SDK

## Implementation Details

- Uses AST parsing to extract API usage without executing example code
- Runs validation scripts using `uv run` in each framework's environment
- Filters out utility imports to focus on framework-specific APIs
- Reports both successful validations and any failures with detailed error messages
