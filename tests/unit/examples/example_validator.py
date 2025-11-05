# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Utility for validating MCP client examples.

Extracts framework classes and method calls from example code,
then validates they can be imported in the framework's environment.
"""

import ast
import pytest
import subprocess
from pathlib import Path


class ExampleValidator:
    """Validates MCP client examples by extracting and testing API usage."""

    # Skip standard library and utility modules to focus on framework APIs
    IGNORED_MODULES = {'asyncio', 'dotenv', 'os', 'warnings'}

    def extract_imports_and_classes(
        self, main_file: Path
    ) -> tuple[list[str], set[str], dict[str, set[str]]]:
        """Extract framework imports, classes, and method calls from example file.

        Returns:
            imports: List of import statements for validation script
            classes: Set of class names to test for __init__ method
            method_calls: Dict mapping object names to their called methods
        """
        tree = ast.parse(main_file.read_text(encoding='utf-8'))
        imports, classes, method_calls = [], set(), {}
        ignored_names = set()  # Track names from ignored modules

        # Walk AST to find imports and method calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._process_import(node, imports, ignored_names)
            elif isinstance(node, ast.ImportFrom):
                self._process_import_from(node, imports, classes, ignored_names)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self._process_method_call(node, method_calls, ignored_names)

        return imports, classes, method_calls

    def _process_import(
        self, node: ast.Import, imports: list[str], ignored_names: set[str]
    ) -> None:
        """Process 'import' statements."""
        for alias in node.names:
            if alias.name in self.IGNORED_MODULES:
                ignored_names.add(alias.name)
            else:
                imports.append(f'    import {alias.name}')

    def _process_import_from(
        self, node: ast.ImportFrom, imports: list[str], classes: set[str], ignored_names: set[str]
    ) -> None:
        """Process 'from ... import' statements."""
        module = node.module or ''
        if any(ignored in module for ignored in self.IGNORED_MODULES):
            for alias in node.names:
                ignored_names.add(alias.name)
        else:
            for alias in node.names:
                imports.append(f'    from {module} import {alias.name}')
                if alias.name[0].isupper():  # Assume uppercase names are classes
                    classes.add(alias.name)

    def _process_method_call(
        self, node: ast.Call, method_calls: dict[str, set[str]], ignored_names: set[str]
    ) -> None:
        """Process method calls like obj.method()."""
        if isinstance(node.func.value, ast.Name):
            obj_name = node.func.value.id
            method_name = node.func.attr
            if obj_name not in ignored_names:
                if obj_name not in method_calls:
                    method_calls[obj_name] = set()
                method_calls[obj_name].add(method_name)

    def create_validation_script(
        self, example_dir: Path, imports: list[str], classes: set[str]
    ) -> str:
        """Generate Python script that validates framework classes can be imported."""
        import_lines = '\n'.join(f'    {imp.strip()}' for imp in imports)
        class_checks = '\n'.join(
            f"    assert hasattr({cls}, '__init__'), '{cls} missing __init__'"
            for cls in sorted(classes)
        )

        template = """
import sys
sys.path.insert(0, r"{example_dir}")
try:
{imports}

{checks}
    print("SUCCESS")
except Exception as e:
    print(f"ERROR: {{e}}")
    sys.exit(1)"""

        return template.format(example_dir=example_dir, imports=import_lines, checks=class_checks)

    def run_in_isolated_env(self, script: str, example_dir: Path) -> None:
        """Execute validation script using uv in the framework's environment."""
        try:
            # Run script in framework's isolated environment with its dependencies
            subprocess.run(
                ['uv', 'run', 'python', '-c', script],
                cwd=example_dir,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            pytest.fail(f'API shape validation failed: {e.stderr.strip()}')
        except FileNotFoundError:
            pytest.skip('uv command not found - please install uv')
