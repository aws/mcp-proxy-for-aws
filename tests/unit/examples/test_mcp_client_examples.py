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

"""Unit tests for MCP client examples.

Extracts framework classes/methods from example code and validates
they can be imported in each framework's isolated environment.
"""

import logging
import pytest
from .example_validator import ExampleValidator
from pathlib import Path


logger = logging.getLogger(__name__)

EXAMPLES_BASE_DIR = Path(__file__).parent.parent.parent.parent / 'examples' / 'mcp-client'
FRAMEWORKS = [
    d.name for d in EXAMPLES_BASE_DIR.iterdir() if d.is_dir()
]  # Auto-discover frameworks


@pytest.mark.unit
class TestMcpClientExamples:
    """Test MCP client usage examples."""

    def setup_method(self):
        """Initialize validator for each test."""
        self.validator = ExampleValidator()

    @pytest.mark.parametrize('framework', FRAMEWORKS)
    def test_api_shapes(self, framework):
        """Validate framework classes can be imported and method calls exist."""
        example_dir = EXAMPLES_BASE_DIR / framework
        main_file = example_dir / 'main.py'

        # Extract what the example uses from framework APIs
        imports, classes, method_calls = self.validator.extract_imports_and_classes(main_file)
        assert classes, f'{framework}: No classes found to test'

        # Test imports work in framework's environment
        script = self.validator.create_validation_script(example_dir, imports, classes)
        self.validator.run_in_isolated_env(script, example_dir)

        # Report what was validated
        logger.info('Validated %d classes: %s', len(classes), sorted(classes))
        if method_calls:
            calls = [
                f'{obj}.{method}()'
                for obj, methods in method_calls.items()
                for method in sorted(methods)
            ]
            logger.info('Validated %d method calls: %s', len(calls), calls)
