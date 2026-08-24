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

"""End-to-end packaging tests for the two published distributions.

These run real `uv build` invocations, so they are marked `integ` rather than `unit`. They
assert the properties users actually depend on: the library wheel contains the code, and the
wrapper wheel carries fully static exact pins -- including when built from its own sdist,
which is the context where the metadata hook cannot reach the workspace.
"""

import pytest
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
PROJECT_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.integ


def _uv_build(args: list[str], cwd: Path, env: dict | None = None) -> None:
    """Run `uv build`, failing the test with uv's own output if it errors."""
    result = subprocess.run(
        ['uv', 'build', *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        pytest.fail(f'uv build {" ".join(args)} failed:\n{result.stdout}\n{result.stderr}')


def _requires_dist(wheel: Path) -> list[str]:
    """Return the `Requires-Dist` entries from a wheel's static METADATA."""
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith('.dist-info/METADATA'))
        text = archive.read(name).decode('utf-8')
    prefix = 'Requires-Dist:'
    return [line[len(prefix) :].strip() for line in text.splitlines() if line.startswith(prefix)]


@pytest.fixture(scope='module')
def built_distributions(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build both distributions the way the release workflow does."""
    out = tmp_path_factory.mktemp('dist')
    _uv_build(['--all-packages', '--out-dir', str(out)], cwd=WORKSPACE_ROOT)
    _uv_build(['--out-dir', str(out), '.'], cwd=PROJECT_ROOT)
    return out


def _single(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    assert len(matches) == 1, f'expected exactly one {pattern}, found {matches}'
    return matches[0]


class TestLibraryDistribution:
    """`mcp-proxy-for-aws` owns the code."""

    def test_wheel_contains_the_importable_module(self, built_distributions: Path) -> None:
        """Guards uv#7227: a name/package mismatch can silently ship an empty wheel."""
        wheel = _single(built_distributions, 'mcp_proxy_for_aws-*.whl')
        with zipfile.ZipFile(wheel) as archive:
            modules = [n for n in archive.namelist() if n.startswith('mcp_proxy_for_aws/')]

        assert 'mcp_proxy_for_aws/__init__.py' in modules
        assert 'mcp_proxy_for_aws/server.py' in modules

    def test_dependencies_stay_loose(self, built_distributions: Path) -> None:
        """Library users must be able to co-resolve it with their own dependencies."""
        wheel = _single(built_distributions, 'mcp_proxy_for_aws-*.whl')
        requirements = _requires_dist(wheel)

        assert requirements
        assert not any('==' in requirement for requirement in requirements)


class TestWrapperDistribution:
    """`mcp-proxy-for-aws-cli` is a metadata-only pinned wrapper."""

    def test_wheel_ships_no_modules(self, built_distributions: Path) -> None:
        """All code comes from the library; the wrapper is metadata plus an entry point."""
        wheel = _single(built_distributions, 'mcp_proxy_for_aws_cli-*.whl')
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()

        assert not [n for n in names if not n.startswith('mcp_proxy_for_aws_cli-')]
        assert any(n.endswith('entry_points.txt') for n in names)

    def test_wheel_pins_the_entire_runtime_tree(self, built_distributions: Path) -> None:
        """Every dependency is an exact pin, so a release installs a frozen tree."""
        wheel = _single(built_distributions, 'mcp_proxy_for_aws_cli-*.whl')
        requirements = _requires_dist(wheel)

        # The library's runtime closure is ~83 packages plus the library itself.
        assert len(requirements) > 50
        for requirement in requirements:
            assert '==' in requirement.split(';')[0], requirement

    def test_wheel_pins_the_library_at_the_matching_version(
        self, built_distributions: Path
    ) -> None:
        """The wrapper and library are released in lockstep."""
        wheel = _single(built_distributions, 'mcp_proxy_for_aws_cli-*.whl')
        version = wheel.name.split('-')[1]

        assert f'mcp-proxy-for-aws=={version}' in _requires_dist(wheel)

    def test_wheel_preserves_environment_markers(self, built_distributions: Path) -> None:
        """Platform-specific pins keep their markers rather than applying everywhere."""
        wheel = _single(built_distributions, 'mcp_proxy_for_aws_cli-*.whl')

        assert [r for r in _requires_dist(wheel) if ';' in r]

    def test_sdist_bundles_the_derived_pins(self, built_distributions: Path) -> None:
        """The sdist carries its pins so it does not need uv or the workspace."""
        sdist = _single(built_distributions, 'mcp_proxy_for_aws_cli-*.tar.gz')
        with tarfile.open(sdist) as archive:
            names = archive.getnames()

        assert any(n.endswith('/_runtime_pins.txt') for n in names)


class TestBuildFromSdist:
    """The wrapper must produce identical pinned metadata when built from its sdist."""

    def test_wheel_built_from_sdist_without_uv_has_identical_pins(
        self, built_distributions: Path, tmp_path: Path
    ) -> None:
        """Rebuild from the sdist in isolation, with `uv` absent from the build's PATH.

        This exercises the baked-pins path: no workspace above the project and no uv to
        export from, which is how a from-sdist install would build the wrapper.
        """
        sdist = _single(built_distributions, 'mcp_proxy_for_aws_cli-*.tar.gz')
        expected = _requires_dist(_single(built_distributions, 'mcp_proxy_for_aws_cli-*.whl'))

        extracted = tmp_path / 'src'
        with tarfile.open(sdist) as archive:
            archive.extractall(extracted)  # noqa: S202 - our own freshly built artifact
        project = _single(extracted, 'mcp_proxy_for_aws_cli-*')

        uv = shutil.which('uv')
        assert uv, 'uv is required to run this test'
        # A PATH without uv, so a regression that ignores the baked pins cannot pass by
        # silently falling back to `uv export`.
        sandbox_bin = tmp_path / 'bin'
        sandbox_bin.mkdir()
        for tool in ('python3', 'sh'):
            if (found := shutil.which(tool)) is not None:
                (sandbox_bin / tool).symlink_to(found)

        out = tmp_path / 'out'
        result = subprocess.run(
            [uv, 'build', '--wheel', '--out-dir', str(out), '.'],
            cwd=project,
            capture_output=True,
            text=True,
            env={'PATH': str(sandbox_bin), 'HOME': str(tmp_path)},
        )
        if result.returncode != 0:
            pytest.fail(f'from-sdist build failed:\n{result.stdout}\n{result.stderr}')

        assert _requires_dist(_single(out, '*.whl')) == expected
