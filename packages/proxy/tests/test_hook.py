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

"""Tests for the build hooks that pin `mcp-proxy-for-aws` from `uv.lock`.

These guard the properties that make the pinned distribution correct: the pins cover the
library's runtime closure only, environment markers survive, and a build fails loudly
rather than shipping a partially-pinned wrapper.
"""

import pytest
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch


if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 has no tomllib.
    import tomli as tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hatch_build import (  # noqa: E402
    BAKED_PINS_FILENAME,
    LIB_NAME,
    PinnedDependenciesMetadataHook,
    SdistPinsBuildHook,
    resolve_runtime_pins,
)


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Dev-only tooling from the `dev` dependency group. The wrapper pins runtime dependencies,
# so none of these may leak into its metadata.
DEV_ONLY_PACKAGES = ('pytest', 'ruff', 'pyright', 'commitizen', 'pre-commit', 'pytest-cov')

# Packages that only reach the lock through the examples/mcp-client/* workspace members.
EXAMPLE_ONLY_PACKAGES = ('langchain', 'llama-index', 'strands-agents', 'agent-framework')


def _names(pins: list[str]) -> set[str]:
    """Return the distribution names from a list of requirement strings."""
    return {pin.split('==')[0].strip().lower() for pin in pins}


def _wrapper_root_in_fake_workspace(tmp_path: Path) -> Path:
    """Return a wrapper project root laid out inside a throwaway workspace with a lock.

    The lock only has to exist: these tests stub out the `uv export` that would read it.
    """
    (tmp_path / 'uv.lock').write_text('', encoding='utf-8')
    project = tmp_path / 'packages' / 'proxy'
    project.mkdir(parents=True)
    return project


@pytest.fixture(scope='module')
def repo_pins() -> list[str]:
    """The runtime pins derived from the repository's committed uv.lock."""
    return resolve_runtime_pins(PROJECT_ROOT)


class TestResolveRuntimePins:
    """Deriving pins from the workspace lock."""

    @pytest.mark.unit
    def test_derives_pins_from_workspace_lock(self, repo_pins: list[str]) -> None:
        """The repository checkout yields a non-trivial set of exact pins."""
        assert repo_pins
        assert all('==' in pin for pin in repo_pins)
        # The real closure is ~83 packages; a handful would mean the export was mis-scoped.
        assert len(repo_pins) > 50

    @pytest.mark.unit
    def test_pins_include_the_direct_runtime_dependencies(self, repo_pins: list[str]) -> None:
        """The library's own declared runtime dependencies are present."""
        assert {'boto3', 'botocore', 'fastmcp'} <= _names(repo_pins)

    @pytest.mark.unit
    def test_pins_are_exact_versions(self, repo_pins: list[str]) -> None:
        """No pin uses a range operator, which would defeat the freeze."""
        for pin in repo_pins:
            requirement = pin.split(';')[0]
            assert '==' in requirement, pin
            assert not any(op in requirement for op in ('>=', '<=', '~=', '>', '<', '!=')), pin

    @pytest.mark.unit
    def test_environment_markers_are_preserved(self, repo_pins: list[str]) -> None:
        """Platform-specific pins keep their markers so they do not over-constrain.

        Without markers, a pin such as `colorama; sys_platform == 'win32'` would apply
        everywhere and could make the wrapper uninstallable off that platform.
        """
        marked = [pin for pin in repo_pins if ';' in pin]
        assert marked, 'expected at least one marker-qualified pin'
        assert any('python_full_version' in pin or 'sys_platform' in pin for pin in marked)

    @pytest.mark.unit
    def test_excludes_dev_dependency_groups(self, repo_pins: list[str]) -> None:
        """Dev tooling must not be pinned as a runtime dependency of the wrapper."""
        leaked = _names(repo_pins) & set(DEV_ONLY_PACKAGES)
        assert not leaked, f'dev-only packages leaked into runtime pins: {sorted(leaked)}'

    @pytest.mark.unit
    def test_excludes_example_workspace_member_trees(self, repo_pins: list[str]) -> None:
        """The example clients' dependency trees must not be pinned either.

        `uv.lock` covers the whole workspace, so an unscoped export would bake in these
        trees and over-pin the wrapper by hundreds of packages.
        """
        leaked = _names(repo_pins) & set(EXAMPLE_ONLY_PACKAGES)
        assert not leaked, f'example-only packages leaked into runtime pins: {sorted(leaked)}'

    @pytest.mark.unit
    def test_excludes_the_workspace_members_themselves(self, repo_pins: list[str]) -> None:
        """Workspace members are not published deps and must be excluded."""
        assert LIB_NAME not in _names(repo_pins)
        assert not any(name.startswith('mcp-client-example') for name in _names(repo_pins))

    @pytest.mark.unit
    def test_is_deterministic(self) -> None:
        """The same lock always projects to the same pins, in the same order."""
        assert resolve_runtime_pins(PROJECT_ROOT) == resolve_runtime_pins(PROJECT_ROOT)

    @pytest.mark.unit
    def test_prefers_baked_pins_when_there_is_no_workspace(self, tmp_path: Path) -> None:
        """A bundled pins file is used verbatim, without invoking uv.

        This is the from-sdist path: the project has no workspace lock above it.
        """
        project = tmp_path / 'packages' / 'proxy'
        project.mkdir(parents=True)
        (project / BAKED_PINS_FILENAME).write_text(
            '# generated\nboto3==1.2.3\ncolorama==0.4.6 ; sys_platform == "win32"\n',
            encoding='utf-8',
        )
        with patch('hatch_build.subprocess.run') as mock_run:
            pins = resolve_runtime_pins(project)
        mock_run.assert_not_called()
        assert pins == ['boto3==1.2.3', 'colorama==0.4.6 ; sys_platform == "win32"']

    @pytest.mark.unit
    def test_workspace_lock_outranks_a_leftover_pins_file(self, tmp_path: Path) -> None:
        """The lock wins whenever it is reachable, even if a pins file is lying around.

        `_runtime_pins.txt` is a gitignored by-product of any earlier sdist build, so it is
        routinely present in a working tree. If it outranked the lock, a build would ship
        those stale pins -- silently, and with no way to tell from the artifact.
        """
        (tmp_path / 'uv.lock').write_text('', encoding='utf-8')
        project = tmp_path / 'packages' / 'proxy'
        project.mkdir(parents=True)
        (project / BAKED_PINS_FILENAME).write_text('boto3==0.0.1\n', encoding='utf-8')
        completed = subprocess.CompletedProcess(['uv'], 0, stdout='boto3==1.2.3\n', stderr='')

        with patch('hatch_build.subprocess.run', return_value=completed) as mock_run:
            pins = resolve_runtime_pins(project)

        mock_run.assert_called_once()
        assert pins == ['boto3==1.2.3']


class TestResolveRuntimePinsFailures:
    """A build must fail loudly rather than emit an unpinned wrapper."""

    @pytest.mark.unit
    def test_raises_when_neither_lock_nor_baked_pins_exist(self, tmp_path: Path) -> None:
        """A partial checkout names both missing inputs instead of blaming a missing uv.

        Without the check they are indistinguishable: `subprocess` reports a non-existent
        `cwd` as `FileNotFoundError`, exactly as it reports an absent executable.
        """
        project = tmp_path / 'packages' / 'proxy'
        project.mkdir(parents=True)
        with (
            patch('hatch_build.subprocess.run') as mock_run,
            pytest.raises(RuntimeError, match='found neither the workspace lock'),
        ):
            resolve_runtime_pins(project)
        mock_run.assert_not_called()

    @pytest.mark.unit
    def test_raises_when_uv_export_fails(self, tmp_path: Path) -> None:
        """A failing `uv export` (for example a stale lock) surfaces uv's message."""
        project = _wrapper_root_in_fake_workspace(tmp_path)
        error = subprocess.CalledProcessError(2, ['uv'], stderr='the lockfile is outdated')
        with (
            patch('hatch_build.subprocess.run', side_effect=error),
            pytest.raises(RuntimeError, match='the lockfile is outdated'),
        ):
            resolve_runtime_pins(project)

    @pytest.mark.unit
    def test_raises_when_uv_is_unavailable(self, tmp_path: Path) -> None:
        """No uv and no bundled pins is an error, not an empty dependency list."""
        project = _wrapper_root_in_fake_workspace(tmp_path)
        with (
            patch('hatch_build.subprocess.run', side_effect=FileNotFoundError),
            pytest.raises(RuntimeError, match='uv'),
        ):
            resolve_runtime_pins(project)

    @pytest.mark.unit
    def test_raises_when_export_yields_no_pins(self, tmp_path: Path) -> None:
        """An empty export must not silently produce an unpinned wrapper.

        Observed for real: `uv export --frozen` can succeed while returning nothing useful,
        which would otherwise ship a wrapper that pins only the library.
        """
        project = _wrapper_root_in_fake_workspace(tmp_path)
        completed = subprocess.CompletedProcess(['uv'], 0, stdout='# comment only\n', stderr='')
        with (
            patch('hatch_build.subprocess.run', return_value=completed),
            pytest.raises(RuntimeError, match='no pins'),
        ):
            resolve_runtime_pins(project)


class TestPinnedDependenciesMetadataHook:
    """The metadata hook's contribution to the built distribution."""

    @pytest.mark.unit
    def test_sets_dependencies_with_lib_pinned_first(self) -> None:
        """Dependencies are the version-locked library followed by its closure."""
        hook = PinnedDependenciesMetadataHook(str(PROJECT_ROOT), {})
        metadata: dict = {'version': '9.9.9'}
        hook.update(metadata)

        assert metadata['dependencies'][0] == f'{LIB_NAME}==9.9.9'
        assert len(metadata['dependencies']) > 50

    @pytest.mark.unit
    def test_pins_library_to_the_wrapper_version(self) -> None:
        """The two distributions are released in lockstep from the same commit."""
        hook = PinnedDependenciesMetadataHook(str(PROJECT_ROOT), {})
        metadata: dict = {'version': '1.2.3'}
        hook.update(metadata)

        assert f'{LIB_NAME}==1.2.3' in metadata['dependencies']
        assert sum(1 for d in metadata['dependencies'] if d.startswith(LIB_NAME)) == 1


class TestSdistPinsBuildHook:
    """Baking pins into the sdist so it builds without uv or the workspace."""

    @pytest.mark.unit
    def test_writes_and_force_includes_pins_for_sdist(self, tmp_path: Path) -> None:
        """Building an sdist generates the pins file and ships it at the root.

        The hook writes into its *root*, so the root is a throwaway directory here. Using
        the real project root would drop `_runtime_pins.txt` into the working tree, and an
        interrupted run would leave it there -- where `resolve_runtime_pins` prefers it over
        the lock and would silently freeze every later build against stale pins.
        """
        hook = SdistPinsBuildHook(
            str(tmp_path),  # root: where the pins file is written
            {},
            {},
            None,
            str(tmp_path / 'dist'),  # directory: build output, unused by this hook
            'sdist',  # type: ignore[arg-type]
        )
        build_data: dict = {}
        with patch('hatch_build.resolve_runtime_pins', return_value=['boto3==1.2.3']):
            hook.initialize('standard', build_data)

        pins_path = tmp_path / BAKED_PINS_FILENAME
        assert pins_path.is_file()
        assert build_data['force_include'][str(pins_path)] == BAKED_PINS_FILENAME
        assert 'boto3==1.2.3' in pins_path.read_text(encoding='utf-8')

    @pytest.mark.unit
    def test_does_nothing_for_wheel_target(self, tmp_path: Path) -> None:
        """Wheels get their pins through the metadata hook, so nothing is bundled."""
        hook = SdistPinsBuildHook(
            str(tmp_path),
            {},
            {},
            None,
            str(tmp_path),
            'wheel',  # type: ignore[arg-type]
        )
        build_data: dict = {}
        hook.initialize('standard', build_data)

        assert build_data == {}
        assert not (tmp_path / BAKED_PINS_FILENAME).exists()


class TestPackagingInvariants:
    """Properties of the checked-in package configuration."""

    @pytest.mark.unit
    def test_license_files_match_the_repository_originals(self) -> None:
        """The wrapper needs its own copies (sdists cannot escape their root).

        Guards against the copies drifting from the canonical files at the repo root.
        """
        for filename in ('LICENSE', 'NOTICE'):
            assert (PROJECT_ROOT / filename).read_bytes() == (
                WORKSPACE_ROOT / filename
            ).read_bytes(), f'packages/proxy/{filename} has drifted from the repository root'

    @pytest.mark.unit
    def test_wrapper_version_matches_library_version(self) -> None:
        """Lockstep versioning; the wrapper pins the library to its own version."""

        def version_of(pyproject: Path) -> str:
            with pyproject.open('rb') as handle:
                return tomllib.load(handle)['project']['version']

        assert version_of(PROJECT_ROOT / 'pyproject.toml') == version_of(
            WORKSPACE_ROOT / 'pyproject.toml'
        )

    @pytest.mark.unit
    def test_wrapper_is_excluded_from_the_uv_workspace(self) -> None:
        """Membership would make `uv lock` build metadata from the lock it is writing."""
        with (WORKSPACE_ROOT / 'pyproject.toml').open('rb') as handle:
            workspace = tomllib.load(handle)['tool']['uv']['workspace']

        assert 'packages/proxy' in workspace.get('exclude', [])
