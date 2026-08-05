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

"""Build hooks that pin `mcp-proxy-for-aws` to the exact runtime tree in `uv.lock`.

`mcp-proxy-for-aws` is a metadata-only wrapper around `mcp-proxy-for-aws-lib`. The
library declares loose ranges so that programmatic users can co-resolve it with their own
dependencies; the wrapper declares the entire runtime closure as `==` pins so that
`uvx mcp-proxy-for-aws@<version>` installs a frozen tree and cannot silently adopt a
newer -- possibly compromised -- release of a transitive dependency.

The pins are never hand-maintained. They are a deterministic projection of the workspace
`uv.lock` computed at build time, so a dependency bump is an ordinary single-commit
`uv.lock` change:

* Building in the repo (the release path) shells out to `uv export`, scoped to the
  library's runtime closure.
* Building from the wrapper's sdist reads `_runtime_pins.txt`, which the sdist build hook
  bakes in. This keeps sdist builds working without `uv` and without the workspace.

Published *wheels* carry fully static `Requires-Dist` metadata, so these hooks never run
on an end user's machine.
"""

import re
import subprocess  # nosec B404 - only used to run a fixed `uv export` argv (shell=False)
from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.metadata.plugin.interface import MetadataHookInterface
from pathlib import Path
from typing import Any, ClassVar


#: Name of the distribution that actually contains the code.
LIB_NAME = 'mcp-proxy-for-aws-lib'

#: Matches a PEP 440 pre-release/dev segment in a `name==version` pin (before any marker).
#: A pinned pre-release makes the wrapper uninstallable without `--prerelease=allow`,
#: which end users of `uvx mcp-proxy-for-aws` cannot pass.
_PRERELEASE_RE = re.compile(
    r'==\s*[0-9][0-9.]*\s*(?:a|b|rc|alpha|beta|dev|pre)[0-9]*', re.IGNORECASE
)


def _reject_prereleases(pins: list[str]) -> list[str]:
    """Fail the build if any pin is a pre-release; otherwise return the pins unchanged."""
    offenders = [p for p in pins if _PRERELEASE_RE.search(p.split(';', 1)[0])]
    if offenders:
        raise RuntimeError(
            'Refusing to build mcp-proxy-for-aws: the pinned runtime closure contains '
            'pre-release versions, which make the wrapper uninstallable without '
            f'`--prerelease=allow` (which uvx/pip users cannot pass): {offenders}. '
            'Re-lock without pre-releases (`uv lock`) and rebuild.'
        )
    return pins


#: Pin list baked into the sdist so that from-sdist builds need neither uv nor the
#: workspace. Relative to the wrapper's project root.
BAKED_PINS_FILENAME = '_runtime_pins.txt'

_PINS_HEADER = (
    '# Generated at build time from the workspace uv.lock. Do not edit.\n'
    f'# Exact runtime closure of {LIB_NAME}, used to pin mcp-proxy-for-aws.\n'
)


def _export_runtime_closure(workspace_root: Path) -> list[str]:
    """Return the library's exact runtime closure by asking uv to export it.

    Scoping matters: `uv.lock` is the *whole* workspace resolution, which also contains
    dev-dependency groups and the `examples/mcp-client/*` members' trees. Baking those in
    would over-pin the wrapper by hundreds of packages and make it practically
    uninstallable. `--package <lib> --no-dev` narrows the export to just the library's
    runtime dependencies.

    Args:
        workspace_root: Directory containing the workspace `pyproject.toml` and `uv.lock`.

    Returns:
        Requirement strings such as `boto3==1.43.51`, with environment markers preserved.

    Raises:
        RuntimeError: If uv is unavailable, the export fails, or it yields no pins.
    """
    command = [
        'uv',
        'export',
        # The lock is authoritative here; never let a build silently re-resolve it.
        '--frozen',
        '--package',
        LIB_NAME,
        '--no-dev',
        '--no-hashes',
        '--no-emit-workspace',
        '--no-annotate',
        '--no-header',
    ]
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603 fixed argv, no shell
            command,
            cwd=workspace_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            'Cannot pin mcp-proxy-for-aws: `uv` was not found on PATH and no '
            f'{BAKED_PINS_FILENAME} was bundled. Install uv to build from the repository.'
        ) from exc
    except subprocess.CalledProcessError as exc:
        # Most often a stale lock: `uv export --frozen` refuses to run when uv.lock does
        # not match the manifests. Surface uv's own message rather than a bare exit code.
        raise RuntimeError(
            'Cannot pin mcp-proxy-for-aws: `uv export` failed in '
            f'{workspace_root}. Run `uv lock` and rebuild.\n{exc.stderr.strip()}'
        ) from exc

    pins = [line.strip() for line in completed.stdout.splitlines() if '==' in line]
    if not pins:
        # Never publish a wrapper with an empty or partial pin set: that would silently
        # ship an unpinned package, which is precisely what this package exists to avoid.
        raise RuntimeError(
            f'Cannot pin mcp-proxy-for-aws: `uv export` returned no pins for {LIB_NAME}.'
        )
    return pins


def _read_baked_pins(path: Path) -> list[str]:
    """Read pins previously baked into the sdist by `SdistPinsBuildHook`."""
    return [
        line.strip()
        for line in path.read_text(encoding='utf-8').splitlines()
        if line.strip() and not line.startswith('#')
    ]


def resolve_runtime_pins(project_root: Path) -> list[str]:
    """Resolve the library's runtime pins for whichever build context we are in.

    Args:
        project_root: The wrapper's project root (the directory holding its pyproject).

    Returns:
        The exact runtime closure of the library, with environment markers preserved.
    """
    baked = project_root / BAKED_PINS_FILENAME
    if baked.is_file():
        return _reject_prereleases(_read_baked_pins(baked))
    # In the repo the wrapper lives at <workspace>/packages/proxy.
    return _reject_prereleases(_export_runtime_closure(project_root.resolve().parents[1]))


class PinnedDependenciesMetadataHook(MetadataHookInterface):
    """Fill in the wrapper's `dependencies` with the frozen runtime tree."""

    PLUGIN_NAME: ClassVar[str] = 'pinned-dependencies'

    def update(self, metadata: dict[str, Any]) -> None:
        """Set `dependencies` to the library plus its exact runtime closure.

        Args:
            metadata: Core project metadata to mutate in place.
        """
        # The wrapper and the library are released together from the same commit, so the
        # wrapper's own version is the correct pin for the library.
        metadata['dependencies'] = [
            f'{LIB_NAME}=={metadata["version"]}',
            *resolve_runtime_pins(Path(self.root)),
        ]


class SdistPinsBuildHook(BuildHookInterface):
    """Bake the resolved pins into the sdist so it builds without uv or the workspace."""

    PLUGIN_NAME: ClassVar[str] = 'sdist-pins'

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """Generate and force-include the pins file when building an sdist.

        Args:
            version: Build target version, unused.
            build_data: Hatchling build data to mutate in place.
        """
        if self.target_name != 'sdist':
            return
        pins_path = Path(self.root) / BAKED_PINS_FILENAME
        if not pins_path.is_file():
            pins_path.write_text(
                _PINS_HEADER + '\n'.join(resolve_runtime_pins(Path(self.root))) + '\n',
                encoding='utf-8',
            )
        build_data.setdefault('force_include', {})[str(pins_path)] = BAKED_PINS_FILENAME
