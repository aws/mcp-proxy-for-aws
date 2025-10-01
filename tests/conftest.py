import pathlib
import pytest


def pytest_collection_modifyitems(config, items):
    """Mark the entire module as unit."""
    rootdir = pathlib.Path(config.rootdir)
    for item in items:
        rel_path = pathlib.Path(item.fspath).relative_to(rootdir)
        if 'unit' in rel_path.parts:
            item.add_marker(pytest.mark.unit)
        elif 'integ' in rel_path.parts:
            item.add_marker(pytest.mark.integ)
