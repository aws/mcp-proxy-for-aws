import pytest


def pytest_collection_modifyitems(config, items):
    """Mark the entire module as unit."""
    for item in items:
        if 'unit' in item.nodeid:
            item.add_marker(pytest.mark.unit)
        elif 'integ' in item.nodeid:
            item.add_marker(pytest.mark.integ)
