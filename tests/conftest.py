"""Root pytest hooks: mark everything under tests/integration as `integration`."""

from pathlib import Path

import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "integration" in Path(str(item.fspath)).parts:
            item.add_marker(pytest.mark.integration)
