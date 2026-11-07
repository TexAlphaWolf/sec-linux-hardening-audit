import os
from pathlib import Path

import pytest

from tests.fixtures import FixtureHost, build_hardened, build_insecure

posix_only = pytest.mark.skipif(os.name != "posix", reason="needs POSIX permissions")


@pytest.fixture(params=["debian", "rhel"])
def family(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
def hardened(tmp_path: Path, family: str) -> FixtureHost:
    build_hardened(tmp_path / "root", family)
    return FixtureHost(tmp_path / "root")


@pytest.fixture
def insecure(tmp_path: Path, family: str) -> FixtureHost:
    build_insecure(tmp_path / "root-insecure", family)
    return FixtureHost(tmp_path / "root-insecure")
