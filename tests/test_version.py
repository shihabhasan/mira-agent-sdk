"""The version sealed into evidence has to be the version that ran.

Every record an SDK-instrumented agent writes carries the SDK that produced it.
For seven releases that was a hard-coded "mira-agent-sdk/0.2.0", so every piece
of evidence misstated its own provenance — and a sealed record cannot be
corrected afterwards, only superseded. These pin the version to one place and
that place to the package metadata.
"""
import re
import tomllib
from pathlib import Path

import mira_agent
from mira_agent import client
from mira_agent._version import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_the_code_version_matches_pyproject():
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert __version__ == declared, (
        f"_version.py says {__version__} and pyproject.toml says {declared}; bump both")


def test_the_package_exports_the_same_version():
    assert mira_agent.__version__ == __version__


def test_no_version_is_hard_coded_into_what_gets_sealed():
    """The failure this guards: a literal that stops being true at the next
    release and goes on being signed into records for months."""
    src = Path(client.__file__).read_text()
    assert not re.search(r'"mira-agent-sdk/\d+\.\d+\.\d+"', src), \
        "a literal SDK version is sealed into records; use _version.__version__"
