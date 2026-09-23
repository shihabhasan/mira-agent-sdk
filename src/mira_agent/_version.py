"""The one place the SDK's version lives in code.

It lives here rather than in `__init__` because `__init__` imports `client`
before it could define anything, and `client` needs the version: it seals it
into every record an agent writes. That record used to carry a hard-coded
"mira-agent-sdk/0.2.0" through seven releases, so every piece of evidence an
SDK-instrumented agent produced misstated which code produced it — and a
sealed record cannot be corrected afterwards, only superseded.

`tests/test_version.py` fails if this and pyproject.toml disagree.
"""
__version__ = "0.10.0"
