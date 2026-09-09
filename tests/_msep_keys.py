"""A named key ring for the MSEP tests.

The control plane derives boundary keys by name from a workspace seed. The SDK
core has no ring, so the tests get one: deterministic from the name, wrapping
the SDK key so it also answers to `key_id_hex`, which is what the ported test
bodies call.
"""
import hashlib

from mira_agent_core.keys import SigningKey as _Key


class SigningKey:
    """The SDK key, with the control plane's attribute names alongside."""

    def __init__(self, inner: _Key):
        self._k = inner

    @classmethod
    def generate(cls, name: str) -> "SigningKey":
        return cls(_Key.generate(name))

    @classmethod
    def from_seed(cls, name: str, seed: bytes) -> "SigningKey":
        return cls(_Key.from_seed(name, seed))

    @property
    def name(self) -> str: return self._k.name
    @property
    def public_bytes(self) -> bytes: return self._k.public_bytes
    @property
    def key_id(self) -> str: return self._k.key_id
    @property
    def key_id_hex(self) -> str: return self._k.key_id
    def sign(self, message: bytes) -> bytes: return self._k.sign(message)


class KeyRing:
    def __init__(self, seed: bytes = b"mira-agent-sdk-tests"):
        self._seed = seed
        self._keys: dict[str, SigningKey] = {}

    def get(self, name: str) -> SigningKey:
        if name not in self._keys:
            self._keys[name] = SigningKey.from_seed(
                name, hashlib.sha256(self._seed + b"\n" + name.encode()).digest())
        return self._keys[name]
