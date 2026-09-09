"""One helper so the protocol modules run on either key type.

The control plane's key exposes `key_id_hex`; the SDK core's exposes
`key_id` as a hex string. Both derive it the same way, which the conformance
vectors prove, so the difference is a name and nothing else.
"""


def _kid(key) -> str:
    v = getattr(key, "key_id_hex", None)
    if v is None:
        v = key.key_id
    return v if isinstance(v, str) else v.hex()
