"""Red Cards that leave the workflow they were issued in.

An adverse trust assertion travels in every successor envelope, so it reaches
every boundary downstream of the event. It does not reach a boundary that
starts a fresh workflow for the same actor tomorrow, because nothing carried it
there. Lineage-bound propagation is the right default for the hot path and it
is not sufficient on its own. Say it plainly: cross-workflow propagation is a
push from the control plane, and a push of "this actor is no longer trusted"
is a revocation list by another name.

The OpenID Shared Signals Framework and CAEP already exist for exactly this:
one party tells another that a subject's standing changed, as a signed
Security Event Token. So rather than invent a feed, a Red Card is emitted as a
SET, and a boundary ingests SETs into the same local adverse store the
envelope path consults. The MSEP-specific event carries the signed assertion
itself, with its trigger commitment, so a receiver can verify it against the
issuing boundary's key and tie it to the exact transition that caused it. A
CAEP assurance-level-change event is emitted alongside so receivers that only
speak the standard vocabulary still get the signal, without the lineage.

Red Card is therefore the execution-lineage-bound extension of CAEP, not a
replacement for it.
"""

from __future__ import annotations

from mira_agent.msep._compat import _kid

import base64
import json
import os
import time
from dataclasses import dataclass

from mira_agent_core.keys import SigningKey
from mira_agent_core.keys import verify as verify_signature
from mira_agent.msep.trust import AdverseTrustAssertion, Severity

# Our event, carrying the assertion. Namespaced so it cannot collide.
EVENT_RED_CARD = "https://liora-ai.co/secevent/msep/red-card"
EVENT_REINSTATED = "https://liora-ai.co/secevent/msep/reinstated"
# The standard CAEP companion: a change in assurance level for the subject.
EVENT_CAEP_ASSURANCE = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

_LEVEL = {Severity.TERMINAL: "nal0", Severity.RESTRICTED: "nal1", Severity.NOTED: "nal2"}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass(frozen=True)
class SecurityEventToken:
    """RFC 8417 SET as a compact JWS, EdDSA-signed."""

    issuer: str
    audience: str
    subject: str
    events: dict
    jti: str
    iat: int
    key_id: str = ""
    signature: str = ""

    def payload(self) -> dict:
        return {
            "iss": self.issuer, "aud": self.audience, "iat": self.iat, "jti": self.jti,
            # RFC 9493 subject identifier: the actor's execution identity.
            "sub_id": {"format": "opaque", "id": self.subject},
            "events": self.events,
        }

    def header(self) -> dict:
        return {"typ": "secevent+jwt", "alg": "EdDSA", "kid": self.key_id}

    def signing_input(self) -> bytes:
        h = _b64u(json.dumps(self.header(), separators=(",", ":"), sort_keys=True).encode())
        p = _b64u(json.dumps(self.payload(), separators=(",", ":"), sort_keys=True).encode())
        return f"{h}.{p}".encode()

    def compact(self) -> str:
        return f"{self.signing_input().decode()}.{self.signature}"


def emit_red_card(card: AdverseTrustAssertion, *, issuer: str, audience: str,
                  key: SigningKey, now_ms: int | None = None) -> SecurityEventToken:
    """Turn a Red Card into a SET the control plane can push to every boundary."""
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    reinstated = card.severity is Severity.NOTED and card.resolution
    events = {
        (EVENT_REINSTATED if reinstated else EVENT_RED_CARD): {
            "assertion": card.to_wire(),
            "trigger_commitment": card.trigger_commitment,
            "issued_by": card.issued_by,
        },
        EVENT_CAEP_ASSURANCE: {
            "event_timestamp": now // 1000,
            "current_level": _LEVEL[card.severity],
            "previous_level": "nal2" if not reinstated else "nal0",
            "change_direction": "increase" if reinstated else "decrease",
            "reason_admin": {"en": card.reason},
        },
    }
    tok = SecurityEventToken(issuer=issuer, audience=audience, subject=card.subject,
                             events=events, jti=os.urandom(12).hex(), iat=now // 1000,
                             key_id=_kid(key))
    sig = _b64u(key.sign(tok.signing_input()))
    return SecurityEventToken(**{**tok.__dict__, "signature": sig})


class SignalIngestError(ValueError):
    pass


def ingest(compact: str, *, resolve_key, expected_audience: str | None = None,
           max_age_s: int = 600, now_ms: int | None = None) -> AdverseTrustAssertion:
    """Verify a SET and return the assertion it carries.

    Two signatures are checked, not one. The token proves the control plane
    sent it; the assertion inside proves a boundary issued it. A control plane
    that could mint Red Cards on its own would be an actor asserting trust
    state about subjects it never observed, which is the thing the design
    says only a boundary may do.
    """
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    try:
        h_b64, p_b64, sig_b64 = compact.split(".")
        header = json.loads(_unb64u(h_b64)); payload = json.loads(_unb64u(p_b64))
    except Exception as e:
        raise SignalIngestError(f"malformed SET: {e}") from e
    if header.get("alg") != "EdDSA" or header.get("typ") != "secevent+jwt":
        raise SignalIngestError("unsupported SET header")
    pub = resolve_key(header.get("kid", ""))
    if pub is None:
        raise SignalIngestError("SET signed by an unknown key")
    if not verify_signature(pub, _unb64u(sig_b64), f"{h_b64}.{p_b64}".encode()):
        raise SignalIngestError("SET signature does not verify")
    if expected_audience and payload.get("aud") != expected_audience:
        raise SignalIngestError("SET not addressed to this boundary")
    if now // 1000 - int(payload.get("iat", 0)) > max_age_s:
        raise SignalIngestError("SET too old")

    ev = payload.get("events", {})
    body = ev.get(EVENT_RED_CARD) or ev.get(EVENT_REINSTATED)
    if body is None:
        raise SignalIngestError("SET carries no MSEP assertion")
    card = AdverseTrustAssertion.from_wire(body["assertion"])
    issuer_pub = resolve_key(card.key_id)
    if issuer_pub is None or not card.signature_valid(issuer_pub):
        raise SignalIngestError("assertion inside the SET does not verify against its issuer")
    if card.subject != payload["sub_id"]["id"]:
        raise SignalIngestError("SET subject and assertion subject differ")
    return card
