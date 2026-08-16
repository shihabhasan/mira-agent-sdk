"""The Mira client: authorize actions, and leave signed evidence.

    from mira_agent import Mira

    mira = Mira()                                  # MIRA_API_KEY from env

    with mira.run(intent="Deploy CHG-0048817") as run:
        d = run.authorize(action="deploy",
                          artifact="update_set:SLA_RECALC_v7",
                          target_instance="prod")
        if not d.allowed:
            raise Interdicted(d.reason)            # BOD-1.1, ~10µs
        deploy(...)

Design commitments, in the order they matter:

  1. The gate is local and synchronous. It evaluates a digest-pinned bundle in
     memory, so authorizing costs microseconds, not a network round trip.
  2. The gate fails CLOSED. If no bundle can be loaded, everything is refused.
     A governance gate that fails open is not a gate.
  3. Recording fails OPEN and never blocks. Evidence is queued and shipped by
     a background thread; a control-plane outage must not take the agent down.
  4. Each step is signed by the CLIENT before it leaves the process, so a
     record attests to what this agent did — not merely to what a server
     received. The control plane counter-signs and sequences.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Iterator

from mira_agent.core.keys import SigningKey
from mira_agent.core.records import (
    PAYLOAD_TYPE,
    RecordType,
    build_statement,
    canonical,
    content_hash,
    now_ms,
    pae,
    sha256_hex,
)

from .policy import Decision, PolicyBundle, evaluate

log = logging.getLogger("mira")

__all__ = ["Mira", "Interdicted", "MiraConfigError", "Decision"]


class Interdicted(RuntimeError):
    """Raised when a proposed action is refused by the basis of design."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(
            f"refused under {decision.rule_id} "
            f"({decision.bundle_id}@{decision.bundle_version}): {decision.reason}"
        )


class MiraConfigError(RuntimeError):
    """The client cannot operate safely — refuse rather than guess."""


@dataclass
class _Step:
    seq: int
    envelope: dict


class Mira:
    """A governed session against one Mira workspace."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        *,
        policy: PolicyBundle | dict | None = None,
        agent: str = "agent",
        signing_key: SigningKey | str | Path | None = None,
        offline: bool = False,
        fail_closed: bool = True,
    ):
        self.base_url = (base_url or os.environ.get("MIRA_BASE_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("MIRA_API_KEY", "")
        self.agent = agent
        self.offline = offline
        self.fail_closed = fail_closed
        self._lock = threading.Lock()

        # ---- identity: this agent signs its own claims -------------------
        if isinstance(signing_key, SigningKey):
            self.key = signing_key
        elif signing_key is not None:
            self.key = SigningKey.load(f"mira/agent/{agent}", signing_key)
        else:
            env_seed = os.environ.get("MIRA_AGENT_SEED")
            if env_seed:
                self.key = SigningKey.from_seed(
                    f"mira/agent/{agent}", bytes.fromhex(env_seed)
                )
            else:
                # Ephemeral by default. The public key travels with every
                # record, so the evidence is still self-consistent; it just
                # cannot be tied to a long-lived identity until one is
                # registered. Honest default, no silent key files.
                self.key = SigningKey.generate(f"mira/agent/{agent}")

        # ---- policy: pinned at startup, evaluated locally ----------------
        self.bundle: PolicyBundle | None = None
        if isinstance(policy, PolicyBundle):
            self.bundle = policy
        elif isinstance(policy, dict):
            self.bundle = PolicyBundle.from_dict(policy)
        elif not offline:
            self.bundle = self._fetch_bundle()

        if self.bundle is None and self.fail_closed and not offline:
            raise MiraConfigError(
                "no policy bundle could be loaded, and fail_closed is set. "
                "Every action would be refused. Pass policy=..., set "
                "MIRA_BASE_URL/MIRA_API_KEY, or construct with offline=True."
            )

        # ---- transport: evidence, off the critical path ------------------
        self._transport = None
        if not offline and self.base_url and self.api_key:
            from .transport import RecordTransport

            self._transport = RecordTransport(self.base_url, self.api_key)

    # ------------------------------------------------------------ policy

    def _fetch_bundle(self) -> PolicyBundle | None:
        if not (self.base_url and self.api_key):
            return None
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/v1/policy/bundle",
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                return PolicyBundle.from_dict(json.loads(r.read()))
        except Exception as e:  # noqa: BLE001 — any failure means "no bundle"
            log.warning("mira: could not fetch policy bundle (%s)", e)
            return None

    def refresh_policy(self) -> bool:
        """Re-pin the bundle. Keeps the last known-good one on failure — a
        transient network problem must not silently widen or narrow policy."""
        fresh = self._fetch_bundle()
        if fresh is None:
            return False
        with self._lock:
            self.bundle = fresh
        return True

    @property
    def policy_digest(self) -> str | None:
        return self.bundle.digest if self.bundle else None

    # --------------------------------------------------------------- runs

    @contextmanager
    def run(self, intent: str, **meta: Any) -> Iterator["Run"]:
        """Open a governed transaction. Everything inside shares one lineage."""
        r = Run(self, intent=intent, meta=meta)
        r._open()
        try:
            yield r
        finally:
            r._close()

    # -------------------------------------------------------- decorators

    def step(self, name: str | None = None) -> Callable:
        """Record a function call as a signed step in the current run."""

        def deco(fn: Callable) -> Callable:
            label = name or fn.__name__

            @wraps(fn)
            def wrapper(*args, **kwargs):
                run = _CURRENT.get()
                if run is None:
                    return fn(*args, **kwargs)
                started = now_ms()
                try:
                    out = fn(*args, **kwargs)
                except Exception as exc:
                    run.record_step(label, inputs=_safe(kwargs), output=None,
                                    error=repr(exc), started_ms=started)
                    raise
                run.record_step(label, inputs=_safe(kwargs), output=_safe(out),
                                started_ms=started)
                return out

            return wrapper

        return deco

    def guarded_tool(
        self, action: str, *, target: str = "target_instance",
        resource: str | None = None, artifact_type: str | None = None,
    ) -> Callable:
        """Authorize a tool call from its own arguments, then record it.

        The mapping is explicit because inferring it is where this gets
        dangerous: a policy that judges `target_instance` is easy, one that has
        to guess which of six kwargs meant production is not.
        """

        def deco(fn: Callable) -> Callable:
            @wraps(fn)
            def wrapper(*args, **kwargs):
                run = _CURRENT.get()
                proposal = {
                    "action": action,
                    "target_instance": kwargs.get(target),
                    "tool": fn.__name__,
                }
                if resource:
                    proposal["artifact"] = kwargs.get(resource)
                if artifact_type:
                    proposal["artifact_type"] = artifact_type
                if run is None:
                    # no open run: still refuse, still deterministic
                    d = self.decide(proposal)
                else:
                    d = run.authorize(**proposal)
                if not d.allowed:
                    raise Interdicted(d)
                return fn(*args, **kwargs)

            return wrapper

        return deco

    # ------------------------------------------------------------ decide

    def decide(self, proposal: dict[str, Any]) -> Decision:
        """Evaluate without recording. Used where there is no open run."""
        with self._lock:
            bundle = self.bundle
        if bundle is None:
            return _refuse_no_policy(proposal)
        return evaluate(proposal, bundle)

    # ------------------------------------------------------------ shutdown

    def close(self, timeout: float = 10.0) -> None:
        if self._transport:
            self._transport.close(timeout)

    @property
    def stats(self) -> dict:
        return self._transport.stats.as_dict() if self._transport else {}

    def __enter__(self) -> "Mira":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _refuse_no_policy(proposal: dict) -> Decision:
    """The fail-closed answer. Shaped exactly like a real refusal so callers
    have one code path."""
    from .policy import decision_request

    return Decision(
        allowed=False, effect="deny", rule_id="NO_POLICY",
        reason=("No policy bundle is loaded, so nothing can be authorized. "
                "This is the fail-closed default, not a rule."),
        bundle_id="", bundle_version="", bundle_digest="",
        request=decision_request(proposal), decide_us=0.0, evaluated=[],
    )


def _safe(value: Any) -> Any:
    """Best-effort JSON-able view of a value, for the forensic payload."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)[:2000]


# --------------------------------------------------------------------------

_CURRENT: "threading.local" = threading.local()
_CURRENT.value = None


def _get_current():
    return getattr(_CURRENT, "value", None)


def _set_current(run):
    _CURRENT.value = run


_CURRENT.get = _get_current  # type: ignore[attr-defined]


class Run:
    """One governed transaction: a shared lineage for a sequence of steps."""

    def __init__(self, mira: Mira, intent: str, meta: dict | None = None):
        self.mira = mira
        self.intent = intent
        self.meta = meta or {}
        self.txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        self.decisions: list[Decision] = []
        self._seq = 0
        self._prev_hash: str | None = None
        self._lock = threading.Lock()
        self._previous = None

    # ------------------------------------------------------------ context

    def _open(self) -> None:
        self._previous = _get_current()
        _set_current(self)
        self.record(
            RecordType.INTENT,
            node="intent",
            predicate={"intentHash": content_hash(
                {"intent": self.intent, "meta": self.meta}
            )},
            content={"intent": self.intent, "meta": self.meta, "agent": self.mira.agent},
        )

    def _close(self) -> None:
        _set_current(self._previous)

    # ---------------------------------------------------------- authorize

    def authorize(self, **proposal: Any) -> Decision:
        """Ask the gate whether this action may happen. Local, synchronous.

        Always records the decision — a refusal is evidence, not an error, and
        an auditor needs to see what was attempted as much as what ran.
        """
        decision = self.mira.decide(proposal)
        self.decisions.append(decision)
        self.record(
            RecordType.DECISION,
            node="policy_gate",
            predicate={"authorization": {
                "decision": decision.effect,
                "ruleId": decision.rule_id,
                "policyBundleId": decision.bundle_id,
                "policyBundleVersion": decision.bundle_version,
                "policyBundleSha256": decision.bundle_digest,
                "decideUs": round(decision.decide_us, 1),
            }, "proposedAction": _safe(proposal)},
            subject=[{"name": "action",
                      "digest": {"sha256": content_hash(proposal).removeprefix("sha256:")}}],
            content={"proposal": _safe(proposal), "decision": decision.to_predicate()},
        )
        return decision

    def require(self, **proposal: Any) -> Decision:
        """authorize(), but raise Interdicted on refusal."""
        d = self.authorize(**proposal)
        if not d.allowed:
            raise Interdicted(d)
        return d

    # ------------------------------------------------------------- record

    def record_step(
        self, name: str, *, inputs: Any = None, output: Any = None,
        error: str | None = None, started_ms: int | None = None,
    ) -> str:
        pred: dict[str, Any] = {"inputHash": content_hash(inputs)}
        if error:
            pred["error"] = error
        return self.record(
            RecordType.SPAN, node=name, predicate=pred,
            subject=[{"name": "output",
                      "digest": {"sha256": content_hash(output).removeprefix("sha256:")}}],
            content={"input": inputs, "output": output, "error": error},
            ts_ms=started_ms,
        )

    def record(
        self, record_type: RecordType | str, *, node: str,
        predicate: dict | None = None, subject: list[dict] | None = None,
        content: dict | None = None, ts_ms: int | None = None,
    ) -> str:
        """Seal one record: canonicalise, hash, sign, queue. Never blocks."""
        with self._lock:
            seq = self._seq
            prev = self._prev_hash
            self._seq += 1

            statement = build_statement(
                record_type=record_type,
                identity={"miraTxnId": self.txn_id, "threadId": self.txn_id, "legId": 1},
                seq=seq,
                prev_record_hash=prev,
                mmr_size_before=-1,  # the log assigns this; the client cannot know it
                predicate={
                    **(predicate or {}),
                    "agent": self.mira.agent,
                    "sdk": "mira-agent-sdk/0.1.0",
                },
                subject=subject,
                ts_ms=ts_ms,
            )
            payload = canonical(statement)
            record_hash = sha256_hex(payload)
            self._prev_hash = record_hash

        import base64

        signature = self.mira.key.sign(pae(PAYLOAD_TYPE, payload))
        envelope = {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [{
                "keyid": self.mira.key.key_id,
                "sig": base64.b64encode(signature).decode(),
            }],
            "recordHash": record_hash,
        }
        if self.mira._transport:
            self.mira._transport.submit({
                "txn_id": self.txn_id,
                "seq": seq,
                "record_type": str(record_type),
                "node": node,
                "envelope": envelope,
                "agent_public_b64": self.mira.key.public_b64,
                "agent_key_name": self.mira.key.name,
                "content": content,
            })
        return record_hash

    def flush(self, timeout: float = 10.0) -> bool:
        return self.mira._transport.flush(timeout) if self.mira._transport else True
