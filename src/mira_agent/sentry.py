"""Calling a governed system through the Zero-Bypass gateway.

First, what this module is not. It does not deliver zero-bypass, and it cannot:
an agent that wants to route around the gateway routes around this library
first. Enforcement lives in the network — egress restricted to Sentry, and no
instance credential ever issued to an agent — and nothing importable can
substitute for that.

What it does is cover the other threat model, which is the one that actually
happens. Most governance failures are not a hostile agent defeating a control;
they are an honest agent misconfigured, pointed at the wrong endpoint, or
holding a stale policy and not knowing it. Against that, a client that can only
address the gateway is worth a great deal.

It adds one thing enforcement alone does not give you. Sentry's decision is
sealed by the control plane as the *gateway's* claim. When a call goes through
here, the agent also signs its own claim about the same action, naming the
gateway and the sequence number Sentry returned. Two independent accounts of
one action mean a disagreement between them is detectable; a single account is
just a log.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from mira_agent.client import Interdicted, MiraConfigError
from mira_agent.policy import Decision, evaluate

__all__ = ["SentryClient", "PolicySkew"]


class PolicySkew(RuntimeError):
    """The agent's pinned bundle and the gateway's disagree.

    Not a refusal and not recoverable by retrying: the two sides are enforcing
    different rules, so neither's answer means what it appears to. Raised
    rather than resolved in the agent's favour, because silently preferring
    either one is how a policy update half-lands across an estate.
    """

    def __init__(self, local: Decision, gateway_rule: str, gateway_digest: str):
        self.local, self.gateway_rule = local, gateway_rule
        self.gateway_digest = gateway_digest
        super().__init__(
            f"local policy {local.bundle_digest} decided {local.effect} under "
            f"{local.rule_id}, gateway policy {gateway_digest} decided under "
            f"{gateway_rule}; refresh the pinned bundle before trusting either"
        )


class SentryClient:
    """A client that can only reach registered targets, through the gateway.

    Deliberately takes a *target name* rather than a URL. A client that accepts
    arbitrary URLs is one typo away from talking to the instance directly, and
    that mistake is silent — the call succeeds, and the only trace of the
    ungoverned action is its absence from the ledger. Naming targets means
    reaching the instance directly requires reaching for a different library,
    which is a visible act rather than a slip.
    """

    def __init__(self, gateway_url: str, token: str, *, mira=None,
                 timeout: float = 30.0, preflight: bool = True):
        parts = urllib.parse.urlsplit(gateway_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise MiraConfigError(
                f"gateway_url {gateway_url!r} is not an http(s) URL")
        if parts.scheme == "http" and parts.hostname not in (
                "127.0.0.1", "::1", "localhost"):
            raise MiraConfigError(
                "refusing a plaintext gateway URL off loopback: the agent's "
                "bearer token would cross the network in the clear")
        self.base = gateway_url.rstrip("/")
        self.token = token
        self.mira = mira
        self.timeout = timeout
        self.preflight = preflight
        self._run = None

    def bind(self, run) -> "SentryClient":
        """Attach to a run so calls land in its lineage."""
        self._run = run
        return self

    # ------------------------------------------------------------- verbs
    def get(self, target: str, path: str, **kw):
        return self.call("GET", target, path, **kw)

    def post(self, target: str, path: str, **kw):
        return self.call("POST", target, path, **kw)

    def put(self, target: str, path: str, **kw):
        return self.call("PUT", target, path, **kw)

    def patch(self, target: str, path: str, **kw):
        return self.call("PATCH", target, path, **kw)

    def delete(self, target: str, path: str, **kw):
        return self.call("DELETE", target, path, **kw)

    # ------------------------------------------------------------- the call
    def call(self, method: str, target: str, path: str, *,
             json_body: Any = None, headers: dict | None = None,
             justification: str | None = None,
             proposal: dict[str, Any] | None = None, **kw):
        """Make one governed call. Raises `Interdicted` if policy refuses it.

        A refusal comes back as the same exception a local `require()` raises,
        so an agent that already knows how to re-target after a denial needs no
        new branch for the gateway.
        """
        if "json" in kw and json_body is None:
            json_body = kw.pop("json")
        if not target or "/" in target:
            raise MiraConfigError(
                f"{target!r} is not a target name; SentryClient addresses "
                "registered targets, not URLs")

        # Ask the local pinned bundle first. It costs microseconds and it
        # spares a round trip for an action that was never going to be
        # permitted — but its answer is advisory: the gateway decides.
        local = None
        if self.preflight and proposal and self.mira is not None:
            local = self.mira.decide(proposal)

        url = f"{self.base}/t/{urllib.parse.quote(target)}/{path.lstrip('/')}"
        body = None if json_body is None else json.dumps(json_body).encode()
        req = urllib.request.Request(url, data=body, method=method.upper())
        req.add_header("Authorization", f"Bearer {self.token}")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if justification:
            # Recorded by the gateway as evidence and never evaluated. Write
            # what an incident review will want to read, not an argument.
            req.add_header("X-Mira-Justification", justification[:2000])
        for k, v in (headers or {}).items():
            req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read()
                meta = {
                    "gatewayId": resp.headers.get("X-Mira-Gateway-Id"),
                    "sealedSeq": _int(resp.headers.get("X-Mira-Sealed-Seq")),
                    "ruleId": resp.headers.get("X-Mira-Authorized-By"),
                    "policyBundleSha256": resp.headers.get("X-Mira-Policy-Sha256"),
                }
                self._check_skew(local, meta)
                self._record(method, target, path, meta, "allow", proposal)
                return _Response(resp.status, dict(resp.headers), payload, meta)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            if exc.code == 403:
                detail = _json(payload)
                if detail.get("error") == "refused_by_policy":
                    meta = {"gatewayId": detail.get("gateway_id"),
                            "sealedSeq": detail.get("sealed_seq"),
                            "ruleId": detail.get("rule"),
                            "policyBundleSha256": detail.get("policy_bundle_sha256")}
                    self._check_skew(local, meta)
                    self._record(method, target, path, meta, "deny", proposal)
                    raise Interdicted(_decision_from(detail, proposal)) from None
                if detail.get("error") == "unclassified_request":
                    raise Interdicted(_unclassified(detail, proposal)) from None
            raise

    # ------------------------------------------------------------- helpers
    def _check_skew(self, local: Decision | None, meta: dict) -> None:
        gd = meta.get("policyBundleSha256")
        if local is None or not gd or gd == local.bundle_digest:
            return
        raise PolicySkew(local, meta.get("ruleId") or "?", gd)

    def _record(self, method, target, path, meta, effect, proposal) -> None:
        """Sign the agent's own account of the call, naming the gateway's.

        This is the half the gateway cannot produce: the gateway attests that
        it decided, and the agent attests that it asked. Binding them by
        gateway id and sequence is what makes a disagreement visible.
        """
        run = self._run
        if run is None:
            return
        run.record_step(
            f"sentry:{method.lower()}:{target}",
            content={"request": {"method": method, "target": target, "path": path},
                     "viaGateway": meta, "decision": effect,
                     "proposal": proposal or {}},
        )


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _json(raw: bytes) -> dict:
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _decision_from(detail: dict, proposal) -> Decision:
    return Decision(
        allowed=False, effect="deny",
        rule_id=detail.get("rule", "UNKNOWN"),
        reason=detail.get("reason", "refused by the gateway"),
        bundle_id=detail.get("policy_bundle_id", "gateway"),
        bundle_version=detail.get("policy_bundle_version", "?"),
        bundle_digest=detail.get("policy_bundle_sha256", ""),
        request=proposal or {},
        decide_us=float(detail.get("decided_in_us") or 0.0),
    )


def _unclassified(detail: dict, proposal) -> Decision:
    return Decision(
        allowed=False, effect="deny", rule_id="UNCLASSIFIED",
        reason=detail.get("detail", "the gateway could not classify this request"),
        bundle_id="gateway", bundle_version="?", bundle_digest="",
        request=proposal or {}, decide_us=0.0,
    )


class _Response:
    __slots__ = ("status", "headers", "content", "gateway")

    def __init__(self, status, headers, content, gateway):
        self.status, self.headers = status, headers
        self.content, self.gateway = content, gateway

    def json(self) -> Any:
        return json.loads(self.content)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def __repr__(self) -> str:
        return (f"<sentry {self.status} via {self.gateway.get('gatewayId')} "
                f"seq {self.gateway.get('sealedSeq')} "
                f"rule {self.gateway.get('ruleId')}>")
