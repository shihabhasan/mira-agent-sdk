"""The SDK's side of Zero-Bypass.

The client cannot enforce anything — an agent that wants to skip the gateway
skips this library first. What it can do is make the honest mistakes hard, turn
a gateway refusal into the same exception a local refusal raises, and bind the
agent's signed claim to the gateway's sealed one. That is what is tested here.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mira_agent.client import Interdicted, MiraConfigError
from mira_agent.policy import PolicyBundle
from mira_agent.sentry import PolicySkew, SentryClient

GATEWAY_DIGEST = "sha256:" + "ab" * 32


class FakeSentry(BaseHTTPRequestHandler):
    """Stands in for the gateway, answering the way mira.sentry.proxy does."""

    seen = []

    def _reply(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n) if n else b""
        FakeSentry.seen.append({
            "path": self.path, "method": self.command,
            "auth": self.headers.get("Authorization"),
            "justification": self.headers.get("X-Mira-Justification"),
            "body": body.decode() or None,
        })
        if "/t/acme-prod/" in self.path:
            payload = json.dumps({
                "error": "refused_by_policy", "gateway_id": "gw_fake",
                "rule": "BOD-1.1", "reason": "no autonomous deploy to Production",
                "policy_bundle_sha256": GATEWAY_DIGEST,
                "decided_in_us": 8.2, "sealed_seq": 7,
            }).encode()
            self.send_response(403)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if "/t/acme-weird/" in self.path:
            payload = json.dumps({"error": "unclassified_request",
                                  "detail": "no rule maps POST /api/x"}).encode()
            self.send_response(403)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        payload = b'{"result":{"sys_id":"abc123"}}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.send_header("X-Mira-Gateway-Id", "gw_fake")
        self.send_header("X-Mira-Sealed-Seq", "42")
        self.send_header("X-Mira-Authorized-By", "BOD-2.1")
        self.send_header("X-Mira-Policy-Sha256", GATEWAY_DIGEST)
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PATCH = do_DELETE = _reply

    def log_message(self, *a):
        pass


@pytest.fixture
def gateway():
    FakeSentry.seen = []
    srv = HTTPServer(("127.0.0.1", 0), FakeSentry)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def client(gateway):
    return SentryClient(gateway, token="tok123")


# ------------------------------------------------------------ what it refuses

def test_it_addresses_target_names_not_urls(client):
    """A client that accepts URLs is one typo from talking to the instance
    directly, and that mistake is silent."""
    with pytest.raises(MiraConfigError, match="not a target name"):
        client.post("https://acme.service-now.com", "/api/now/table/incident")


def test_a_plaintext_gateway_off_loopback_is_refused():
    with pytest.raises(MiraConfigError, match="plaintext"):
        SentryClient("http://sentry.internal:8790", token="t")


def test_a_nonsense_gateway_url_is_refused():
    with pytest.raises(MiraConfigError):
        SentryClient("sentry.internal:8790", token="t")


def test_https_off_loopback_is_fine():
    assert SentryClient("https://sentry.internal:8790", token="t").base


# --------------------------------------------------------- refusal ergonomics

def test_a_gateway_refusal_raises_the_same_exception_a_local_one_does(client):
    """So an agent that already re-targets after a denial needs no new branch."""
    with pytest.raises(Interdicted) as e:
        client.post("acme-prod", "/api/sn_cicd/app/batch/install", json={})
    assert e.value.decision.rule_id == "BOD-1.1"
    assert e.value.decision.allowed is False
    assert "Production" in e.value.decision.reason


def test_an_unclassified_request_also_raises_interdicted(client):
    with pytest.raises(Interdicted) as e:
        client.post("acme-weird", "/api/x", json={})
    assert e.value.decision.rule_id == "UNCLASSIFIED"


def test_an_allowed_call_returns_the_body_and_the_gateway_binding(client):
    r = client.post("acme-dev", "/api/sn_cicd/app/batch/install", json={"a": 1})
    assert r.status == 200
    assert r.json()["result"]["sys_id"] == "abc123"
    assert r.gateway == {"gatewayId": "gw_fake", "sealedSeq": 42,
                         "ruleId": "BOD-2.1",
                         "policyBundleSha256": GATEWAY_DIGEST}


def test_the_agent_token_goes_to_the_gateway_and_the_body_is_forwarded(client):
    client.post("acme-dev", "/api/now/table/x", json={"short_description": "hi"})
    call = FakeSentry.seen[-1]
    assert call["auth"] == "Bearer tok123"
    assert json.loads(call["body"]) == {"short_description": "hi"}


def test_a_justification_is_sent_for_the_record(client):
    client.post("acme-dev", "/api/now/table/x", json={},
                justification="rolling back INC0012345")
    assert FakeSentry.seen[-1]["justification"] == "rolling back INC0012345"


# ------------------------------------------------------------- policy skew

def _bundle(digest_seed: str) -> PolicyBundle:
    # snake_case is the wire shape: it is what /api/v1/policy/bundle serves
    # and what from_dict reads. to_jcs()'s camelCase exists for the digest.
    return PolicyBundle.from_dict({
        "bundle_id": "test", "version": digest_seed, "default_effect": "deny",
        "rules": [{"id": "R-1", "effect": "allow", "description": "d",
                   "match": {"action": "deploy"}}],
    })


class _FakeMira:
    def __init__(self, bundle):
        self._b = bundle

    def decide(self, proposal):
        from mira_agent.policy import evaluate
        return evaluate(proposal, self._b)


def test_a_disagreement_between_the_pinned_and_gateway_policy_is_raised(client):
    """Both sides enforcing different rules means neither answer means what it
    looks like. Preferring either silently is how an update half-lands."""
    client.mira = _FakeMira(_bundle("1.0.0"))
    with pytest.raises(PolicySkew) as e:
        client.post("acme-dev", "/api/sn_cicd/app/batch/install", json={},
                    proposal={"action": "deploy", "target_instance": "dev"})
    assert GATEWAY_DIGEST in str(e.value)


def test_matching_digests_do_not_raise(client, monkeypatch):
    mira = _FakeMira(_bundle("1.0.0"))
    monkeypatch.setattr(type(mira._b), "digest",
                        property(lambda self: GATEWAY_DIGEST))
    client.mira = mira
    r = client.post("acme-dev", "/api/sn_cicd/app/batch/install", json={},
                    proposal={"action": "deploy", "target_instance": "dev"})
    assert r.status == 200


# ------------------------------------------------------------ dual attestation

class _FakeRun:
    def __init__(self):
        self.steps = []

    def record_step(self, name, content=None, **kw):
        self.steps.append((name, content))


def test_the_agent_signs_its_own_claim_naming_the_gateways(client):
    """One account of an action is a log. Two independent ones make a
    disagreement between them detectable."""
    run = _FakeRun()
    client.bind(run)
    client.post("acme-dev", "/api/sn_cicd/app/batch/install", json={})
    name, content = run.steps[-1]
    assert name == "sentry:post:acme-dev"
    assert content["viaGateway"]["gatewayId"] == "gw_fake"
    assert content["viaGateway"]["sealedSeq"] == 42
    assert content["decision"] == "allow"


def test_a_refusal_is_recorded_by_the_agent_too(client):
    run = _FakeRun()
    client.bind(run)
    with pytest.raises(Interdicted):
        client.post("acme-prod", "/api/sn_cicd/app/batch/install", json={})
    name, content = run.steps[-1]
    assert content["decision"] == "deny"
    assert content["viaGateway"]["sealedSeq"] == 7
