"""The client's boundary calls, against a stand-in server."""
import io, json, urllib.request

import pytest

from mira_agent import Mira, MiraConfigError


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


@pytest.fixture
def served(monkeypatch):
    calls = []
    def fake_urlopen(req, timeout=10):
        calls.append((req.get_method(), req.full_url, req.get_header("Authorization"),
                      req.data and json.loads(req.data)))
        path = req.full_url.split("/api", 1)[1]
        body = {"/v1/residency": {"ledger": {"selfHosted": True}, "liora": {"callsRequiredToSeal": 0}},
                "/msep/boundary": {"custody": "customer-only", "hot_path": {"implementation": "rust"}},
                "/runs/txn-1/msep": {"txn_id": "txn-1", "hops": []},
                "/msep/reinstate": {"subject": "spiffe://x", "severity": "noted"}}[path]
        return _Resp(json.dumps(body).encode())
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return calls


def test_boundary_calls_carry_the_bearer_key(served):
    m = Mira(api_key="k-1", base_url="https://mira.example", offline=True)
    assert m.residency()["liora"]["callsRequiredToSeal"] == 0
    assert m.boundary_status()["custody"] == "customer-only"
    assert m.run_chain("txn-1")["txn_id"] == "txn-1"
    assert m.reinstate("spiffe://x")["severity"] == "noted"
    assert all(auth == "Bearer k-1" for _, _, auth, _ in served)
    assert served[-1][0] == "POST" and served[-1][3] == {"subject": "spiffe://x"}


def test_boundary_calls_need_a_configured_control_plane():
    m = Mira(offline=True, api_key="", base_url="")
    with pytest.raises(MiraConfigError):
        m.residency()
