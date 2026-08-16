"""SPIFFE identity binding.

The property that matters: a record must never imply an attribution it cannot
support. An anonymous agent says so; an SVID-backed one carries the SPIFFE ID
that infrastructure already believes.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mira_agent import Mira, PolicyBundle
from mira_agent_core.identity import (
    SpiffeError,
    SpiffeId,
    load_identity,
    spiffe_id_from_certificate,
)

BUNDLE = {
    "bundle_id": "t", "version": "1", "default_effect": "deny",
    "rules": [{"id": "A1", "effect": "allow", "description": "reads",
               "match": {"action": "inspect"}}],
}


def make_svid(tmp_path, uris, name="svid"):
    """A real X.509 certificate with URI SANs, as SPIRE would issue."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "workload")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in uris]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cp = tmp_path / f"{name}.pem"
    kp = tmp_path / f"{name}.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return cp, kp


# ------------------------------------------------------------- parsing

def test_spiffe_id_parses():
    sid = SpiffeId.parse("spiffe://example.org/ns/prod/sa/release-agent")
    assert sid.trust_domain == "example.org"
    assert sid.path == "/ns/prod/sa/release-agent"
    assert sid.workload == "release-agent"


@pytest.mark.parametrize("bad", [
    "https://example.org/x", "spiffe:/example.org", "not a uri", "spiffe://",
])
def test_malformed_ids_are_rejected(bad):
    with pytest.raises(SpiffeError):
        SpiffeId.parse(bad)


def test_id_is_read_from_a_real_svid(tmp_path):
    cert, _ = make_svid(tmp_path, ["spiffe://example.org/ns/prod/sa/deployer"])
    sid = spiffe_id_from_certificate(cert.read_bytes())
    assert sid.uri == "spiffe://example.org/ns/prod/sa/deployer"


def test_a_certificate_with_no_spiffe_san_is_rejected(tmp_path):
    cert, _ = make_svid(tmp_path, ["https://example.org/not-spiffe"])
    with pytest.raises(SpiffeError, match="no spiffe"):
        spiffe_id_from_certificate(cert.read_bytes())


def test_two_spiffe_ids_are_rejected_as_ambiguous(tmp_path):
    """The X509-SVID spec requires exactly one. Picking one would be inventing
    an attribution."""
    cert, _ = make_svid(tmp_path, [
        "spiffe://example.org/a", "spiffe://example.org/b",
    ])
    with pytest.raises(SpiffeError, match="ambiguous"):
        spiffe_id_from_certificate(cert.read_bytes())


# ------------------------------------------------------------ identity

def test_identity_from_an_svid_is_attributable(tmp_path):
    cert, key = make_svid(tmp_path, ["spiffe://example.org/ns/prod/sa/deployer"])
    ident = load_identity(svid_cert=cert, svid_key=key)
    assert ident.attributable
    assert ident.name == "deployer"
    assert ident.spiffe.trust_domain == "example.org"
    pred = ident.to_predicate()
    assert pred["identity"]["spiffeId"].endswith("/deployer")
    assert pred["identity"]["svidSerial"]


def test_the_record_key_is_stable_for_the_life_of_an_svid(tmp_path):
    """Derived, not random: restarting the agent must not change who signed."""
    cert, key = make_svid(tmp_path, ["spiffe://example.org/w"])
    a = load_identity(svid_cert=cert, svid_key=key)
    b = load_identity(svid_cert=cert, svid_key=key)
    assert a.key.key_id == b.key.key_id
    assert a.key.public_b64 == b.key.public_b64


def test_a_different_svid_gives_a_different_key(tmp_path):
    c1, k1 = make_svid(tmp_path, ["spiffe://example.org/one"], name="a")
    c2, k2 = make_svid(tmp_path, ["spiffe://example.org/two"], name="b")
    assert load_identity(svid_cert=c1, svid_key=k1).key.key_id != \
           load_identity(svid_cert=c2, svid_key=k2).key.key_id


def test_anonymous_identity_says_so():
    ident = load_identity(name="anon")
    assert ident.attributable is False
    assert ident.to_predicate()["attributable"] is False
    assert "identity" not in ident.to_predicate()


def test_a_spiffe_id_without_a_key_is_refused():
    """An identity claim signed by an unrelated ephemeral key is not
    attribution — it is a claim anyone could make."""
    with pytest.raises(SpiffeError, match="not attribution"):
        load_identity(spiffe_id="spiffe://example.org/w")


# ------------------------------------------------------- through the client

def test_client_binds_the_identity_into_records(tmp_path):
    cert, key = make_svid(tmp_path, ["spiffe://example.org/ns/prod/sa/releaser"])
    m = Mira(offline=True, policy=PolicyBundle.from_dict(BUNDLE),
             svid_cert=cert, svid_key=key)
    assert m.identity.attributable
    assert m.agent == "releaser"
    assert m.key.name == "mira/agent/releaser"


def test_client_without_an_svid_is_anonymous_but_functional():
    m = Mira(offline=True, policy=PolicyBundle.from_dict(BUNDLE), agent="plain")
    assert m.identity.attributable is False
    assert m.decide({"action": "inspect"}).allowed is True
