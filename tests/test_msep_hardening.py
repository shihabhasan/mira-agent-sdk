"""The nine limitations, each with the test that shows it was addressed.

Numbered to match the review they answer. A limitation that is "addressed"
without a test is addressed in prose, and prose is what the review was
already reading.
"""

import json

import pytest

from _msep_keys import KeyRing, SigningKey
from mira_agent.msep import (BoundaryCertificate, Capability, CertificateStore, Consequence,
                       Custody, Disposition, ExecutionBoundary, ExecutionState,
                       FreshnessPolicy, KeyCache, LocalWrapper, Permissions,
                       PolicyOutcome, RedactionRule, Reject, Residency, Severity,
                       SyncState, Treatment, TrustAnchor, TrustEpoch, apply_redactions,
                       blast_radius, emit_red_card, fast, ingest_signal,
                       issue_certificate, issue_red_card, new_envelope, pseudonymise,
                       reconstruct, reconstruct_lineage, seal, verify_inbound)
from mira_agent.msep.signals import SignalIngestError

POLICY = "sha256:policy-v1"
T0 = 1_700_000_000_000


@pytest.fixture
def ring():
    return KeyRing()


@pytest.fixture
def perms():
    return Permissions((Capability("deploy", "dev"), Capability("deploy", "prod"),
                        Capability("inspect")))


@pytest.fixture
def state(perms):
    return ExecutionState("sha256:pay", "deploy", "dev", "update_set", permissions=perms)


def env(ring, state, perms, key="msep/a", **kw):
    args = dict(identity="spiffe://acme/agent/1", state=state, scope="node-b",
                permissions=perms, epoch=1, policy_digest=POLICY, key=ring.get(key),
                now_ms=T0, ttl_ms=600_000)
    args.update(kw)
    return new_envelope(**args)


# ============================== 1. the boundary is the new attack surface

class TestBoundaryKeys:
    def _store(self, ring, now=T0):
        anchor_key = ring.get("root/control-plane")
        store = CertificateStore([TrustAnchor("acme-root", anchor_key.public_bytes)],
                                 now_ms=lambda: now)
        return anchor_key, store

    def test_a_key_is_trusted_because_a_root_certified_it_not_because_it_is_cached(
            self, ring, state, perms):
        _, store = self._store(ring)
        v = verify_inbound(env(ring, state, perms), keys=store, epoch=TrustEpoch(1),
                           destination="node-b", state=state, policy_digest=POLICY, now_ms=T0)
        assert Reject.UNKNOWN_KEY in v.reasons

    def test_a_certified_key_verifies(self, ring, state, perms):
        anchor_key, store = self._store(ring)
        store.install(issue_certificate(anchor_key=anchor_key, anchor_name="acme-root",
                                        boundary="node-a", key=ring.get("msep/a"),
                                        epoch=1, now_ms=T0))
        v = verify_inbound(env(ring, state, perms), keys=store, epoch=TrustEpoch(1),
                           destination="node-b", state=state, policy_digest=POLICY, now_ms=T0)
        assert v.ok, v.reasons

    def test_certificates_expire_on_their_own(self, ring, state, perms):
        """Rotation is routine. A key that stops mattering by itself needs no
        revocation to reach every boundary."""
        anchor_key, store = self._store(ring, now=T0 + 2 * 3_600_000)
        store.install(issue_certificate(anchor_key=anchor_key, anchor_name="acme-root",
                                        boundary="node-a", key=ring.get("msep/a"),
                                        epoch=1, validity_ms=3_600_000, now_ms=T0))
        v = verify_inbound(env(ring, state, perms), keys=store, epoch=TrustEpoch(1),
                           destination="node-b", state=state, policy_digest=POLICY, now_ms=T0)
        assert Reject.KEY_EXPIRED in v.reasons

    def test_a_key_used_outside_its_certified_context_is_refused(self, ring, state, perms):
        """The first thing a compromise looks like is a real key in the wrong
        place. Prompt injection to code execution gets an attacker the key
        material; it does not get them the attested context."""
        anchor_key, store = self._store(ring)
        store.install(issue_certificate(anchor_key=anchor_key, anchor_name="acme-root",
                                        boundary="node-a", key=ring.get("msep/a"),
                                        epoch=1, attestation="tpm:pcr7=abc", now_ms=T0))
        v = verify_inbound(env(ring, state, perms, attestation="tpm:pcr7=DIFFERENT"),
                           keys=store, epoch=TrustEpoch(1), destination="node-b",
                           state=state, policy_digest=POLICY, now_ms=T0)
        assert Reject.ATTESTATION_MISMATCH in v.reasons
        ok = verify_inbound(env(ring, state, perms, attestation="tpm:pcr7=abc"),
                            keys=store, epoch=TrustEpoch(1), destination="node-b",
                            state=state, policy_digest=POLICY, now_ms=T0)
        assert ok.ok

    def test_a_boundary_s_own_signatures_verify_without_a_context(self, ring):
        """A Red Card or a SET carries no attestation; the key that signed it
        must still resolve, or every attested boundary refuses its own
        cards. This was failing silently before the live binding surfaced it."""
        anchor_key, store = self._store(ring)
        store.install(issue_certificate(anchor_key=anchor_key, anchor_name="acme-root",
                                        boundary="node-a", key=ring.get("msep/a"),
                                        epoch=1, attestation="tpm:pcr7=abc", now_ms=T0))
        assert store.get(ring.get("msep/a").key_id_hex) == ring.get("msep/a").public_bytes
        assert store.resolve(ring.get("msep/a").key_id_hex).public_bytes is None

    def test_rotation_leaves_no_window_with_two_valid_keys(self, ring, state, perms):
        anchor_key, store = self._store(ring)
        old, new = ring.get("msep/a"), ring.get("msep/a2")
        store.install(issue_certificate(anchor_key=anchor_key, anchor_name="acme-root",
                                        boundary="node-a", key=old, epoch=1, now_ms=T0))
        store.rotate(old.key_id_hex, issue_certificate(
            anchor_key=anchor_key, anchor_name="acme-root", boundary="node-a", key=new,
            epoch=2, now_ms=T0))
        assert store.resolve(old.key_id_hex).code == "revoked"
        assert store.resolve(new.key_id_hex)

    def test_a_certificate_from_an_unknown_root_cannot_be_installed(self, ring):
        _, store = self._store(ring)
        rogue = ring.get("root/rogue")
        with pytest.raises(ValueError, match="unknown root"):
            store.install(issue_certificate(anchor_key=rogue, anchor_name="rogue-root",
                                            boundary="node-x", key=ring.get("msep/x"),
                                            epoch=1))

    def test_blast_radius_is_enumerated_from_evidence_not_estimated(self, ring, state, perms):
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "msep/b"])
        b = ExecutionBoundary(name="node-b", key=ring.get("msep/b"), keys=keys,
                              epoch=TrustEpoch(1), policy_digest=POLICY)
        for i in range(4):
            b.handle(inbound=env(ring, state, perms), state=state, next_destination="node-c",
                     now_ms=T0 + i)
        receipts = b.queue.drain()
        r = blast_radius(receipts, ring.get("msep/b").key_id_hex)
        assert r.receipts_signed == 4 and len(r.successors_minted) == 4
        assert r.identities_touched == ["spiffe://acme/agent/1"]
        assert blast_radius(receipts, "deadbeef").receipts_signed == 0


# ================================ 2. central dependency amortised over a TTL

class TestFreshness:
    def _boundary(self, ring, sync):
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "msep/b"])
        return ExecutionBoundary(name="node-b", key=ring.get("msep/b"), keys=keys,
                                 epoch=TrustEpoch(1), policy_digest=POLICY, sync=sync)

    def test_the_numbers_are_stated(self):
        p = FreshnessPolicy()
        assert (p.policy_sync_ms, p.revocation_sync_ms, p.high_consequence_max_age_ms,
                p.hard_limit_ms) == (60_000, 30_000, 5_000, 300_000)

    def test_a_production_change_on_stale_state_is_gated_not_released(self, ring, perms):
        sync = SyncState(); sync.record_all(T0)
        b = self._boundary(ring, sync)
        prod = ExecutionState("sha256:pay", "deploy", "prod", "update_set", permissions=perms)
        r = b.handle(inbound=env(ring, prod, perms), state=prod, now_ms=T0 + 20_000)
        assert r.disposition is Disposition.GATE
        assert Reject.STALE_STATE in r.verdict.reasons
        assert "20.0s-old" in r.verdict.detail

    def test_an_ordinary_action_on_the_same_stale_state_continues(self, ring, state, perms):
        sync = SyncState(); sync.record_all(T0)
        b = self._boundary(ring, sync)
        r = b.handle(inbound=env(ring, state, perms), state=state, now_ms=T0 + 20_000)
        assert r.disposition is Disposition.RELEASE

    def test_past_the_hard_limit_everything_stops(self, ring, state, perms):
        """Five minutes without hearing from the centre is a partition or a
        node being kept in the dark. Neither is a state to mint authority in."""
        sync = SyncState(); sync.record_all(T0)
        b = self._boundary(ring, sync)
        r = b.handle(inbound=env(ring, state, perms), state=state, now_ms=T0 + 400_000)
        assert r.disposition is Disposition.INTERDICT
        assert "hard limit" in r.verdict.detail

    def test_hearing_from_the_control_plane_lifts_the_gate(self, ring, perms):
        sync = SyncState(); sync.record_all(T0)
        b = self._boundary(ring, sync)
        prod = ExecutionState("sha256:pay", "deploy", "prod", "update_set", permissions=perms)
        b.heard_from_control_plane(T0 + 20_000)
        r = b.handle(inbound=env(ring, prod, perms), state=prod, now_ms=T0 + 21_000)
        assert r.disposition is Disposition.RELEASE

    def test_the_oldest_channel_is_what_counts(self):
        sync = SyncState(); sync.record_all(T0)
        sync.record("revocation", T0 - 100_000)
        assert sync.staleness(T0) == 100_000
        assert sync.due(T0) == ["revocation"]

    def test_consequence_defaults_land_on_the_careful_side(self):
        from mira_agent.msep.freshness import consequence_of as f
        assert f("deploy", "prod") is Consequence.HIGH
        assert f("inspect", "dev") is Consequence.LOW
        assert f("whatever", "somewhere") is Consequence.STANDARD


# ============================== 3. red cards across workflows, via SSF/CAEP

class TestSignals:
    def test_a_red_card_travels_as_a_security_event_token(self, ring):
        card = issue_red_card(subject="spiffe://acme/agent/1", reason="honey_tool_trip",
                              trigger_commitment="sha256:evt", issued_by="node-a", epoch=1,
                              key=ring.get("msep/a"), now_ms=T0)
        tok = emit_red_card(card, issuer="acme-control-plane", audience="node-b",
                            key=ring.get("root/control-plane"), now_ms=T0)
        compact = tok.compact()
        header = json.loads(__import__("base64").urlsafe_b64decode(compact.split(".")[0] + "=="))
        assert header == {"alg": "EdDSA", "kid": ring.get("root/control-plane").key_id_hex,
                          "typ": "secevent+jwt"}
        assert "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change" \
            in tok.events

    def test_a_boundary_that_never_saw_the_workflow_still_refuses_the_actor(self, ring, state, perms):
        """The gap the review named. Lineage-bound propagation cannot reach a
        fresh workflow; a pushed signal can."""
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "msep/b", "root/control-plane"])
        node_a = ExecutionBoundary(name="node-a", key=ring.get("msep/a"), keys=keys,
                                   epoch=TrustEpoch(1), policy_digest=POLICY)
        card = issue_red_card(subject="spiffe://acme/agent/1", reason="prohibited_exfiltration",
                              trigger_commitment="sha256:evt", issued_by="node-a", epoch=1,
                              key=ring.get("msep/a"), now_ms=T0)
        node_a.record_adverse(card)
        # A different boundary, a different workflow, nothing carried across.
        node_b = ExecutionBoundary(name="node-b", key=ring.get("msep/b"), keys=keys,
                                   epoch=TrustEpoch(1), policy_digest=POLICY)
        before = node_b.handle(inbound=env(ring, state, perms), state=state, now_ms=T0)
        assert before.disposition is Disposition.RELEASE
        # The control plane pushes the card.
        tok = emit_red_card(card, issuer="acme-control-plane", audience="node-b",
                            key=ring.get("root/control-plane"), now_ms=T0)
        node_b.apply_signal(tok.compact(), now_ms=T0)
        after = node_b.handle(inbound=env(ring, state, perms), state=state, now_ms=T0 + 1)
        assert Reject.ADVERSE_TERMINAL in after.verdict.reasons

    def test_the_control_plane_cannot_mint_a_red_card_on_its_own(self, ring):
        """Two signatures. The token proves the control plane sent it; the
        assertion inside proves a boundary issued it. A control plane that
        could invent one would be asserting trust state it never observed."""
        rogue = SigningKey.generate("rogue-boundary")
        card = issue_red_card(subject="a", reason="honey_tool_trip", trigger_commitment="x",
                              issued_by="nowhere", epoch=1, key=rogue, now_ms=T0)
        tok = emit_red_card(card, issuer="cp", audience="node-b",
                            key=ring.get("root/control-plane"), now_ms=T0)
        keys = KeyCache(); keys.add_keyring(ring, ["root/control-plane"])
        with pytest.raises(SignalIngestError, match="issuer"):
            ingest_signal(tok.compact(), resolve_key=keys.get, now_ms=T0)

    def test_a_token_for_another_boundary_is_refused(self, ring):
        card = issue_red_card(subject="a", reason="honey_tool_trip", trigger_commitment="x",
                              issued_by="node-a", epoch=1, key=ring.get("msep/a"), now_ms=T0)
        tok = emit_red_card(card, issuer="cp", audience="node-z",
                            key=ring.get("root/control-plane"), now_ms=T0)
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "root/control-plane"])
        with pytest.raises(SignalIngestError, match="not addressed"):
            ingest_signal(tok.compact(), resolve_key=keys.get, expected_audience="node-b",
                          now_ms=T0)

    def test_a_tampered_token_is_refused(self, ring):
        card = issue_red_card(subject="a", reason="honey_tool_trip", trigger_commitment="x",
                              issued_by="node-a", epoch=1, key=ring.get("msep/a"), now_ms=T0)
        tok = emit_red_card(card, issuer="cp", audience="node-b",
                            key=ring.get("root/control-plane"), now_ms=T0)
        h, p, sig = tok.compact().split(".")
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "root/control-plane"])
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        with pytest.raises(SignalIngestError, match="signature"):
            ingest_signal(f"{h}.{p}.{flipped}", resolve_key=keys.get, now_ms=T0)
        with pytest.raises(SignalIngestError):
            ingest_signal(f"{h}.{p}x.{sig}", resolve_key=keys.get, now_ms=T0)


# ================================= 4. cross-enterprise needs a federated root

class TestFederation:
    def test_a_foreign_root_is_refused_by_default(self, ring, state, perms):
        ours, theirs = ring.get("root/acme"), ring.get("root/partner")
        store = CertificateStore([TrustAnchor("acme", ours.public_bytes)], now_ms=lambda: T0)
        store.federate(TrustAnchor("partner", theirs.public_bytes))
        store.install(issue_certificate(anchor_key=theirs, anchor_name="partner",
                                        boundary="partner-node", key=ring.get("msep/a"),
                                        epoch=1, now_ms=T0))
        v = verify_inbound(env(ring, state, perms), keys=store, epoch=TrustEpoch(1),
                           destination="node-b", state=state, policy_digest=POLICY, now_ms=T0)
        assert Reject.FOREIGN_ROOT in v.reasons
        store.accept_foreign = True
        assert verify_inbound(env(ring, state, perms), keys=store, epoch=TrustEpoch(1),
                              destination="node-b", state=state, policy_digest=POLICY, now_ms=T0).ok


# ============================================= 5. what is inside the number

class TestHotPath:
    def test_rust_and_python_produce_identical_bytes(self, ring, state, perms):
        if not fast.AVAILABLE:
            pytest.skip("mira_agent_core_rs built without the MSEP hot path")
        import rfc8785
        import mira_agent_core_rs as mira_core
        e = env(ring, state, perms)
        body = json.dumps(e.signing_body())
        assert mira_core.canon(body) == rfc8785.dumps(e.signing_body())
        assert mira_core.envelope_commitment(body) == e.commitment()
        assert mira_core.state_digest(json.dumps(state.to_jcs())) == state.digest()
        assert mira_core.verify_envelope(body, e.signature, ring.get("msep/a").public_bytes)

    def test_the_algorithm_is_named_on_the_wire(self, ring, state, perms):
        e = env(ring, state, perms)
        assert e.to_wire()["alg"] == "Ed25519"
        from mira_agent.msep import Envelope
        with pytest.raises(ValueError, match="unsupported envelope algorithm"):
            Envelope.from_wire({**e.to_wire(), "alg": "HS256"})

    def test_mac_mode_verifies_inside_a_domain(self, ring, state, perms):
        if not fast.AVAILABLE:
            pytest.skip("MAC mode needs the Rust core")
        shared = bytes(range(32))
        keys = KeyCache(); keys.add_mac_key("domain-key-1", shared)
        e = new_envelope(identity="a", state=state, scope="node-b", permissions=perms,
                         epoch=1, policy_digest=POLICY, key=ring.get("msep/a"), now_ms=T0,
                         ttl_ms=600_000).sign_mac(shared, "domain-key-1")
        assert e.alg == "BLAKE3-keyed"
        v = verify_inbound(e, keys=keys, epoch=TrustEpoch(1), destination="node-b",
                           state=state, policy_digest=POLICY, now_ms=T0)
        assert v.ok, v.reasons

    def test_a_mac_key_cannot_verify_a_signature_nor_the_reverse(self, ring, state, perms):
        """The algorithm field is signed, so an attacker cannot relabel an
        Ed25519 envelope as a MAC one to get it checked against a weaker key."""
        if not fast.AVAILABLE:
            pytest.skip("MAC mode needs the Rust core")
        from dataclasses import replace
        shared = bytes(range(32))
        keys = KeyCache(); keys.add_mac_key(ring.get("msep/a").key_id_hex, shared)
        e = env(ring, state, perms)
        assert not e.signature_valid(shared)
        assert not replace(e, alg="BLAKE3-keyed").signature_valid(shared)


# ==================================== 6. policy expressiveness and redaction

class TestRedaction:
    PAYLOAD = {"applicant": {"name": "Priya", "tfn": "123456789", "dob": "1990-01-01"},
               "amount": 480000, "notes": "free text with a TFN 123 456 789 in it"}

    def test_redaction_is_by_path_and_deterministic(self):
        rules = [RedactionRule("/applicant/tfn", Treatment.MASK),
                 RedactionRule("/applicant/dob", Treatment.HASH),
                 RedactionRule("/applicant/name", Treatment.REMOVE)]
        a = apply_redactions(self.PAYLOAD, rules)
        b = apply_redactions(self.PAYLOAD, rules)
        assert a.payload == b.payload
        assert a.payload["applicant"]["tfn"] == "[REDACTED]"
        assert a.payload["applicant"]["dob"].startswith("sha256:")
        assert "name" not in a.payload["applicant"]
        assert a.applied == ("/applicant/tfn", "/applicant/dob", "/applicant/name")

    def test_redaction_does_not_pretend_to_read_free_text(self):
        """The limit, stated as a test: a TFN in a field nobody declared is
        still there afterwards. Finding it is a classifier's job."""
        r = apply_redactions(self.PAYLOAD, [RedactionRule("/applicant/tfn")])
        assert "123 456 789" in r.payload["notes"]

    def test_an_absent_path_is_recorded_not_raised(self):
        r = apply_redactions(self.PAYLOAD, [RedactionRule("/applicant/passport")])
        assert r.absent == ("/applicant/passport",) and not r.changed

    def test_the_original_is_not_mutated(self):
        apply_redactions(self.PAYLOAD, [RedactionRule("/amount", Treatment.REMOVE)])
        assert self.PAYLOAD["amount"] == 480000

    def test_paths_must_be_json_pointers(self):
        with pytest.raises(ValueError, match="JSON pointer"):
            RedactionRule("applicant.tfn")


# ======================================================== 7. key custody

class TestCustody:
    def test_customer_only_is_the_default_and_refuses_a_liora_wrap(self):
        with pytest.raises(ValueError, match="decryption oracle"):
            seal(b"x", storage_ref="s3://c/1",
                 wrappers=[LocalWrapper("customer-kms"), LocalWrapper("liora", holder="liora")])

    def test_customer_only_lodgement_says_liora_cannot_decrypt(self):
        _, l = seal(b"x", storage_ref="s3://c/1", wrappers=[LocalWrapper("customer-kms")])
        assert l.custody == Custody.CUSTOMER_ONLY and l.liora_can_decrypt is False
        assert l.to_jcs()["lioraCanDecrypt"] is False

    def test_dual_custody_is_explicit_and_flagged(self):
        _, l = seal(b"x", storage_ref="s3://c/1", custody=Custody.DUAL,
                    wrappers=[LocalWrapper("customer-kms"), LocalWrapper("liora", holder="liora")])
        assert l.liora_can_decrypt is True and l.dual_wrapped

    def test_no_custody_model_may_drop_the_customer_wrap(self):
        with pytest.raises(ValueError, match="customer-held wrap"):
            seal(b"x", storage_ref="s3://c/1", custody=Custody.DUAL,
                 wrappers=[LocalWrapper("liora", holder="liora")])


# ====================================================== 8. ledger residency

class TestResidency:
    def test_residency_is_declared_in_writing(self, monkeypatch):
        monkeypatch.setenv("MIRA_REGION", "au-southeast-2")
        d = Residency.from_env().describe()
        assert d["ledger"]["selfHosted"] is True
        assert d["ledger"]["region"] == "au-southeast-2"
        assert d["liora"]["callsRequiredToSeal"] == 0
        assert d["liora"]["holdsDecryptionKeysByDefault"] is False

    def test_pseudonymised_receipts_keep_lineage_and_lose_names(self, ring, state, perms):
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "msep/b"])
        b = ExecutionBoundary(name="node-b", key=ring.get("msep/b"), keys=keys,
                              epoch=TrustEpoch(1), policy_digest=POLICY)
        r1 = b.handle(inbound=env(ring, state, perms), state=state, now_ms=T0).receipt
        r2 = b.handle(inbound=env(ring, state, perms), state=state, now_ms=T0).receipt
        key = bytes(32)
        p1, p2 = pseudonymise(r1, key), pseudonymise(r2, key)
        assert p1.inbound_commitment == r1.inbound_commitment      # lineage intact
        assert "acme" not in p1.identity and "node-b" not in p1.boundary
        assert p1.identity == p2.identity                          # same actor still links
        assert pseudonymise(r1, bytes([1]) * 32).identity != p1.identity



# ==================================================== 9. the smaller gaps

class TestSmallerGaps:
    def test_a_terminal_hop_that_drops_its_receipt_is_detectable(self, ring, state, perms):
        """The hop before it already committed to having handed authority on."""
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "msep/b"])
        b = ExecutionBoundary(name="node-b", key=ring.get("msep/b"), keys=keys,
                              epoch=TrustEpoch(1), policy_digest=POLICY)
        r = b.handle(inbound=env(ring, state, perms), state=state,
                     next_destination="node-c", now_ms=T0)
        lineage = reconstruct_lineage([r.receipt])
        assert lineage.missing_successors == [r.successor.commitment()]
        assert not lineage.complete

    def test_a_missing_parent_is_a_gap_not_a_repair(self, ring, state, perms):
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "msep/b"])
        b = ExecutionBoundary(name="node-b", key=ring.get("msep/b"), keys=keys,
                              epoch=TrustEpoch(1), policy_digest=POLICY)
        parent = env(ring, state, perms)
        child = new_envelope(identity="a", state=state, scope="node-b", permissions=perms,
                             epoch=1, policy_digest=POLICY, key=ring.get("msep/a"),
                             predecessor=parent.commitment(), depth=1, now_ms=T0, ttl_ms=600_000)
        r = b.handle(inbound=child, state=state, now_ms=T0)
        assert reconstruct_lineage([r.receipt]).missing_parents == [parent.commitment()]

    def test_the_receipt_records_what_was_released_and_what_came_back(self, ring, state, perms):
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "msep/b"])
        b = ExecutionBoundary(name="node-b", key=ring.get("msep/b"), keys=keys,
                              epoch=TrustEpoch(1), policy_digest=POLICY)
        r = b.handle(inbound=env(ring, state, perms), state=state, now_ms=T0,
                     execute=lambda: ("deploy", b'{"status":"ok"}'))
        assert r.receipt.action_released == "deploy"
        assert r.receipt.response_digest.startswith("sha256:")
        assert r.receipt.signer_key_id == ring.get("msep/b").key_id_hex

    def test_recover_on_an_external_side_effect_becomes_elevate(self, ring, perms):
        """A replay of a step whose effect already left the boundary is a
        second copy of the effect, not an undo."""
        keys = KeyCache(); keys.add_keyring(ring, ["msep/a", "msep/b"])
        ext = ExecutionState("sha256:pay", "deploy", "dev", "update_set",
                             permissions=perms, side_effects="external")
        b = ExecutionBoundary(name="node-b", key=ring.get("msep/b"), keys=keys,
                              epoch=TrustEpoch(1), policy_digest=POLICY,
                              decide=lambda e, s: PolicyOutcome(Disposition.RECOVER))
        r = b.handle(inbound=env(ring, ext, perms), state=ext, now_ms=T0)
        assert r.disposition is Disposition.ELEVATE
        assert "second copy" not in r.verdict.detail and "repeat the effect" in r.verdict.detail
        idem = ExecutionState("sha256:pay", "deploy", "dev", "update_set", permissions=perms)
        assert b.handle(inbound=env(ring, idem, perms), state=idem,
                        now_ms=T0).disposition is Disposition.RECOVER

    def test_side_effects_are_part_of_the_sealed_state(self, perms):
        a = ExecutionState("sha256:p", "deploy", "dev", "x", permissions=perms)
        b = ExecutionState("sha256:p", "deploy", "dev", "x", permissions=perms,
                           side_effects="external")
        assert a.digest() != b.digest()
