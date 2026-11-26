import base64
import hashlib

import pytest

from passkeyreg.register import (
    check_challenge,
    check_origin,
    issue_challenge,
    parse_public_key,
    register,
    register_batch,
)

NOW = 1_800_000_000
ORIGIN = "https://login.example.test"
RP_ID = "example.test"
POLICY = {"challenge_ttl": 120, "origin": ORIGIN, "rp_id": RP_ID}


def new_store():
    return {"challenges": {}, "credentials": {}}


def sample_key():
    return base64.b64encode(b"\x04" + b"\x5c" * 64).decode("ascii")


def proof_for(challenge, credential_id):
    return hashlib.sha256(f"{challenge}:{credential_id}".encode("utf-8")).hexdigest()


def attestation(challenge, credential_id):
    return {
        "client_data": {"origin": ORIGIN, "rp_id": RP_ID, "challenge": challenge},
        "credential_id": credential_id,
        "alg": -7,
        "public_key": sample_key(),
        "proof": proof_for(challenge, credential_id),
    }


def test_issue_challenge_sets_expiry():
    store = new_store()
    issued = issue_challenge(store, "alice", NOW, POLICY)
    assert issued["user"] == "alice"
    assert issued["expires_at"] == NOW + POLICY["challenge_ttl"]
    assert issued["challenge"] in store["challenges"]

    stale = issue_challenge(store, "alice", NOW, POLICY)["challenge"]
    assert check_challenge(store, stale, "alice", NOW + POLICY["challenge_ttl"] + 1) is False


def test_origin_match_is_exact():
    assert check_origin({"origin": ORIGIN}, ORIGIN) is True
    assert check_origin({"origin": ORIGIN + ".attacker.test"}, ORIGIN) is False
    assert check_origin({"origin": ORIGIN + ":8443"}, ORIGIN) is False


def test_parse_public_key_rejects_garbage():
    with pytest.raises(ValueError):
        parse_public_key({"alg": -7, "public_key": "not base64 at all"})

    parsed = parse_public_key({"alg": -7, "public_key": sample_key()})
    assert parsed["alg"] == -7
    assert len(parsed["public_key"]) == 65


def test_register_succeeds_and_consumes_challenge():
    store = new_store()
    challenge = issue_challenge(store, "alice", NOW, POLICY)["challenge"]
    att = attestation(challenge, "cred-alice")

    first = register(store, "alice", challenge, att, NOW)
    assert first["ok"] is True
    assert first["credential"]["user"] == "alice"
    assert store["credentials"]["cred-alice"]["alg"] == -7

    second = register(store, "alice", challenge, att, NOW)
    assert second["ok"] is False


def test_register_batch_handles_requests_independently():
    store = new_store()
    alice_challenge = issue_challenge(store, "alice", NOW, POLICY)["challenge"]
    bob_challenge = issue_challenge(store, "bob", NOW, POLICY)["challenge"]

    outcome = register_batch(
        [
            {
                "user": "alice",
                "challenge": alice_challenge,
                "attestation": attestation(alice_challenge, "cred-a"),
            },
            {
                "user": "bob",
                "challenge": bob_challenge,
                "attestation": attestation(bob_challenge, "cred-b"),
            },
        ],
        store,
        NOW,
    )

    assert [item["ok"] for item in outcome["results"]] == [True, True]
    assert outcome["results"][1]["challenge"] == bob_challenge
    assert set(store["credentials"]) == {"cred-a", "cred-b"}