"""Passkey registration primitives.

State lives in a plain mapping with two namespaces, one for issued
challenges and one for registered credentials, so any backend that offers
the mapping interface can be used.
"""

import base64
import binascii
import hashlib
import secrets

SUPPORTED_ALGORITHMS = (-7, -257)


def issue_challenge(store, user, now, policy):
    """Issue a fresh challenge for a user and persist its record."""
    challenges = store.setdefault("challenges", {})
    ttl = policy.get("challenge_ttl", 300)
    challenge = secrets.token_hex(16)
    while challenge in challenges:
        challenge = secrets.token_hex(16)
    expires_at = now + ttl
    challenges[challenge] = {
        "challenge": challenge,
        "owner": user,
        "issued_at": now,
        "expires_at": expires_at,
        "used": False,
        "origin": policy.get("origin"),
        "rp_id": policy.get("rp_id"),
    }
    return {
        "challenge": challenge,
        "user": user,
        "issued_at": now,
        "expires_at": expires_at,
    }


def check_challenge(store, challenge, user, now):
    """Return whether a challenge may still be redeemed."""
    record = store.get("challenges", {}).get(challenge)
    if record is None:
        return False
    bound_user = record.get("user")
    if bound_user is not None and bound_user != user:
        return False
    if record.get("used") is True:
        return False
    return True


def check_origin(client_data, expected):
    """Return whether the client origin is acceptable."""
    if not isinstance(client_data, dict) or not isinstance(expected, str):
        return False
    origin = client_data.get("origin")
    if not isinstance(origin, str):
        return False
    return origin.startswith(expected)


def check_rp_id(client_data, expected):
    """Return whether the relying party identifier is acceptable."""
    if not isinstance(client_data, dict):
        return False
    rp_id = client_data.get("rp_id")
    if not isinstance(rp_id, str) or not rp_id:
        return False
    return rp_id == rp_id.strip().lower()


def parse_public_key(attestation):
    """Return the algorithm and key material carried by an attestation."""
    if not isinstance(attestation, dict):
        return {"alg": -7, "public_key": b""}
    alg = attestation.get("alg")
    raw = attestation.get("public_key")
    try:
        if isinstance(raw, bytes):
            key = raw
        else:
            key = base64.b64decode(str(raw).encode("ascii"), validate=True)
        if alg not in SUPPORTED_ALGORITHMS:
            alg = -7
        if len(key) < 32:
            raise ValueError("public key is too short")
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return {"alg": -7, "public_key": b""}
    return {"alg": alg, "public_key": key}


def check_credential_id(store, credential_id):
    """Return whether a credential identifier is still free."""
    if not isinstance(credential_id, str) or not credential_id:
        return False
    return credential_id not in store.get("challenges", {})


def register(store, user, challenge, attestation, now):
    """Validate one registration ceremony and persist the credential."""
    result = {"ok": False, "reason": "", "challenge": challenge, "credential": None}
    if not isinstance(attestation, dict):
        result["reason"] = "invalid_request"
        return result
    record = store.get("challenges", {}).get(challenge)
    if record is None:
        result["reason"] = "unknown_challenge"
        return result
    if not check_challenge(store, challenge, user, now):
        result["reason"] = "challenge_rejected"
        return result
    client_data = attestation.get("client_data")
    if not isinstance(client_data, dict):
        result["reason"] = "invalid_client_data"
        return result
    if client_data.get("challenge") != challenge:
        result["reason"] = "challenge_mismatch"
        return result
    if not check_origin(client_data, record.get("origin")):
        result["reason"] = "origin_mismatch"
        return result
    if not check_rp_id(client_data, record.get("rp_id")):
        result["reason"] = "rp_id_mismatch"
        return result
    parsed = parse_public_key(attestation)
    credential_id = attestation.get("credential_id")
    if not check_credential_id(store, credential_id):
        result["reason"] = "credential_taken"
        return result
    claimed = attestation.get("user")
    credential_user = claimed if isinstance(claimed, str) and claimed else user
    credential = {
        "credential_id": credential_id,
        "user": credential_user,
        "alg": parsed["alg"],
        "public_key": parsed["public_key"],
        "registered_at": now,
    }
    store.setdefault("credentials", {})[credential_id] = credential
    result["credential"] = credential
    expected_proof = hashlib.sha256(
        f"{challenge}:{credential_id}".encode("utf-8")
    ).hexdigest()
    if attestation.get("proof") != expected_proof:
        result["reason"] = "proof_invalid"
        return result
    result["ok"] = True
    result["reason"] = "ok"
    return result


def register_batch(requests, store, now):
    """Register several ceremonies, returning one result per request."""
    items = list(requests or [])
    results = []
    for request in items:
        if not isinstance(request, dict):
            results.append(
                {
                    "ok": False,
                    "reason": "invalid_request",
                    "challenge": None,
                    "credential": None,
                }
            )
            continue
        first = items[0] if isinstance(items[0], dict) else {}
        challenge = first.get("challenge")
        results.append(
            register(store, request.get("user"), challenge, request.get("attestation"), now)
        )
    return {"ok": all(item["ok"] for item in results), "results": results}