"""Passkey registration primitives.

State lives in a plain mapping with two namespaces, one for issued
challenges and one for registered credentials, so any backend that offers
the mapping interface can be used.
"""

import base64
import binascii
import hashlib
import hmac
import secrets

SUPPORTED_ALGORITHMS = (-7, -257)
MIN_PUBLIC_KEY_LENGTH = 32


def issue_challenge(store, user, now, policy):
    """Issue a fresh, user-bound challenge and persist its record."""
    challenges = store.setdefault("challenges", {})
    if not isinstance(policy, dict):
        policy = {}

    ttl = policy.get("challenge_ttl")
    if ttl is None:
        ttl = policy.get("ttl", 300)

    challenge = secrets.token_hex(16)
    while challenge in challenges:
        challenge = secrets.token_hex(16)

    expires_at = now + ttl
    challenges[challenge] = {
        "challenge": challenge,
        "user": user,
        # Keep "owner" as an alias for older record layouts/readers.
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


def _redeemable_challenge(store, challenge, user, now):
    """Return the challenge record if it can still be redeemed.

    This helper is deliberately non-mutating.  :func:`check_challenge` is the
    redeeming operation and marks a valid challenge as used.
    """
    if not isinstance(challenge, str) or not challenge:
        return None

    try:
        challenges = store.get("challenges", {})
        record = challenges.get(challenge)
    except (AttributeError, TypeError):
        return None

    if not isinstance(record, dict):
        return None
    if record.get("used"):
        return None

    if "user" in record:
        bound_user = record.get("user")
    else:
        bound_user = record.get("owner")
    if bound_user != user:
        return None

    if record.get("challenge", challenge) != challenge:
        return None

    expires_at = record.get("expires_at")
    if expires_at is None:
        return None
    try:
        if now >= expires_at:
            return None
    except TypeError:
        return None

    return record


def check_challenge(store, challenge, user, now):
    """Redeem a challenge and return whether that was permitted.

    A valid call is single-use: the first valid call marks the record used,
    and every later call for the same challenge fails closed.
    """
    record = _redeemable_challenge(store, challenge, user, now)
    if record is None:
        return False

    record["used"] = True
    return True


def check_origin(client_data, expected):
    """Return whether the client origin is exactly the expected origin."""
    if not isinstance(client_data, dict):
        return False
    if not isinstance(expected, str) or not expected:
        return False

    origin = client_data.get("origin")
    return isinstance(origin, str) and origin == expected


def check_rp_id(client_data, expected):
    """Return whether the relying party identifier exactly matches."""
    if not isinstance(client_data, dict):
        return False
    if not isinstance(expected, str) or not expected:
        return False

    rp_id = client_data.get("rp_id")
    return isinstance(rp_id, str) and rp_id == expected


def parse_public_key(attestation):
    """Parse and validate the algorithm and public-key material.

    Invalid input raises :class:`ValueError`; it is never silently replaced
    by a default key or algorithm.
    """
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be an object")

    alg = attestation.get("alg")
    if (
        not isinstance(alg, int)
        or isinstance(alg, bool)
        or alg not in SUPPORTED_ALGORITHMS
    ):
        raise ValueError("unsupported or missing public-key algorithm")

    raw = attestation.get("public_key")
    if isinstance(raw, (bytes, bytearray, memoryview)):
        key = bytes(raw)
    elif isinstance(raw, str) and raw:
        try:
            key = base64.b64decode(raw.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
            raise ValueError("public key is not valid base64") from exc
    else:
        raise ValueError("public key is missing or invalid")

    if len(key) < MIN_PUBLIC_KEY_LENGTH:
        raise ValueError("public key is too short")

    return {"alg": alg, "public_key": key}


def check_credential_id(store, credential_id):
    """Return whether a credential identifier is valid and globally free."""
    if not isinstance(credential_id, str) or not credential_id:
        return False

    try:
        credentials = store.get("credentials", {})
        return credential_id not in credentials
    except (AttributeError, TypeError):
        return False


def _invalid_registration(challenge, reason):
    return {
        "ok": False,
        "reason": reason,
        "challenge": challenge,
        "credential": None,
    }


def register(store, user, challenge, attestation, now):
    """Validate one registration ceremony and persist its credential."""
    if not isinstance(attestation, dict):
        return _invalid_registration(challenge, "invalid_request")

    if not isinstance(challenge, str) or not challenge:
        return _invalid_registration(challenge, "unknown_challenge")

    record = store.get("challenges", {}).get(challenge)
    if record is None:
        return _invalid_registration(challenge, "unknown_challenge")

    # Non-mutating validity pre-check. The single-use redemption happens
    # after the attestation fields and proof have also been validated.
    if _redeemable_challenge(store, challenge, user, now) is None:
        return _invalid_registration(challenge, "challenge_rejected")

    client_data = attestation.get("client_data")
    if not isinstance(client_data, dict):
        return _invalid_registration(challenge, "invalid_client_data")

    if client_data.get("challenge") != challenge:
        return _invalid_registration(challenge, "challenge_mismatch")

    if not check_origin(client_data, record.get("origin")):
        return _invalid_registration(challenge, "origin_mismatch")

    if not check_rp_id(client_data, record.get("rp_id")):
        return _invalid_registration(challenge, "rp_id_mismatch")

    try:
        parsed_key = parse_public_key(attestation)
    except ValueError:
        return _invalid_registration(challenge, "invalid_public_key")

    credential_id = attestation.get("credential_id")
    if not check_credential_id(store, credential_id):
        return _invalid_registration(challenge, "credential_taken")

    expected_proof = hashlib.sha256(
        f"{challenge}:{credential_id}".encode("utf-8")
    ).hexdigest()
    proof = attestation.get("proof")
    proof_valid = False
    if isinstance(proof, str):
        try:
            proof_valid = hmac.compare_digest(
                proof.encode("utf-8"),
                expected_proof.encode("ascii"),
            )
        except (UnicodeError, TypeError):
            proof_valid = False

    if not proof_valid:
        # No credential has been written, and no existing credential replaced.
        return _invalid_registration(challenge, "proof_invalid")

    # Redeem the challenge only after every request check has succeeded.
    # check_challenge() revalidates and performs the single-use transition.
    if not check_challenge(store, challenge, user, now):
        return _invalid_registration(challenge, "challenge_rejected")

    credentials = store.setdefault("credentials", {})
    if credential_id in credentials:
        # Defensive re-check if the backend changed during redemption.
        return _invalid_registration(challenge, "credential_taken")

    credential = {
        "credential_id": credential_id,
        # Bind to the authenticated caller, never to an attestation claim.
        "user": user,
        "alg": parsed_key["alg"],
        "public_key": parsed_key["public_key"],
        "registered_at": now,
    }
    credentials[credential_id] = credential

    return {
        "ok": True,
        "reason": "ok",
        "challenge": challenge,
        "credential": credential,
    }


def register_batch(requests, store, now):
    """Register several independent ceremonies, one result per request."""
    if requests is None:
        items = []
    elif isinstance(requests, (list, tuple)):
        items = list(requests)
    else:
        try:
            items = list(requests)
        except TypeError:
            return {
                "ok": False,
                "results": [_invalid_registration(None, "invalid_request")],
            }

    results = []
    for request in items:
        if not isinstance(request, dict):
            results.append(_invalid_registration(None, "invalid_request"))
            continue

        challenge = None
        try:
            challenge = request.get("challenge")
            result = register(
                store,
                request.get("user"),
                challenge,
                request.get("attestation"),
                now,
            )
        except Exception:
            # One malformed request must not prevent later batch items from
            # being processed independently.
            result = _invalid_registration(challenge, "invalid_request")
        results.append(result)

    return {"ok": all(item["ok"] for item in results), "results": results}
