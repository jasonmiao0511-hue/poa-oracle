# SPDX-License-Identifier: MIT
"""Contract tests for the PoA-Attest oracle.

The integrity of this attractor IS the scope contract: a verdict must always
carry the scope disclaimer, must never overclaim via a bare `verified` field,
and its signature must verify. These tests guard exactly that.
"""
import json
import os
import sqlite3
import tempfile

import oracle


def _temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE miner_attest_recent (miner TEXT PRIMARY KEY, ts_ok INTEGER, "
        "device_family TEXT, device_arch TEXT, entropy_score REAL, "
        "fingerprint_passed INTEGER, source_ip TEXT, signing_pubkey TEXT)")
    import time
    conn.execute("INSERT INTO miner_attest_recent VALUES (?,?,?,?,?,?,?,?)",
                 ("g4-powerbook-115", int(time.time()) - 100, "PowerPC", "g4",
                  0.9, 1, None, "abc123pub"))
    conn.execute("INSERT INTO miner_attest_recent VALUES (?,?,?,?,?,?,?,?)",
                 ("vm-faker", int(time.time()) - 50, "x86_64", "modern",
                  0.0, 0, None, "def456pub"))
    conn.commit(); conn.close()
    return path


def _signer():
    fd, kp = tempfile.mkstemp(suffix=".json"); os.close(fd); os.remove(kp)
    return oracle.Signer(kp)


def _verify_sig(env):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    inner = {k: env[k] for k in ("oracle_version", "scope", "attestation", "issued_at")}
    msg = json.dumps(inner, sort_keys=True, separators=(",", ":")).encode()
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(env["oracle_pubkey"]))
    pk.verify(bytes.fromhex(env["oracle_signature"]), msg)  # raises on failure
    return True


fails = 0
def check(cond, label):
    global fails
    if cond: print(f"  PASS: {label}")
    else: fails += 1; print(f"  FAIL: {label}")


def main():
    db = oracle.OracleDB(_temp_db())
    signer = _signer()

    # 1. real vintage hardware -> physical=True, vintage class
    v = oracle.build_verdict("g4-powerbook-115", db.lookup("g4-powerbook-115"), signer)
    check(v["attestation"]["is_physical"] is True, "real G4 -> is_physical True")
    check(v["attestation"]["antiquity_class"] == "vintage-ppc", "g4 -> vintage-ppc class")

    # 2. VM/failed-fingerprint -> physical=False
    v2 = oracle.build_verdict("vm-faker", db.lookup("vm-faker"), signer)
    check(v2["attestation"]["is_physical"] is False, "failed-fp -> is_physical False")
    check(v2["attestation"]["anti_emulation_pass"] is False, "failed-fp -> anti_emu False")

    # 3. unknown id -> found False, still scoped + signed
    v3 = oracle.build_verdict("nobody", db.lookup("nobody"), signer)
    check(v3["attestation"]["found"] is False, "unknown id -> found False")

    # 4. THE SCOPE CONTRACT — every verdict carries it
    for tag, ver in (("real", v), ("vm", v2), ("unknown", v3)):
        check("scope" in ver and "does NOT attest" in ver["scope"], f"{tag}: scope present")
        # never a bare `verified` key anywhere in the envelope
        blob = json.dumps(ver)
        check('"verified"' not in blob, f"{tag}: no bare 'verified' field")
        check(ver["oracle_signature"] and ver["oracle_pubkey"], f"{tag}: signed")
        check(_verify_sig(ver), f"{tag}: signature verifies")

    # 5. lookup by signing_pubkey works too
    vp = oracle.build_verdict("abc123pub", db.lookup("abc123pub"), signer)
    check(vp["attestation"]["found"] is True, "lookup by signing_pubkey works")

    print(f"\n{'ALL PASS' if fails==0 else str(fails)+' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
