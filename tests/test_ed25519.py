"""Tests for the pure Ed25519 implementation and the hashing helpers."""

from __future__ import annotations

import hashlib
import unittest

from _support import ROOT  # noqa: F401  (puts the project root on sys.path)

from solution.crypto.ed25519 import (
    Ed25519Error,
    private_key_from_seed,
    public_key_from_private,
    sign,
    verify,
)
from solution.integrity import (
    canonical_json_bytes,
    compute_seal,
    sha256_bytes,
    verify_seal,
)

# RFC 8032 section 7.1 test vectors.
RFC8032_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for sk_hex, pk_hex, msg_hex, sig_hex in RFC8032_VECTORS:
            with self.subTest(sk=sk_hex[:8]):
                sk = bytes.fromhex(sk_hex)
                pk = bytes.fromhex(pk_hex)
                msg = bytes.fromhex(msg_hex)
                sig = bytes.fromhex(sig_hex)

                self.assertEqual(public_key_from_private(sk).hex(), pk_hex)
                self.assertEqual(sign(sk, msg).hex(), sig_hex)
                self.assertTrue(verify(pk, msg, sig))

    def test_signature_rejects_tampered_message(self):
        sk = bytes.fromhex(RFC8032_VECTORS[0][0])
        pk = public_key_from_private(sk)
        sig = sign(sk, b"payload")
        self.assertTrue(verify(pk, b"payload", sig))
        self.assertFalse(verify(pk, b"payloae", sig))

    def test_signature_rejects_wrong_key(self):
        sk1 = bytes.fromhex(RFC8032_VECTORS[0][0])
        sk2 = bytes.fromhex(RFC8032_VECTORS[1][0])
        sig = sign(sk1, b"payload")
        self.assertFalse(verify(public_key_from_private(sk2), b"payload", sig))

    def test_signature_rejects_malformed_input(self):
        pk = public_key_from_private(bytes.fromhex(RFC8032_VECTORS[0][0]))
        self.assertFalse(verify(b"", b"x", b"y"))
        self.assertFalse(verify(pk, b"x", b"\x00" * 64))
        # s >= L must be rejected outright.
        bad = bytearray(sign(bytes.fromhex(RFC8032_VECTORS[0][0]), b""))
        bad[63] = 0xFF
        self.assertFalse(verify(pk, b"", bytes(bad)))

    def test_seed_length_is_validated(self):
        with self.assertRaises(Ed25519Error):
            public_key_from_private(b"too short")
        with self.assertRaises(Ed25519Error):
            private_key_from_seed(b"also too short")


class IntegrityTests(unittest.TestCase):
    def test_sha256_matches_hashlib(self):
        self.assertEqual(sha256_bytes(b"abc"), hashlib.sha256(b"abc").hexdigest())

    def test_canonical_json_ignores_key_order_and_whitespace(self):
        a = canonical_json_bytes({"b": 2, "a": [1, {"d": 4, "c": 3}]})
        b = canonical_json_bytes({"a": [1, {"c": 3, "d": 4}], "b": 2})
        self.assertEqual(a, b)
        self.assertEqual(a, b'{"a":[1,{"c":3,"d":4}],"b":2}')

    def test_seal_round_trip_and_tamper(self):
        body = {"schema": "x", "sources": [{"id": "a", "sha256": "00" * 32}]}
        key = b"unit-test-key"
        seal = compute_seal(body, key)
        self.assertTrue(seal.startswith("hmac-sha256:"))
        self.assertTrue(verify_seal(body, seal, key))
        self.assertFalse(verify_seal(body, seal, b"other-key"))
        body["sources"][0]["sha256"] = "11" * 32
        self.assertFalse(verify_seal(body, seal, key))

    def test_seal_rejects_wrong_algorithm(self):
        self.assertFalse(verify_seal({"a": 1}, "sha256:abcd", b"k"))


if __name__ == "__main__":
    unittest.main()
