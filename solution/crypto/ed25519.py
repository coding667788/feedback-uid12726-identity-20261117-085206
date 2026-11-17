"""Pure Python Ed25519 (RFC 8032) signing and verification.

The task allows the ``cryptography`` package, but it is not guaranteed to be
installed; this module keeps the tool runnable on a bare CPython 3.12 with
only the standard library.  It implements the maths from RFC 8032 directly,
is constant-time nowhere (it is offline forensic tooling, not a side-channel
hardened library), and is covered by the RFC 8032 test vectors in
``tests/test_ed25519.py``.

The simulator prefers the system ``cryptography`` package when present and
falls back to this module otherwise; both produce byte-identical keys,
signatures and verification outcomes.
"""

from __future__ import annotations

import hashlib

# Curve constants, RFC 8032 section 5.1.
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
BASE_Y = (4 * pow(5, P - 2, P)) % P

PUBLIC_KEY_LEN = 32
SIGNATURE_LEN = 64


class Ed25519Error(ValueError):
    """Raised for malformed keys, signatures or seeds."""


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * t1 * t2 * D) % P
    d = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    if (x1 * z2 - x2 * z1) % P != 0:
        return False
    return (y1 * z2 - y2 * z1) % P == 0


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


_BASE = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202
    % P,
    BASE_Y,
    1,
    (
        15112221349535400772501151409588531511454012693041857206046113283949847762202
        * BASE_Y
    )
    % P,
)


def _compress(p) -> bytes:
    x, y, z, _ = p
    zinv = _inv(z)
    x = x * zinv % P
    y = y * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _expand_seed(seed: bytes):
    if len(seed) != 32:
        raise Ed25519Error(f"seed must be 32 bytes, got {len(seed)}")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    return a, prefix


def _clamp_scalar(scalar: int) -> bytes:
    return (scalar % L).to_bytes(32, "little")


def public_key_from_private(private_key: bytes) -> bytes:
    """Derive the 32 byte public key for a 32 byte private seed."""
    a, _ = _expand_seed(private_key)
    return _compress(_mul(a, _BASE))


def private_key_from_seed(seed: bytes) -> bytes:
    """Return the 32 byte seed as the private key (RFC 8032 style)."""
    if len(seed) != 32:
        raise Ed25519Error(f"seed must be 32 bytes, got {len(seed)}")
    return bytes(seed)


def _hash_to_scalar(*parts: bytes) -> int:
    h = hashlib.sha512()
    for part in parts:
        h.update(part)
    return int.from_bytes(h.digest(), "little") % L


def sign(private_key: bytes, message: bytes) -> bytes:
    """Sign ``message`` with the 32 byte private seed, returning 64 bytes."""
    a, prefix = _expand_seed(private_key)
    public = _compress(_mul(a, _BASE))
    r = _hash_to_scalar(prefix, message)
    big_r = _compress(_mul(r, _BASE))
    k = _hash_to_scalar(big_r, public, message)
    s = (r + k * a) % L
    return big_r + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature; returns False for any malformed input."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        a_point = _decompress(public_key)
        if a_point is None:
            return False
        r_bytes = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        r_point = _decompress(r_bytes)
        if r_point is None:
            return False
        k = _hash_to_scalar(r_bytes, public_key, message)
        left = _mul(s, _BASE)
        right = _add(r_point, _mul(k, a_point))
        return _equal(left, right)
    except Ed25519Error:
        return False
    except Exception:  # pragma: no cover - defensive: never crash verification
        return False
