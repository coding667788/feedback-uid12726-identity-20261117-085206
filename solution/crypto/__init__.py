"""Ed25519 primitives for attesting host records.

The task allows the optional ``cryptography`` package, but the tool must run on
a bare CPython 3.12, so the signature maths lives here as a dependency free
implementation of RFC 8032.  SHA-256 content digests are in
:mod:`solution.integrity` and come from the standard library.

To switch to ``cryptography``, replace ``sign`` and ``verify`` here with
``Ed25519PrivateKey.sign`` / ``Ed25519PublicKey.verify``; nothing else in the
tool calls into the maths.
"""

from .ed25519 import (  # noqa: F401
    PUBLIC_KEY_LEN,
    SIGNATURE_LEN,
    Ed25519Error,
    private_key_from_seed,
    public_key_from_private,
    sign,
    verify,
)
