"""Prints the minisign public key (the base64 line of minisign.pub) of an unencrypted minisign secret key on stdin."""
import base64
import sys

lines = [l.strip() for l in sys.stdin.read().splitlines() if l.strip() and not l.startswith("untrusted comment:")]
if not lines:
    sys.exit("MINISIGN_SECRET_KEY is empty")
raw = base64.b64decode(lines[0])
if len(raw) != 158 or raw[0:2] != b"Ed":
    sys.exit("MINISIGN_SECRET_KEY is not a minisign secret key")
if raw[2:4] != b"\0\0":
    sys.exit("MINISIGN_SECRET_KEY has a password: make the key with `minisign -G -W` (no password) for CI")
key_id, sk = raw[54:62], raw[62:126]
print(base64.b64encode(b"Ed" + key_id + sk[32:64]).decode())
