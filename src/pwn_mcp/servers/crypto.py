"""Encoding, decoding, hashing, and JWT utilities for security testing."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import hmac
import html
import json
import quopri
import re
import time
import urllib.parse
from typing import Literal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

mcp = FastMCP("crypto")

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

Encodings = Literal[
    "base64", "base32", "base58", "hex", "url", "url_full", "html",
    "unicode_escape", "rot13", "quoted_printable", "binary",
]


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + out


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            raise ToolError(f"Invalid base58 character: {ch!r}")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def _encode_bytes(raw: bytes, encoding: Encodings) -> str:
    if encoding == "base64":
        return base64.b64encode(raw).decode()
    if encoding == "base32":
        return base64.b32encode(raw).decode()
    if encoding == "base58":
        return _b58encode(raw)
    if encoding == "hex":
        return raw.hex()
    if encoding == "url":
        return urllib.parse.quote_from_bytes(raw, safe="/")
    if encoding == "url_full":
        return urllib.parse.quote_from_bytes(raw, safe="")
    if encoding == "html":
        return html.escape(raw.decode("utf-8", "replace"), quote=True)
    if encoding == "unicode_escape":
        return raw.decode("utf-8", "replace").encode("unicode_escape").decode()
    if encoding == "rot13":
        return codecs.encode(raw.decode("utf-8", "replace"), "rot13")
    if encoding == "quoted_printable":
        return quopri.encodestring(raw).decode()
    if encoding == "binary":
        return " ".join(f"{b:08b}" for b in raw)
    raise ToolError(f"Unsupported encoding: {encoding}")


def _decode_bytes(data: str, encoding: Encodings) -> bytes:
    if encoding == "base64":
        return base64.b64decode(_pad_b64(data))
    if encoding == "base32":
        pad = "=" * ((8 - len(data) % 8) % 8)
        return base64.b32decode(data + pad)
    if encoding == "base58":
        return _b58decode(data)
    if encoding == "hex":
        return bytes.fromhex(re.sub(r"\s|0x", "", data))
    if encoding in ("url", "url_full"):
        return urllib.parse.unquote_to_bytes(data)
    if encoding == "html":
        return html.unescape(data).encode()
    if encoding == "unicode_escape":
        return codecs.decode(data, "unicode_escape").encode()
    if encoding == "rot13":
        return codecs.decode(data, "rot13").encode()
    if encoding == "quoted_printable":
        return quopri.decodestring(data.encode())
    if encoding == "binary":
        bits = re.sub(r"\s", "", data)
        return int(bits, 2).to_bytes(len(bits) // 8, "big")
    raise ToolError(f"Unsupported encoding: {encoding}")


def _pad_b64(s: str) -> str:
    return s + "=" * ((4 - len(s) % 4) % 4)


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def encode(data: str, encoding: Encodings) -> str:
    """Encode text using a common encoding scheme.

    Args:
        data: The plaintext to encode.
        encoding: One of base64, base32, base58, hex, url, url_full
            (percent-encode everything), html, unicode_escape, rot13,
            quoted_printable, binary.
    """
    return _encode_bytes(data.encode(), encoding)


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def decode(data: str, encoding: Encodings) -> str:
    """Decode text produced by ``encode``.

    Args:
        data: The encoded input.
        encoding: The scheme used to encode it.
    """
    raw = _decode_bytes(data, encoding)
    return raw.decode("utf-8", "replace")


_HASH_PATTERNS: list[tuple[str, str]] = [
    (r"^[a-f0-9]{32}$", "md5 / ntlm (32-hex — ambiguous)"),
    (r"^[a-f0-9]{40}$", "sha1 / ripemd160 (40-hex)"),
    (r"^[a-f0-9]{56}$", "sha224 / sha3-224"),
    (r"^[a-f0-9]{64}$", "sha256 / sha3-256 / blake2s"),
    (r"^[a-f0-9]{96}$", "sha384 / sha3-384"),
    (r"^[a-f0-9]{128}$", "sha512 / sha3-512 / blake2b / whirlpool"),
    (r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
    (r"^\$argon2(id|i|d)\$", "argon2"),
    (r"^\$1\$", "md5-crypt"),
    (r"^\$5\$", "sha256-crypt"),
    (r"^\$6\$", "sha512-crypt"),
    (r"^\$apr1\$", "apache md5"),
    (r"^\{SSHA\}", "salted sha1 (LDAP)"),
    (r"^\{SHA\}", "sha1 (LDAP)"),
    (r"^[a-f0-9]{16}$", "mysql323 / half-md5"),
]


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def hash_text(data: str, algorithm: str = "sha256") -> str:
    """Hash text with a hashlib algorithm.

    Args:
        data: The plaintext to hash.
        algorithm: e.g. md5, sha1, sha256, sha512, sha3_256, blake2b.
    """
    try:
        return hashlib.new(algorithm, data.encode()).hexdigest()
    except ValueError:
        available = ", ".join(sorted(hashlib.algorithms_guaranteed))
        raise ToolError(f"Unknown algorithm '{algorithm}'. Available: {available}")


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def hash_identify(hash_string: str) -> list[str]:
    """Identify the likely hash type(s) of a hash string by format.

    Args:
        hash_string: The hash to classify (e.g. '5f4dcc3b5aa765d61d8327deb882cf99').
    """
    h = hash_string.strip()
    matches = [name for pat, name in _HASH_PATTERNS if re.match(pat, h, re.IGNORECASE)]
    return matches or [f"unrecognized ({len(h)} chars)"]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(_pad_b64(s))


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def jwt_decode(token: str) -> dict:
    """Decode a JWT without verifying the signature, with security analysis.

    Args:
        token: The JWT string (header.payload.signature).
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ToolError(f"Not a JWT: expected 3 dot-separated parts, got {len(parts)}")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error) as e:
        raise ToolError(f"Failed to decode JWT: {e}")

    alg = str(header.get("alg", ""))
    findings: list[str] = []
    if alg.lower() == "none":
        findings.append("alg=none — signature may be stripped entirely")
    elif alg.startswith("HS"):
        findings.append(f"{alg} uses a shared HMAC secret — try weak-secret brute force")
    elif alg.startswith(("RS", "ES")):
        findings.append(
            f"{alg} is asymmetric — try alg-confusion (RS256→HS256 with public key)"
        )
    if "kid" in header:
        findings.append("kid header present — test for path traversal / SQLi / injection in kid")
    if "jku" in header or "x5u" in header:
        findings.append("jku/x5u header present — test for SSRF / key-host substitution")

    now = int(time.time())
    for claim, label in (("exp", "expired"), ("nbf", "not yet valid"), ("iat", "issued in future")):
        val = payload.get(claim)
        if isinstance(val, (int, float)):
            if claim == "exp" and val < now:
                findings.append(f"Token expired at {val} ({now - val}s ago)")
            elif claim == "nbf" and val > now:
                findings.append(f"Token not valid before {val}")
            elif claim == "iat" and val > now:
                findings.append("iat is in the future")

    return {
        "header": header,
        "payload": payload,
        "signature_b64": parts[2],
        "signature_present": bool(parts[2]),
        "findings": findings,
    }


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def jwt_sign(
    payload: dict,
    secret: str = "",
    alg: Literal["HS256", "HS384", "HS512", "none"] = "HS256",
    header_extra: dict | None = None,
) -> str:
    """Forge a JWT with a supplied secret — for weak-secret and alg=none tests.

    Args:
        payload: Claims dict for the token body.
        secret: HMAC secret (ignored for alg=none).
        alg: HS256, HS384, HS512, or none.
        header_extra: Extra header fields to merge (e.g. kid, jku).
    """
    header = {"alg": alg, "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    if alg == "none":
        return signing_input + "."
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    sig = hmac.new(secret.encode(), signing_input.encode(), digest).digest()
    return f"{signing_input}.{_b64url(sig)}"


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def transform(
    data: str,
    operation: Literal[
        "upper", "lower", "swapcase", "reverse", "urlencode", "urlencode_double",
        "html_entities", "sql_comment_space", "null_byte", "unicode_escape",
        "mixed_case", "spaces_to_tabs",
    ],
) -> str:
    """Mutate a payload string — useful for WAF/filter bypass variants.

    Args:
        data: The payload to mutate.
        operation: One of upper, lower, swapcase, reverse, urlencode,
            urlencode_double, html_entities, sql_comment_space (spaces→/**/),
            null_byte (append %00), unicode_escape, mixed_case, spaces_to_tabs.
    """
    if operation == "upper":
        return data.upper()
    if operation == "lower":
        return data.lower()
    if operation == "swapcase":
        return data.swapcase()
    if operation == "reverse":
        return data[::-1]
    if operation == "urlencode":
        return urllib.parse.quote(data, safe="")
    if operation == "urlencode_double":
        return urllib.parse.quote(urllib.parse.quote(data, safe=""), safe="")
    if operation == "html_entities":
        return "".join(f"&#{ord(c)};" for c in data)
    if operation == "sql_comment_space":
        return data.replace(" ", "/**/")
    if operation == "null_byte":
        return data + "%00"
    if operation == "unicode_escape":
        return data.encode("unicode_escape").decode()
    if operation == "mixed_case":
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(data))
    if operation == "spaces_to_tabs":
        return data.replace(" ", "\t")
    raise ToolError(f"Unsupported operation: {operation}")


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def xor(data: str, key: str, input_hex: bool = False, output_hex: bool = True) -> str:
    """XOR data with a repeating key.

    Args:
        data: Input text (or hex string when input_hex=True).
        key: XOR key (repeating); prefix with 'hex:' to supply a hex key.
        input_hex: Interpret data as a hex string.
        output_hex: Return hex instead of utf-8 text.
    """
    raw = bytes.fromhex(data) if input_hex else data.encode()
    k = bytes.fromhex(key[4:]) if key.startswith("hex:") else key.encode()
    if not k:
        raise ToolError("Key must not be empty")
    out = bytes(b ^ k[i % len(k)] for i, b in enumerate(raw))
    return out.hex() if output_hex else out.decode("utf-8", "replace")


@mcp.tool(
    tags={"crypto"},
    annotations={"readOnlyHint": True, "openWorldHint": False},
)
def caesar(data: str, shift: int = 13) -> str:
    """Caesar-shift letters by a fixed amount (shift=13 is rot13).

    Args:
        data: Text to shift.
        shift: Positions to shift (negative to shift backwards).
    """
    out = []
    for c in data:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + shift) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)
