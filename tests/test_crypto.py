"""Tests for the crypto_* tools — all deterministic, no network."""

import pytest
from fastmcp import Client


@pytest.mark.parametrize("encoding", [
    "base64", "base32", "base58", "hex", "url", "url_full", "html",
    "unicode_escape", "rot13", "quoted_printable", "binary",
])
async def test_encode_decode_roundtrip(mcp_client: Client, encoding: str):
    original = "Hello, <World>! & goodbye"
    enc = await mcp_client.call_tool(
        "crypto_encode", {"data": original, "encoding": encoding})
    dec = await mcp_client.call_tool(
        "crypto_decode", {"data": enc.data, "encoding": encoding})
    assert dec.data == original


async def test_base58_known_vector(mcp_client: Client):
    # "Hello World!" in base58 is a fixed known value
    r = await mcp_client.call_tool(
        "crypto_encode", {"data": "Hello World!", "encoding": "base58"})
    assert r.data == "2NEpo7TZRRrLZSi2U"
    dec = await mcp_client.call_tool(
        "crypto_decode", {"data": "2NEpo7TZRRrLZSi2U", "encoding": "base58"})
    assert dec.data == "Hello World!"


async def test_hash_text(mcp_client: Client):
    r = await mcp_client.call_tool(
        "crypto_hash_text", {"data": "password", "algorithm": "md5"})
    assert r.data == "5f4dcc3b5aa765d61d8327deb882cf99"


async def test_hash_identify(mcp_client: Client):
    r = await mcp_client.call_tool(
        "crypto_hash_identify",
        {"hash_string": "5f4dcc3b5aa765d61d8327deb882cf99"})
    assert any("md5" in m for m in r.data)
    r = await mcp_client.call_tool(
        "crypto_hash_identify",
        {"hash_string": "$2b$12$" + "a" * 53})
    assert r.data == ["bcrypt"]


async def test_jwt_decode_alg_none(mcp_client: Client):
    token = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
             ".eyJzdWIiOiJhZG1pbiJ9.")
    r = await mcp_client.call_tool("crypto_jwt_decode", {"token": token})
    assert r.data["header"]["alg"] == "none"
    assert r.data["payload"]["sub"] == "admin"
    assert any("alg=none" in f for f in r.data["findings"])


async def test_jwt_sign_and_decode(mcp_client: Client):
    r = await mcp_client.call_tool("crypto_jwt_sign", {
        "payload": {"sub": "attacker", "admin": True},
        "secret": "s3cret", "alg": "HS256"})
    token = r.data
    assert token.count(".") == 2
    d = await mcp_client.call_tool("crypto_jwt_decode", {"token": token})
    assert d.data["payload"]["admin"] is True
    assert d.data["header"]["alg"] == "HS256"


async def test_jwt_sign_none_alg(mcp_client: Client):
    r = await mcp_client.call_tool("crypto_jwt_sign", {
        "payload": {"sub": "x"}, "alg": "none"})
    assert r.data.endswith(".")


async def test_transform(mcp_client: Client):
    r = await mcp_client.call_tool("crypto_transform", {
        "data": "SELECT * FROM t", "operation": "sql_comment_space"})
    assert r.data == "SELECT/**/*/**/FROM/**/t"
    r = await mcp_client.call_tool("crypto_transform", {
        "data": "<script>", "operation": "urlencode"})
    assert r.data == "%3Cscript%3E"


async def test_xor_and_caesar(mcp_client: Client):
    r = await mcp_client.call_tool("crypto_xor", {
        "data": "hello", "key": "K", "output_hex": True})
    assert r.data == "232e272724"  # 'hello' ^ 'K'
    r2 = await mcp_client.call_tool("crypto_xor", {
        "data": r.data, "key": "K", "input_hex": True, "output_hex": False})
    assert r2.data == "hello"

    r = await mcp_client.call_tool(
        "crypto_caesar", {"data": "attack at dawn", "shift": 13})
    assert r.data == "nggnpx ng qnja"
