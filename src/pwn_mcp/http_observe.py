"""Label an HTTP response so a caller can tell documents apart.

These labels are observations about the bytes that came back. They are not
findings, and they do not say whether a target is vulnerable.
"""

from __future__ import annotations

import hashlib
import re

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WS = re.compile(r"\s+")


def body_fingerprint(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()


def html_title(body: str) -> str:
    match = _TITLE.search(body)
    if not match:
        return ""
    return _WS.sub(" ", match.group(1)).strip()[:200]


def baseline_from(body: str) -> dict:
    return {
        "fingerprint": body_fingerprint(body),
        "title": html_title(body),
        "size": len(body),
    }


def matches_baseline(body: str, baseline: dict | None) -> bool:
    """True when *body* is the same document as *baseline* (SPA catch-all)."""
    if not baseline:
        return False
    if body_fingerprint(body) == baseline.get("fingerprint"):
        return True
    title = html_title(body)
    base_title = baseline.get("title") or ""
    if base_title and title and title == base_title:
        return abs(len(body) - int(baseline.get("size") or 0)) <= 64
    return False


_ENCODED_MARKERS = (
    "&quot;",
    "&apos;",
    "&lt;",
    "&gt;",
    "&#34;",
    "&#39;",
    "&#60;",
    "&#62;",
    "&#x22;",
    "&#x27;",
    "&#x3c;",
    "&#x3e;",
)


def classify_reflection(body: str, canary: str, status: int) -> dict:
    """Judge how a canary payload came back.

    Flags look only at the bytes between the two canary copies (the payload's
    own `'"><` tail). Tags in the surrounding page do not count as unescaped
    input. ``appears_encoded`` means those characters came back as entities.
    ``reflection_in_error`` means the response status is 500 or higher.
    """
    idx = body.find(canary)
    if idx < 0:
        return {"reflected": False, "status": status}

    after = idx + len(canary)
    second = body.find(canary, after)
    if second != -1:
        window = body[after:second]
    else:
        # One copy left. The other canary may have been stripped, leaving the
        # payload punctuation immediately before this copy. Keep that run and
        # the suffix up to the next tag. Do not keep the surrounding page.
        tail = body[after:after + 32]
        tag = re.search(r"</?[A-Za-z!]", tail)
        suffix = tail[:tag.start()] if tag else tail
        prefix = body[max(0, idx - 48):idx]
        run = re.search(
            r"(?:&(?:quot|apos|lt|gt|#\d+|#x[0-9a-fA-F]+);|['\"<>])+$",
            prefix,
        )
        window = (run.group(0) if run else "") + suffix
    quote_raw = "'" in window or '"' in window
    angle_raw = "<" in window or ">" in window
    encoded = any(marker in window.lower() for marker in _ENCODED_MARKERS)
    lookbehind = body[max(0, idx - 80):idx]
    context = "html_text"
    if "<script" in (lookbehind + window).lower():
        context = "inside_script"
    elif lookbehind.rfind("<") > lookbehind.rfind(">"):
        context = "inside_tag_or_attr"
    return {
        "reflected": True,
        "status": status,
        "context": context,
        "special_chars_unescaped": {"quote": quote_raw, "angle": angle_raw},
        "appears_encoded": encoded and not (quote_raw or angle_raw),
        "reflection_in_error": status >= 500,
        "reflection_excerpt": window[:300],
    }


def project_json(document: object, fields: list[str]) -> dict:
    """Keep only the requested paths from a JSON document.

    A path is dotted. ``[]`` walks every object in a list:
    ``data[].name`` keeps ``name`` on each element of ``data``. Missing paths
    are omitted. The result is a dict even when every path misses.
    """
    dest: dict = {}
    for field in fields:
        parts = _path_parts(field)
        if parts:
            _write_path(dest, document, parts)
    return dest


def _path_parts(field: str) -> list[tuple[str, bool]]:
    parts: list[tuple[str, bool]] = []
    for piece in field.strip().lstrip(".").split("."):
        if not piece:
            continue
        array = piece.endswith("[]")
        key = piece[:-2] if array else piece
        if not key:
            continue
        parts.append((key, array))
    return parts


def _write_path(dest: dict, src: object, parts: list[tuple[str, bool]]) -> None:
    key, array = parts[0]
    rest = parts[1:]
    if not isinstance(src, dict) or key not in src:
        return
    value = src[key]
    if not rest:
        dest[key] = value
        return
    if array:
        if not isinstance(value, list):
            return
        bucket = dest.setdefault(key, [])
        if not isinstance(bucket, list):
            return
        for index, item in enumerate(value):
            while len(bucket) <= index:
                bucket.append({})
            if not isinstance(bucket[index], dict):
                bucket[index] = {}
            if isinstance(item, dict):
                _write_path(bucket[index], item, rest)
        return
    if not isinstance(value, dict):
        return
    child = dest.setdefault(key, {})
    if isinstance(child, dict):
        _write_path(child, value, rest)


def preview(body: str, limit: int = 240) -> str:
    text = _WS.sub(" ", body.replace("\r", " ").replace("\n", " ")).strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _directory_listing(body: str, title: str) -> bool:
    lowered = title.lower()
    if "listing directory" in lowered or lowered.startswith("index of"):
        return True
    head = body[:800].lower()
    return "index of /" in head or "<title>index of" in head


_LISTING_LINK = re.compile(
    r"""<a\s[^>]*href=["']([^"'#]+)["'][^>]*>(?:\s*<span[^>]*class=["'][^"']*\bname\b[^"']*["'][^>]*>)?\s*([^<]*)""",
    re.IGNORECASE,
)
_LISTING_SKIP = frozenset({".", "..", "/", "./", "../"})


def directory_entries(body: str, limit: int = 200) -> list[dict]:
    """Names and hrefs from an Apache or serve-index directory page.

    The HTML around those links is mostly CSS. Callers should return this
    list and drop the page body.
    """
    entries: list[dict] = []
    seen: set[str] = set()
    for href, label in _LISTING_LINK.findall(body):
        href = href.strip()
        if href in _LISTING_SKIP or href.startswith("?"):
            continue
        name = _WS.sub(" ", label).strip() or href.rstrip("/").rsplit("/", 1)[-1]
        if name in ("", ".", ".."):
            continue
        if href in seen:
            continue
        seen.add(href)
        entries.append({"name": name, "href": href})
        if len(entries) >= limit:
            break
    return entries


def classify(
    *,
    status: int,
    content_type: str,
    body: str,
    baseline: dict | None = None,
) -> str:
    """Return a short label for one response.

    Labels: ``spa_shell``, ``json``, ``directory_listing``, ``html``,
    ``text``, ``error``, ``other``.
    """
    if status and matches_baseline(body, baseline):
        return "spa_shell"
    ctype = (content_type or "").lower()
    stripped = body.lstrip()
    if "json" in ctype or (
        stripped[:1] in "{[" and "html" not in ctype and "xml" not in ctype
    ):
        return "json"
    title = html_title(body)
    if _directory_listing(body, title):
        return "directory_listing"
    if (
        "html" in ctype
        or stripped[:9].lower().startswith("<!doctype")
        or stripped[:5].lower().startswith("<html")
    ):
        return "html"
    if status >= 400:
        return "error"
    if ctype.startswith("text/") or "xml" in ctype:
        return "text"
    return "other"
