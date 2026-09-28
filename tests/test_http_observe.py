"""Response labels are observations, not findings."""

from pwn_mcp.http_observe import (
    baseline_from,
    classify,
    classify_reflection,
    directory_entries,
    matches_baseline,
    project_json,
)


INDEX = "<!doctype html><html><head><title>App</title></head><body><app-root></app-root></body></html>"


def test_same_body_is_spa_shell():
    baseline = baseline_from(INDEX)
    assert matches_baseline(INDEX, baseline)
    assert classify(status=200, content_type="text/html", body=INDEX, baseline=baseline) == "spa_shell"


def test_json_and_listing_are_not_the_shell():
    baseline = baseline_from(INDEX)
    body = '{"status":"success","data":[{"name":"Apple"}]}'
    assert classify(
        status=200, content_type="application/json", body=body, baseline=baseline,
    ) == "json"
    listing = "<html><title>listing directory /ftp</title><a href='notes.md'>notes</a></html>"
    assert classify(
        status=200, content_type="text/html", body=listing, baseline=baseline,
    ) == "directory_listing"


def test_directory_entries_keep_names_and_drop_parents():
    page = (
        "<html><title>listing directory /ftp</title>"
        "<a href='ftp/notes.md'><span class='name'>notes.md</span></a>"
        "<a href='..'><span class='name'>..</span></a>"
        "</html>"
    )
    assert directory_entries(page) == [{"name": "notes.md", "href": "ftp/notes.md"}]


def test_reflection_flags_use_the_payload_window_only():
    canary = "pwnabcdefgh"
    payload = f"{canary}'\"><{canary}/"
    raw = f"<html><body><h1>Title</h1>You said: {payload}</body></html>"
    judged = classify_reflection(raw, canary, 200)
    assert judged["reflected"] is True
    assert judged["context"] == "html_text"
    assert judged["special_chars_unescaped"]["quote"] is True
    assert judged["special_chars_unescaped"]["angle"] is True
    assert judged["appears_encoded"] is False
    assert judged["reflection_in_error"] is False
    assert "<h1>" not in judged["reflection_excerpt"]


def test_encoded_error_page_is_not_unescaped():
    canary = "pwnabcdefgh"
    # SQL-style error page: specials are entities, and the page is full of tags.
    body = (
        "<html><head><title>Error: SQLITE_ERROR: near "
        f"&quot;&quot;&gt;&lt;{canary}/</title></head>"
        "<body><h1>OWASP</h1><ul><li>at handler</li></ul></body></html>"
    )
    judged = classify_reflection(body, canary, 500)
    assert judged["reflected"] is True
    assert judged["special_chars_unescaped"] == {"quote": False, "angle": False}
    assert judged["appears_encoded"] is True
    assert judged["reflection_in_error"] is True
    assert "<html>" not in judged["reflection_excerpt"]


def test_project_json_keeps_list_fields():
    document = {
        "status": "success",
        "data": [
            {"name": "Apple", "solved": False, "noise": "x" * 50},
            {"name": "Orange", "solved": True, "noise": "y"},
        ],
    }
    assert project_json(document, ["status", "data[].name", "data[].solved"]) == {
        "status": "success",
        "data": [
            {"name": "Apple", "solved": False},
            {"name": "Orange", "solved": True},
        ],
    }


def test_project_json_omits_missing_paths():
    assert project_json({"ok": True}, ["missing", "ok"]) == {"ok": True}


def test_distinct_html_is_not_a_shell():
    baseline = baseline_from(INDEX)
    body = "<html><title>UnauthorizedError: No Authorization header was found</title></html>"
    assert classify(
        status=401, content_type="text/html", body=body, baseline=baseline,
    ) == "html"
