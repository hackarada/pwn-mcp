"""Read-only map of how to use pwn-mcp.

This is not a tool catalog. ``tools/list`` is the catalog. The guide is the
contract an agent cannot get from a schema: how to reach a target, and how
to read a result.
"""

from __future__ import annotations

from fastmcp import FastMCP

GUIDE_URI = "pwn://guide"

GUIDE = """\
# pwn-mcp

Tools return evidence. You decide what to follow. This server does not store tokens, cookies, or recon notes, and it does not tell you to stop.

`tools/list` is the catalog. Read a tool schema before calling it. `list_resources` lists these pages. `read_resource` takes a `uri`.

Only use this against a target you are authorized to test.

## Reach a target

From `recon_*` and `scan_*`, a host-published app is `http://host.docker.internal:<port>/`. `127.0.0.1` inside this server is the server itself.

From a host shell, that same app is `http://127.0.0.1:<port>/`.

In `browser_*`, `127.0.0.1` and `localhost` are the Playwright sidecar. Open `http://host.docker.internal:<port>/`. Do not pass `filename` to `browser_snapshot`; the snapshot in the tool result is the one to read.

If a scope file is configured, active tools only run in scope. Call `recon_scope_check` on the URL first.

## Read a response

`recon_probe_paths` labels each path with `kind`:

- `spa_shell`: the same document as the site index. Not an API, and not GraphQL.
- `json`: a JSON document. The preview is the evidence.
- `directory_listing`: filenames are in `entries` or `listing`. Do not re-read the HTML.
- `html`, `text`, `error`: a distinct document. "Unexpected path" or 401 on a login path means GET is the wrong method.

`body_encoding` `base64` means the bytes are not UTF-8. Decode them before saving. `body_length` is the real size.

`scan_sqli_probe` with `content_type=json` POSTs one JSON field. `form` is the default. `auth_differential` means an auth field appeared that the baseline did not have. `error_based` is a database error string. `status_differential` is only a status change.

`scan_reflected_xss_probe` only sees a value come back in an HTTP body. `appears_encoded` or `reflection_in_error` means the payload was escaped or the hit was an error page.

`playbook_run` batches calls and returns step data plus job ids. `kill_signals` are notes about that batch.

## Session

Send a token on the next request as `Authorization: Bearer <token>` and, when the API also reads the cookie, `Cookie: token=<token>`. Replay values from `set_cookies`. They are not stored here.

A TOTP code dies in its time step. Put `{{totp}}` in the body or a header and pass `totp_secret` on that same `recon_http_request`.

A scan that would exceed the tool timeout goes to `jobs_start`, then `jobs_status` and `jobs_result`.
"""


def register(mcp: FastMCP) -> None:
    @mcp.resource(
        GUIDE_URI,
        name="guide",
        description=(
            "How to reach a target and read pwn-mcp results. "
            "Not a tool list; tools/list is the catalog."
        ),
        mime_type="text/markdown",
    )
    def guide() -> str:
        """How to reach a target and read pwn-mcp results."""
        return GUIDE
