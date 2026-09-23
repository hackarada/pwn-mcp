"""Standalone entrypoint for `fastmcp run` / fastmcp.json.

Imports the installed pwn_mcp package so the server modules can use
relative imports internally.
"""

from pwn_mcp.server import main, mcp

__all__ = ["mcp", "main"]

if __name__ == "__main__":
    main()
