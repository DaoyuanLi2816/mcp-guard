"""Example: a *vulnerable* HTTP-transport MCP server.

This example is config-only for v0.1 (mcp-guard's live HTTP inspector is
on the roadmap), but we ship a minimal binding-anywhere stub so the
intent is reproducible. The startup command in `mcp.json` is what
`mcp-guard scan` flags.

Do not run on a network you don't fully control.
"""

from __future__ import annotations

import argparse
import http.server
import json


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        try:
            msg = json.loads(body) if body else {}
        except json.JSONDecodeError:
            msg = {}
        resp = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"echoed": msg}}
        payload = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):  # silence default stderr logs
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    httpd = http.server.HTTPServer((args.bind, args.port), _Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
