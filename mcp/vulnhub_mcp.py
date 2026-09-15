#!/usr/bin/env python3
"""VulnHub MCP server.

Gives an agent the tools to work VulnHub's asset estate: read it, correct the
CMDB, map an asset on to its Tenable record, and work the scanning-coverage
gap list -- the assets the CMDB or Intune knows about that Tenable has never
scanned, which contribute zero to every vulnerability chart and therefore look
perfect.

Speaks MCP over stdio with no third-party dependencies, because the one thing
worse than no tooling is tooling that stops working when a package moves.

Configuration, in order of precedence:

    VULNHUB_URL     default https://vulnhub.example.com
    VULNHUB_USER    default vulnhub-mcp
    VULNHUB_TOKEN   or the contents of VULNHUB_TOKEN_FILE
    VULNHUB_TOKEN_FILE  default /home/romy/vulnhub/.mcp_token

The token is a WordPress application password. It is read from disk and used
as HTTP basic auth; it is never logged, and WordPress will only accept it over
HTTPS.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("VULNHUB_URL", "https://vulnhub.example.com").rstrip("/")
USER = os.environ.get("VULNHUB_USER", "vulnhub-mcp")
TOKEN_FILE = os.environ.get("VULNHUB_TOKEN_FILE", "/home/romy/vulnhub/.mcp_token")
API = BASE + "/wp-json/vulnhub-mcp/v1"
TIMEOUT = 60


def token() -> str:
    tok = os.environ.get("VULNHUB_TOKEN", "")
    if tok:
        return tok.strip()
    try:
        with open(TOKEN_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError as exc:
        raise RuntimeError(
            f"No VulnHub token. Set VULNHUB_TOKEN or create {TOKEN_FILE}: {exc}"
        ) from exc


def call(method: str, path: str, params=None, body=None):
    url = API + path
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "")})

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    # Cloudflare sits in front of the tunnel and bans urllib's default
    # user-agent outright (error 1010), so identify ourselves properly.
    req.add_header("User-Agent", "VulnHub-MCP/1.0 (+https://vulnhub.example.com)")
    auth = base64.b64encode(f"{USER}:{token()}".encode()).decode()
    req.add_header("Authorization", "Basic " + auth)

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:600]
        try:
            parsed = json.loads(detail)
            msg = parsed.get("message", detail)
        except Exception:
            msg = detail
        raise RuntimeError(f"VulnHub returned {exc.code}: {msg}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach VulnHub at {BASE}: {exc.reason}") from None


# --------------------------------------------------------------------- tools

TOOLS = [
    {
        "name": "vulnhub_coverage_summary",
        "description": (
            "Scanning coverage across the estate: how many assets Tenable has actually "
            "scanned, how many it has never seen, and a breakdown by a chosen dimension. "
            "Start here when asked how well covered the estate is."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dimension": {
                    "type": "string",
                    "description": "asset_type, environment, criticality, primary_source, operating_system, team or location.",
                    "default": "asset_type",
                }
            },
        },
    },
    {
        "name": "vulnhub_coverage_gaps",
        "description": (
            "The assets that need a scanner pointed at them: known to the CMDB or Intune "
            "but absent from Tenable, present in Tenable but never scanned, or last "
            "scanned outside the freshness window."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "description": "not_in_tenable, never_scanned or stale. Omit for all three.",
                },
                "asset_type": {"type": "string"},
                "search": {"type": "string", "description": "Hostname, FQDN, IP or serial."},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
        },
    },
    {
        "name": "vulnhub_search_assets",
        "description": "Search the asset inventory by hostname, FQDN, IP or serial, optionally filtered by type or coverage state.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string"},
                "asset_type": {"type": "string"},
                "coverage": {"type": "string", "description": "A coverage state, or 'gap' for any gap."},
                "limit": {"type": "integer", "default": 25},
                "offset": {"type": "integer", "default": 0},
            },
        },
    },
    {
        "name": "vulnhub_get_asset",
        "description": "One asset in full: identities, owner, coverage state and open findings by severity.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "integer"}},
            "required": ["id"],
        },
    },
    {
        "name": "vulnhub_upsert_asset",
        "description": (
            "Create or update a CMDB asset record. Matches an existing asset on cmdb_id, "
            "tenable_uuid, intune_id, serial_number or hostname before creating a new one, "
            "so calling this twice with the same identity updates rather than duplicates. "
            "At least one identifying field is required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cmdb_id": {"type": "string"},
                "hostname": {"type": "string"},
                "fqdn": {"type": "string"},
                "ipv4": {"type": "string", "description": "A real address; 'DHCP' and similar placeholders are discarded."},
                "serial_number": {"type": "string"},
                "asset_type": {"type": "string", "description": "workstation, server, mobile, network, cloud, appliance."},
                "operating_system": {"type": "string"},
                "criticality": {"type": "string"},
                "environment": {"type": "string"},
                "business_service": {"type": "string"},
                "lifecycle_status": {"type": "string", "description": "Free text; normalised to the platform's vocabulary."},
                "intune_id": {"type": "string"},
                "tenable_uuid": {"type": "string"},
            },
        },
    },
    {
        "name": "vulnhub_update_asset",
        "description": "Change fields on an existing asset by id. Use this to correct classification and ownership data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "fields": {"type": "object", "description": "Any writable asset field and its new value."},
            },
            "required": ["id", "fields"],
        },
    },
    {
        "name": "vulnhub_map_tenable",
        "description": (
            "Attach an asset to its Tenable record by UUID. This is what turns a "
            "'not in Tenable' coverage gap into a covered asset. Refuses with a 409 if "
            "another asset already holds that UUID, because that is a record merge, not a mapping."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "integer"}, "tenable_uuid": {"type": "string"}},
            "required": ["id", "tenable_uuid"],
        },
    },
    {
        "name": "vulnhub_list_teams",
        "description": "Remediation teams, for assigning ownership.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "vulnhub_recalculate_coverage",
        "description": "Recompute every asset's coverage state. Run after a batch of changes; a scheduled sync does it automatically.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def run_tool(name: str, args: dict):
    if name == "vulnhub_coverage_summary":
        return call("GET", "/coverage", {"dimension": args.get("dimension", "asset_type")})
    if name == "vulnhub_coverage_gaps":
        return call("GET", "/coverage/gaps", {
            "state": args.get("state"),
            "asset_type": args.get("asset_type"),
            "search": args.get("search"),
            "limit": args.get("limit", 50),
            "offset": args.get("offset", 0),
        })
    if name == "vulnhub_search_assets":
        return call("GET", "/assets", {
            "search": args.get("search"),
            "asset_type": args.get("asset_type"),
            "coverage": args.get("coverage"),
            "limit": args.get("limit", 25),
            "offset": args.get("offset", 0),
        })
    if name == "vulnhub_get_asset":
        return call("GET", f"/assets/{int(args['id'])}")
    if name == "vulnhub_upsert_asset":
        return call("POST", "/assets", body={k: v for k, v in args.items() if v not in (None, "")})
    if name == "vulnhub_update_asset":
        return call("PATCH", f"/assets/{int(args['id'])}", body=dict(args.get("fields") or {}))
    if name == "vulnhub_map_tenable":
        return call("PATCH", f"/assets/{int(args['id'])}/tenable",
                    body={"tenable_uuid": args["tenable_uuid"]})
    if name == "vulnhub_list_teams":
        return call("GET", "/teams")
    if name == "vulnhub_recalculate_coverage":
        return call("POST", "/coverage/recalculate", body={})

    raise RuntimeError(f"Unknown tool: {name}")


# ---------------------------------------------------------------- transport

def reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    try:
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        # The client hung up mid-answer. Nothing to say and nobody to say it to.
        sys.exit(0)


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "initialize":
            reply(msg_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vulnhub", "version": "1.0.0"},
            })
        elif method == "tools/list":
            reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                result = run_tool(params.get("name", ""), params.get("arguments") or {})
                reply(msg_id, {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False,
                })
            except Exception as exc:  # noqa: BLE001 -- surfaced to the agent as tool output
                reply(msg_id, {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                })
        elif msg_id is not None:
            reply(msg_id, error={"code": -32601, "message": f"Unknown method: {method}"})


if __name__ == "__main__":
    main()
