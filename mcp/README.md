# VulnHub MCP connector

Lets an agent read the asset estate, correct the CMDB, map assets on to their
Tenable records and work the scanning-coverage gap list.

## Two halves

**`wp-content/plugins/vulnhub-mcp`** — the REST surface, under
`/wp-json/vulnhub-mcp/v1`. Writes go through `Repo::upsert_asset()`, the same
path the connectors use, so identity matching, IP cleaning, lifecycle
normalisation and the ownership engine all behave exactly as they do for a
real sync. Every change is written to the audit trail against the acting
account, because "an agent changed it" has to be answerable months later.

**`mcp/vulnhub_mcp.py`** — an MCP server speaking stdio, with no third-party
dependencies. It is a thin client for the REST surface above.

## Tools

| Tool | What it does |
|---|---|
| `vulnhub_coverage_summary` | Coverage across the estate, broken down by device type, environment, criticality, discovery source, OS, team or site |
| `vulnhub_coverage_gaps` | The gap list: not in Tenable / never scanned / stale |
| `vulnhub_search_assets` | Search by hostname, FQDN, IP or serial; filter by type or coverage |
| `vulnhub_get_asset` | One asset: identities, owner, coverage, open findings |
| `vulnhub_upsert_asset` | Create or update a CMDB record, matched on identity so it never duplicates |
| `vulnhub_update_asset` | Correct fields on an existing asset |
| `vulnhub_map_tenable` | Attach an asset to its Tenable UUID — the call that closes a coverage gap |
| `vulnhub_list_teams` | Remediation teams, for assigning ownership |
| `vulnhub_recalculate_coverage` | Recompute coverage after a batch of changes |

## Credentials

The server authenticates as the `vulnhub-mcp` WordPress account using an
application password held in `/srv/vulnhub/.mcp_token` (chmod 600).
That account has the `vulnhub_admin` role and no WordPress administration
rights, so a mistake in an agent's prompt cannot reach wp-admin.

WordPress only accepts application passwords over HTTPS, so the server needs
to talk to the site's public HTTPS hostname (e.g. through whatever reverse
proxy or tunnel you publish it behind) rather than to `localhost:8093`
directly. If that's Cloudflare, note it bans urllib's default user-agent
outright with error 1010, which is why the client sets its own.

To rotate the credential:

```bash
cd /srv/vulnhub
./wp.sh user application-password list vulnhub-mcp          # find the old one
./wp.sh user application-password delete vulnhub-mcp <uuid>
./wp.sh user application-password create vulnhub-mcp "MCP server" --porcelain \
  | tr -d '\r\n' > .mcp_token
chmod 600 .mcp_token
```

## Registering it with a client

```json
{
  "mcpServers": {
    "vulnhub": {
      "command": "python3",
      "args": ["/srv/vulnhub/mcp/vulnhub_mcp.py"],
      "env": {
        "VULNHUB_URL": "https://your-domain.example",
        "VULNHUB_USER": "vulnhub-mcp",
        "VULNHUB_TOKEN_FILE": "/srv/vulnhub/.mcp_token"
      }
    }
  }
}
```

`VULNHUB_URL` must be set to wherever you've published the site (see the main
README's "Publishing behind a reverse proxy or tunnel" section) — application
passwords require HTTPS, so `localhost:8093` alone won't work here.

## Checking it by hand

```bash
cd /srv/vulnhub
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vulnhub_coverage_summary","arguments":{}}}' \
  | python3 mcp/vulnhub_mcp.py
```

## Guard rails worth knowing

- `vulnhub_upsert_asset` refuses a body with no identifying field, rather than
  creating a duplicate asset on every call.
- `vulnhub_map_tenable` refuses with 409 if another asset already holds that
  UUID. Pointing two asset records at one Tenable record is a merge, and a
  merge is not something to do silently on an agent's say-so.
- Reads need `vulnhub_view`; writes need `vulnhub_manage`. There is no route
  without a real `permission_callback`.
