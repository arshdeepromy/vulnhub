# Jira: OAuth 2.0 (3LO), project allowlist, requests and attachments

The Jira connector can sign in two ways:

| | API token | OAuth (3LO) |
|---|---|---|
| Acts as | the account the token belongs to | whoever clicked **Allow** |
| Credential | email + API token (Basic) | Bearer access token, refreshed with a rotating refresh token |
| Host called | the site, `https://<site>.atlassian.net/rest/…` | the gateway, `https://api.atlassian.com/ex/jira/<cloudId>/rest/…` |
| Setting | `auth_method = basic` (default) | `auth_method = oauth` |

Both modes use the same request paths. Only the host and the `Authorization`
header change, and both of those are decided in `VulnHub_Jira_Client::call()`.
Every other class calls the client without knowing which mode is active.

## Setting it up

1. At developer.atlassian.com → Console → Create → **OAuth 2.0 integration**:
   - Add the **Jira API** and **Jira Service Management API** permissions and
     their scopes.
   - Under Authorization → OAuth 2.0 (3LO), set the callback URL to the
     connector's **Callback URL** exactly as shown.
2. On the connector, set:
   - **Sign in with:** OAuth.
   - **OAuth client ID** and **OAuth client secret** from the Console.
   - **Jira site URL:** the `*.atlassian.net` address, not a custom domain in
     front of it.
   - **Only write to projects** (see below).
   Then save.
3. Click **Connect to Jira**, approve the consent screen, and you land back on
   the settings screen showing who is connected. Run **Test connection**.

**Callback URL.** Atlassian requires an exact match, including the query
string. If the setting is blank, the callback is derived from `admin_url()`,
which follows the host the request came in on. On an install reached both as
`localhost` and through a public hostname, that derived value changes with the
host, so set the callback explicitly. `http://localhost:<port>` is allowed.
Any other host must use `https`.

**Scopes.** The defaults are
`read:jira-work write:jira-work read:jira-user read:servicedesk-request write:servicedesk-request offline_access`.
`offline_access` is always added, because without it Atlassian issues no
refresh token and the connection stops working an hour after connecting.

## The flow (`VulnHub_Jira_OAuth`)

1. **Start.** `admin-post.php?action=vulnhub_jira_oauth_start` needs a nonce and
   `vulnhub_manage`.
   - It mints a `state` and a PKCE verifier, and stores them in a 10-minute
     transient keyed by an HMAC of the state.
   - The request is bound to the browser (a cookie holding a random binder) and
     to the WordPress user who started it.
   - It then redirects to `auth.atlassian.com/authorize` with `prompt=consent`
     and an S256 code challenge.
2. **Callback.** `admin-post.php?action=vulnhub_jira_oauth_cb`:
   - Uses the state once, then deletes it, and checks the browser binding and
     the user.
   - Exchanges the code at `POST /oauth/token` (JSON body, with
     `code_verifier`).
   - Stores both tokens encrypted.
   - Picks the `cloudId` from `GET /oauth/token/accessible-resources`: the
     resource whose URL matches the configured site, or the only resource if no
     site is set. When several sites come back and none matches, it
     **refuses** rather than guessing.
   - Reads `/myself` through the gateway to record who connected.
3. **Use.** `access_token()` refreshes when fewer than 60 seconds remain.
   `call()` refreshes once and retries once on a 401.
   - Each refresh stores the new refresh token, because Atlassian rotates them.
   - Refreshing holds a 30-second lock (`vulnhub_jira_oauth_refresh_lock`), so
     two workers do not both spend the same refresh token.
   - `invalid_grant` means the grant is gone. The tokens are dropped and calls
     answer "not connected", instead of failing with a 401 on every request.
4. **Disconnect.** Deletes the tokens locally. Atlassian documents no revocation
   endpoint for 3LO apps, so the screen tells the operator to remove the app
   under Atlassian account settings → Connected apps.

**Where state lives.**
- **Tokens:** connector secrets `oauth_access_token` and `oauth_refresh_token`
  (encrypted).
- **Connection details:** the separate option `vulnhub_jira_oauth` (cloudId,
  site, account, expiry, last message).

Connection details are deliberately **not** in the connector settings.
`Settings::update()` writes back the whole array the request loaded, so a sync
that started before a refresh would restore the old expiry, and one that
started before a Disconnect would restore the old cloudId. The OAuth option is
always read fresh.

**Configured, under OAuth.** Core's `Connector::is_configured()` treats every
`required` field as mandatory, and the email and API token are required for
API-token sign-in. Under OAuth those fields are hidden and empty, so the Jira
connector overrides the check: it counts as configured when the OAuth app is
saved, the connection is live, and a default project is set. Without this
override the connector card showed a working connection as *Not configured*.

Nothing logs a token, code or verifier. `Http::scrub()` already masks
`access_token`, `code` and `client_secret` in URLs.

## Project allowlist

**Only write to projects** (`allowed_projects`) is a comma-separated list of
project keys. OAuth scopes are product-wide, so a token that can write to one
project can write to all of them. This setting is what narrows it.

It is enforced in `VulnHub_Jira_Client::call()`, the one method every request
goes through, including in mock mode. No caller can bypass it: not the ticketer,
reopener, automation, routing, or anything added later.

- **Reads** are never refused.
- **Writes** are checked against the project they target:
  - `POST /issue`: `fields.project.key`, or the project looked up from its id.
  - `POST /servicedeskapi/request` and `/servicedesk/{id}/…`: the desk's
    `projectKey`.
  - Anything under `/issue/{key}` or `/request/{key}`: the key prefix. A
    numeric id is looked up first.
- **A write whose project cannot be determined is refused.** The check fails
  closed.
- A refusal is a synthetic `403` response whose error says why. It is logged in
  the run log, and no request is sent.

Blank means unrestricted, which is how existing installs behave. The
connection test fails if the default project is outside the allowlist.

## Adds are sent once

Anything that adds to Jira is attempted **exactly once**: creating an issue
(`create_issue`) or a request (`create_request`), commenting (`comment`,
`request_comment`), and uploading (`attach`, `request_attach`). The limit is
set by `VulnHub_Jira_Client::CREATE_ATTEMPTS`.

Core's `Http` retries timeouts and 5xx responses up to five times. That is right
for a read and wrong for an add: Jira can create the issue, post the comment or
store the file, then fail to answer, and a retry makes a second one. A failed
add returns its error for a person to repeat.

- **Still retried:** reads, edits (summary, transitions) and the remote link,
  which is idempotent through its `globalId`.
- **One retry kept for adds:** the OAuth refresh after a `401`, because a 401
  means Jira did nothing.

## One raise per group at a time

The ticketer checks for an open ticket covering the group (for example, the
same asset and severity) and then either extends that ticket or creates one.
Those are two separate steps. Without a guard, two raises for the same group
arriving together would both find nothing open and both create an issue.

`VulnHub_Jira_Ticketer::handle_group()` therefore holds a lock for the group
(the option `vulnhub_jira_raise_<md5 of grouping key>`, taken with
`add_option()`, which only one caller can win) around the check and the create.

- **A second raise for the same group arriving meanwhile is refused** with "A
  ticket for this asset and severity is being raised right now. Try again in a
  moment." Retrying after that joins the ticket the first raise saved.
- **Different groups never block each other.**
- **A lock older than 120 seconds belongs to a raise that died,** so it is taken
  over rather than blocking for ever.

## Client methods added

| Method | Endpoint |
|---|---|
| `create_request( $desk, $type, $fields )` | `POST /rest/servicedeskapi/request` |
| `get_request( $key )` | `GET /rest/servicedeskapi/request/{key}` |
| `request_comment( $key, $text, $public )` | `POST /rest/servicedeskapi/request/{key}/comment` |
| `issue_comments( $key )` | `GET /rest/api/3/issue/{key}/comment` |
| `attach( $key, $name, $bytes, $mime )` | `POST /rest/api/3/issue/{key}/attachments` (multipart, `file`) |
| `request_attach( $desk, $key, … )` | `POST …/servicedesk/{id}/attachTemporaryFile`, then `POST …/request/{key}/attachment` |

Core's `Http` JSON-encodes array bodies, so uploads build the multipart body as
a string, which `Http` sends as-is. The mock site answers all of these.

## Not done yet

- The ticketer still raises issues through `POST /rest/api/3/issue`, with the
  request type only choosing the issue type. Raising through
  `create_request()` would keep the JSM portal, request type and SLAs, but it
  changes which fields can be set (labels, priority and due date are not all
  request fields), so it is a separate change.
- No MCP tools for raise, get, comment and attach yet.
