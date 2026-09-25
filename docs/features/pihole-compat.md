# Pi-hole Compatibility

Ferrous DNS can expose a Pi-hole v6 compatible API, making it a drop-in replacement for existing Pi-hole integrations, dashboards, and automation scripts.

---

## Enabling Compatibility Mode

```toml
[server]
pihole_compat = true
```

!!! note "Restart required"
    Changing `pihole_compat` requires a server restart to take effect.

---

## How It Works

When `pihole_compat = true`:

| Path | API |
|:-----|:----|
| `/api/*` | Pi-hole v6 compatible API |
| `/ferrous/api/*` | Ferrous DNS native API |
| `/` | Ferrous DNS dashboard (unchanged) |

The Ferrous dashboard automatically detects the correct API prefix via the `/ferrous-config.js` endpoint — no manual configuration needed.

When `pihole_compat = false` (default):

| Path | API |
|:-----|:----|
| `/api/*` | Ferrous DNS native API |
| `/` | Ferrous DNS dashboard |

---

## Supported Pi-hole v6 Endpoints

The compatibility layer is **not read-only** — it implements full CRUD for
domains, lists, groups and clients, a blocking enable/disable toggle, and the
Pi-hole action endpoints. All paths below are served under `/api/*` when
`pihole_compat = true`.

!!! tip "Interactive spec"
    The Pi-hole layer publishes its own OpenAPI document at `GET /api/openapi.json`
    with a built-in Scalar UI at `GET /api/docs`. See the
    [REST API reference](../api.md#interactive-documentation-openapi-scalar) for the
    full route table.

### Authentication

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/auth` | Login — returns a session token (`sid`) |
| `GET` | `/api/auth` | Get current session status |
| `DELETE` | `/api/auth` | Logout — invalidate session |

### Statistics & history

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/stats/summary` | Dashboard summary (queries, blocked, percentage, clients); `forwarded` counts only upstream answers — cache hits and local DNS records are excluded |
| `GET` | `/api/stats/history` | Query history timeline for charts |
| `GET` | `/api/stats/top_blocked` | Top blocked domains |
| `GET` | `/api/stats/top_clients` | Top querying clients |
| `GET` | `/api/stats/top_domains` | Top allowed domains (`?blocked=true` for blocked) |
| `GET` | `/api/stats/query_types` | Query type distribution (A, AAAA, CNAME, etc.) |
| `GET` | `/api/stats/upstreams` | Upstream DNS server usage |
| `GET` | `/api/stats/recent_blocked` | Most recently blocked domain |
| `GET` | `/api/history/clients` | Per-client query totals for the last 24 h |

!!! note "Database aliases"
    For Pi-hole compatibility several stats endpoints are also reachable under
    `/api/stats/database/*` (`summary`, `top_domains`, `top_clients`, `upstreams`,
    `query_types`), and `/api/stats/history` is mirrored at `/api/history`.

### Query log & search

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/queries` | Paginated query log (filters: `domain`, `client`, `status`, `cursor`, `length`, `start`) |
| `GET` | `/api/queries/suggestions` | Categorised filter suggestions from recent queries |
| `GET` | `/api/search/{domain}` | Check whether a domain would be blocked (optional `?client`) |

### DNS blocking toggle

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/dns/blocking` | Current blocking status; `timer` is the seconds left on a pending timer, `null` when none |
| `POST` | `/api/dns/blocking` | Set blocking: `{"blocking": false, "timer": 300}` — with a `timer` the mode flips back when it elapses |

As on Pi-hole, the timer works both ways: `{"blocking": true, "timer": N}` enables blocking now and disables it after `N` seconds. Every `POST` replaces the pending timer, so one without `timer` cancels it. The timer lives in memory and does not survive a restart.

### Domains (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/domains` | List all managed and regex domains |
| `GET` | `/api/domains/{type}` | List by type (`allow` / `deny`) |
| `GET` | `/api/domains/{type}/{kind}` | List by type and kind (`exact` / `regex`) |
| `POST` | `/api/domains/{type}/{kind}` | Create a domain entry |
| `PUT` | `/api/domains/{type}/{kind}/{domain}` | Update a domain entry |
| `DELETE` | `/api/domains/{type}/{kind}/{domain}` | Delete a domain entry |
| `POST` | `/api/domains:batchDelete` | Batch delete domains |

### Lists / adlists (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/lists` | List all adlists (optional `?type=allow\|block`) |
| `POST` | `/api/lists?type=allow\|block` | Create an adlist |
| `GET` | `/api/lists/{list}` | Lists with this address (optional `?type=allow\|block`) |
| `PUT` | `/api/lists/{list}?type=allow\|block` | Update an adlist (`comment`, `groups`, `enabled`) |
| `DELETE` | `/api/lists/{list}?type=allow\|block` | Delete an adlist |
| `POST` | `/api/lists:batchDelete` | Batch delete: `[{"item": "<address>", "type": "block"}]` |

As in Pi-hole v6, `{list}` is the list's URL-encoded address, and `type` says which table it lives in: blocklists and allowlists are stored separately, so the same address — or the same numeric id, which `{list}` also accepts — can name one of each. `POST`, `PUT`, `DELETE` and every `batchDelete` item require `type`; a missing or unknown type is rejected with `400` and changes nothing. `GET /api/lists/{list}` without `type` returns the matches of both types. Each list in a reply carries `"type": "allow"` or `"type": "block"`, and `GET`/`PUT` on `/api/lists/{list}` reply with `{"lists": [...]}`.

!!! warning "Changed in v0.9.19"
    Earlier versions ignored the list type on `/api/lists/{id}`, so an allowlist whose id matched a blocklist could not be read, updated or deleted — the request hit the blocklist instead. `type` in replies was `0`/`1` and is now `"block"`/`"allow"`; the type moved from the `POST` body to `?type=`; `PUT` no longer renames a list; and `batchDelete` takes Pi-hole's `[{item, type}]` array instead of `{"items": [...]}`.

### Groups (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/groups` | List all groups |
| `POST` | `/api/groups` | Create a group |
| `GET` | `/api/groups/{name}` | Get a group by name |
| `PUT` | `/api/groups/{name}` | Update a group |
| `DELETE` | `/api/groups/{name}` | Delete a group |
| `POST` | `/api/groups:batchDelete` | Batch delete groups |

### Clients (CRUD)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/clients` | List all clients (`limit`, `offset`) |
| `POST` | `/api/clients` | Create a client |
| `GET` | `/api/clients/_suggestions` | IP/hostname suggestions |
| `PUT` | `/api/clients/{client}` | Update a client (by IP) |
| `DELETE` | `/api/clients/{client}` | Delete a client (by IP) |
| `POST` | `/api/clients:batchDelete` | Batch delete clients |

### Info

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/info/version` | Version info |
| `GET` | `/api/info/ftl` | FTL daemon info |
| `GET` | `/api/info/system` | Host system info (load, memory, disk) |
| `GET` | `/api/info/host` | Host hostname |
| `GET` | `/api/info/database` | Query database info |

### Actions

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/action/gravity` | Trigger a blocklist (gravity) reload |
| `POST` | `/api/action/restartdns` | Reload configuration in-memory (no process restart), like `POST /api/config/reload`: upstream pools hot-reloaded, command-line overrides kept |
| `POST` | `/api/action/flush/logs` | Clean up old query logs |

---

## Authentication

With `[auth] enabled = true` (the default), every endpoint except `/api/auth` requires a session — the same rule as a Pi-hole that has a password set. With `[auth] enabled = false` the API is open, like a Pi-hole without a password, and `POST /api/auth` answers `{"valid": true, "sid": null, "validity": -1}`.

The login flow is Pi-hole v6's:

1. `POST /api/auth` with `{"password": "..."}` returns `session.sid`. The password can be:
    - the **admin password** from `[auth.admin]` — the Pi-hole API always logs in as that account, since Pi-hole has a single password; or
    - an **API token** (Settings > API > API Tokens), the equivalent of Pi-hole's *app password*. As on Pi-hole, it skips the second factor, so use one for unattended integrations — it is what the Home Assistant Pi-hole v6 integration asks for as its "API key".
2. If the admin account has TOTP enabled, send the code in the same request: `{"password": "...", "totp": 123456}`. Without it the reply is `400` (`bad_request`); a wrong code is `401` (`unauthorized`).
3. Send the `sid` with every later request, in the `X-FTL-SID` header, a `sid` header, or the `?sid=` query parameter. Anything else gets `401` with `{"error": {"key": "unauthorized", ...}}`.
4. `DELETE /api/auth` with the same `sid` ends the session.

Failed logins count toward the same lockout as the dashboard login: after `login_rate_limit_attempts` wrong passwords or codes from one client, `POST /api/auth` answers `429` (`rate_limiting`) until `login_rate_limit_window_secs` has passed. See [Login lockout](security.md#login-lockout).

!!! note "Not supported"
    Pi-hole's `sid` **cookie** (sent with an `X-FTL-CSRF` header — what the Pi-hole web interface uses) and a `sid` inside the request body are not accepted, and `session.csrf` is always `null`. `validity` is the seconds left on the session (`session_ttl_hours`), not Pi-hole's sliding 30-minute timeout.

!!! warning "Changed in v0.9.19"
    Earlier versions served every Pi-hole endpoint without checking the session, and `POST /api/auth` accepted any password. Integrations that never logged in now need the admin password or an API token. An integration configured with a key that was never valid here — often an old Pi-hole app password — now gets `401`, and the server log shows `Pi-hole API login rejected`; add that same key as an API token (Settings > API > API Tokens > **Custom Token**) and the integration works again unchanged.

!!! note "Shared auth backend"
    Since v0.7.0, Pi-hole compat auth and Ferrous DNS auth share the same session system. A session created via `POST /api/auth` (Pi-hole) is also valid for Ferrous DNS native endpoints, and vice versa.

---

## Compatible Third-Party Tools

The following tools and integrations work with Ferrous DNS in Pi-hole compat mode:

| Tool | Status | Notes |
|:-----|:------:|:------|
| Pi-hole Android/iOS apps | Partial | Stats, summary and most management endpoints work; coverage varies by app version |
| Grafana Pi-hole dashboards | Works | Stats and history endpoints are compatible |
| Home Assistant Pi-hole integration | Works | Uses summary stats and the blocking toggle |
| Custom scripts using Pi-hole API | Partial | Depends on which endpoints the script uses |

!!! note
    Ferrous DNS implements the commonly used Pi-hole v6 endpoints — stats, history and top lists **plus** management: full CRUD for domains, lists, groups and clients, the DNS blocking toggle, and the action endpoints (gravity, restartdns, flush logs). You can also drive these through the Ferrous DNS native [REST API](../api.md).

---

## Migrating from Pi-hole

### Step 1: Export Your Pi-hole Configuration

Note your current Pi-hole settings:

- Upstream DNS servers
- Blocklist URLs (Settings > Blocklists)
- Custom blocked domains (Local DNS > DNS Records)
- Client groups and assignments

### Step 2: Configure Ferrous DNS

Transfer your settings to `ferrous-dns.toml`:

```toml
[server]
pihole_compat = true    # keep Pi-hole API for existing integrations

[[dns.pools]]
name = "default"
strategy = "Parallel"
priority = 1
servers = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

[blocking]
enabled = true
```

### Step 3: Add Blocklists

Add your Pi-hole blocklist URLs via the Ferrous DNS dashboard:

1. Open `http://<server>:8080`
2. Go to **DNS Filter > Blocklist Sources**
3. Add each URL and click **Save** — every list is downloaded and activated as
   soon as it is saved

### Step 4: Update DNS on Your Network

Point your router's DHCP DNS setting to your Ferrous DNS server IP. Clients will switch over as their DHCP leases renew.

### Step 5: Update Integrations

If you have tools pointing to Pi-hole's API:

- **Same server IP**: no changes needed — `/api/*` continues to work
- **Different server**: update the IP/hostname in your integration
- **Tools logged in with a Pi-hole app password**: create an API token with the same value (Settings > API > API Tokens > **Custom Token**) and they keep working unchanged

---

## Limitations

- Management is exposed (domains, lists, groups, clients, blocking toggle, gravity/restartdns/flush actions), but not every niche Pi-hole v6 endpoint is implemented — request payloads and field names track Pi-hole closely but may differ in edge cases
- `restartdns` reloads configuration in-memory (upstream pools included, command-line overrides kept); it does not restart the process, and `gravity` reloads blocklists rather than re-downloading via Pi-hole's gravity pipeline
- Gravity Sync is not supported (different database format)
- The Pi-hole web interface is not included — use the Ferrous DNS dashboard
