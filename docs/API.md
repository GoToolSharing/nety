# NETY HTTP API

Base path `/api`. JSON in, JSON out, UTF-8. All times are RFC 3339 UTC.

Authentication is a session cookie (`nety_session`, HttpOnly, SameSite=Lax,
Secure unless TLS is disabled). Every mutating request must also carry the
CSRF token: read it from the `nety_csrf` cookie (readable by JS) and send it
back in the `X-CSRF-Token` header.

Errors are `{"error": "message", "code": "slug"}` with a 4xx/5xx status.
Common codes: `unauthorized`, `forbidden`, `not_found`, `conflict`,
`invalid`, `busy`, `internal`.

Roles: `admin` (everything, user management), `operator` (run scans on their
missions), `viewer` (read-only on their missions).

## Session

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/auth/login` | `{username, password}` | sets the cookies, returns `{user, csrf_token}` |
| POST | `/api/auth/logout` | - | clears the session |
| GET | `/api/auth/me` | - | `{user, csrf_token}`; 401 when not logged in |
| POST | `/api/auth/password` | `{current_password, new_password}` | self-service change |

## Users (admin only, except `GET /me`)

`GET /api/users` · `POST /api/users` `{username, display_name, role, password}`
`PATCH /api/users/{id}` `{display_name?, role?, disabled?}`
`POST /api/users/{id}/password` `{new_password, must_change?}`
`DELETE /api/users/{id}`

## Missions

`GET /api/missions` - missions the caller can see
`POST /api/missions` `{name, client?, description?, scope_cidrs?, exclude_cidrs?}`
`GET /api/missions/{id}` · `PATCH /api/missions/{id}` · `DELETE /api/missions/{id}` (admin)
`GET /api/missions/{id}/members` · `PUT /api/missions/{id}/members` `{user_ids: []}`
`GET /api/missions/{id}/summary` - counts per network, severity totals, matrix size

## Networks (one per VLAN / attachment point)

`GET /api/missions/{id}/networks`
`POST /api/missions/{id}/networks` `{name, vlan_id?, description?, interface?, local_ip?, prefixes?, gateway?, dns_servers?}`
`GET|PATCH|DELETE /api/networks/{id}`
`GET /api/interfaces` - local NICs the server can use
`POST /api/networks/detect` `{interface?}` - auto-detect addressing/gateway/DNS/DHCP, returns a draft Network (does not save)

## Scans

`POST /api/missions/{id}/scans` → 201 `{scan}`
```jsonc
{
  "network_id": 12,
  "kind": "discovery",           // discovery | segmentation | l2probe
  "options": {
    "profile": "standard",
    "targets": ["10.10.0.0/16"], "excludes": [], "auto_targets": true,
    "tcp_ports": "top1000", "udp_ports": "top20",
    "rate": 5000, "retries": 1, "timeout_ms": 3000, "concurrency": 64,
    "scan_mode": "auto",         // auto | syn | connect
    "host_discovery": true, "service_detection": true,
    "identity_collection": true, "checks": true,
    "allow_default_creds": false,   // opt-in, the only intrusive checks
    // segmentation only
    "source_network_ids": [], "techniques": [], "allow_l2_active": false,
    "vlan_range": ""
  }
}
```
`GET /api/missions/{id}/scans` · `GET /api/scans/{id}` · `DELETE /api/scans/{id}`
`POST /api/scans/{id}/start` - start or **resume** (same endpoint; a paused or
interrupted scan continues exactly where it stopped)
`POST /api/scans/{id}/pause` · `POST /api/scans/{id}/stop`
`POST /api/scans/{id}/retry-failed` - requeue the failed work units
`GET /api/scans/{id}/logs?after=<id>&limit=` - live log lines
`GET /api/scan-profiles` - the built-in profiles for the launch form
`GET /api/techniques` - segmentation techniques `{id, title, description, l2_active, one_way, default}`
`GET /api/checks` - the check catalog

A scan object carries `status` (`queued|running|paused|completed|failed|cancelled`),
`phase`, `progress` (0..1), `phases[]` (`{phase,total,done,failed,active,started}`),
`stats`, `resumable`, and the timestamps.

## Results

`GET /api/missions/{id}/hosts?network_id=`
`GET /api/missions/{id}/services?network_id=&host_id=&port=&protocol=&q=&triage=&limit=&offset=`
(`triage` takes a comma separated list of statuses)
`GET /api/missions/{id}/findings?network_id=&host_id=&triage=`
`GET /api/missions/{id}/assets`
`GET /api/assets/{id}` · `PATCH /api/assets/{id}` `{label?, notes?, tags?, kind?}`
`POST /api/assets/{id}/merge` `{source_id}`
`GET /api/hosts/{id}` - host plus its services
`GET /api/missions/{id}/matrix` - `{networks: [...], cells: [...], techniques: [...]}`
`GET /api/missions/{id}/reach?source_network_id=`

## Triage

A scan says what is exposed and which checks fired; deciding whether each
service, and each finding, is really a problem is manual work. These endpoints
track that pass so a long engagement keeps its place, and a re-scan never
erases it. Services and findings work the same way throughout.

Statuses: `todo` (default), `in_progress`, `done`, `flagged`, `skipped`.

| Method | Path | Body |
|---|---|---|
| GET | `/api/services/{id}` | - |
| PATCH | `/api/services/{id}` | `{status?, note?}`, either or both; a field left out is left alone |
| POST | `/api/missions/{id}/services/triage` | `{service_ids: [], status}`, one status for a selection |
| GET | `/api/findings/{id}` | - |
| PATCH | `/api/findings/{id}` | `{status?, note?}`, same rules as a service |
| POST | `/api/missions/{id}/findings/triage` | `{finding_ids: [], status}`, one status for a selection |
| GET | `/api/missions/{id}/triage?network_id=` | counts per status, plus `total` and `reviewed` |

Triage is carried on every service and every finding object under `triage`:

```jsonc
"triage": {
  "status": "flagged",
  "note": "SMB signing not required, relay confirmed from the office VLAN",
  "updated_by": 2, "updated_by_name": "martina",
  "updated_at": "2026-11-04T09:30:00Z"
}
```

The summary counts the two passes separately, because they are done
separately: the services stay at the top level and the findings sit beside
them under `findings`.

```jsonc
{
  "counts": {"todo": 42, "done": 7, ...}, "total": 49, "reviewed": 7,
  "statuses": ["todo", "in_progress", "done", "flagged", "skipped"],
  "findings": {"counts": {"todo": 3, ...}, "total": 3, "reviewed": 0}
}
```

Triage is never written by a scan, and it is exported in the services and
findings CSVs, the Excel workbook, the JSON dump and the reports.

## Exports

`GET /api/missions/{id}/export?format=<id>&network_id=` - streams a file with
`Content-Disposition`.
`GET /api/export-formats` - `[{id, title, extension, content_type}]`

Formats: `json`, `csv-hosts`, `csv-services`, `csv-findings`, `csv-reach`,
`csv-assets`, `nmap-xml`, `gnmap`, `targets-txt`, `markdown`, `html`, `xlsx`.

## Live events (WebSocket)

`GET /api/missions/{id}/events` - upgrade to WebSocket. The server pushes
`model.Event` envelopes:

```jsonc
{ "type": "service", "mission_id": 1, "scan_id": 7,
  "time": "2026-11-04T13:20:01Z", "data": { /* the model object */ } }
```

Types: `scan.status`, `scan.phase`, `scan.progress`, `scan.log`, `host`,
`service`, `finding`, `reach`, `asset`, `network`.

The server sends a ping every 30 s; clients should reconnect with backoff.
If the client cannot keep up, the server sends
`{"type":"scan.log","data":{"level":"warn","message":"events dropped, resynchronise"}}`
and the client must refetch the affected tables.

## Status

`GET /api/status` - version, uptime, privileges (whether raw sockets are
available), running scans, database counters. No auth required for the
version field; the rest needs a session.
