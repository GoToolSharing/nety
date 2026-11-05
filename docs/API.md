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

### Diff between two scans

`GET /api/missions/{id}/scans/{scanID}/diff?against=<other scan id>` - what
changed on a network between two of its scans. Without `against`, the server
compares with the most recent earlier **completed** scan of the same network and
says so in `from_picked`. Both scans must be on the same network.

```jsonc
{
  "mission_id": 1, "network_id": 2,
  "from": { "id": 7, "network_id": 2, "kind": "discovery", "status": "completed",
            "created_at": "...", "finished_at": "..." },   // null on a first scan
  "to":   { "id": 9, ... },
  "from_picked": true,          // the server chose `from`
  "changed": true,
  "message": "",                // set when there is nothing to show
  "caveats": ["..."],           // what the comparison cannot see
  "counts": {
    "hosts_added": 1, "hosts_removed": 1, "hosts_same": 24, "hosts_moved": 1,
    "ports_opened": 2, "ports_closed": 1, "services_changed": 1,
    "findings_raised": 1, "findings_cleared": 1
  },
  "hosts":    [{ "change": "moved", "host_id": 11, "ip": "10.20.0.8",
                 "previous_ip": "10.20.0.7", "asset_id": 100, "asset_label": "srv-web" }],
  "services": [{ "change": "changed", "service_id": 21, "ip": "10.20.0.8", "port": 443,
                 "protocol": "tcp", "product": "nginx", "version": "1.24.0",
                 "previous_version": "1.18.0" }],
  "findings": [{ "change": "removed", "finding_id": 31, "ip": "10.20.0.8",
                 "check_id": "tls-expired", "severity": "low", "title": "..." }]
}
```

`change` is `added`, `removed`, `same`, `moved` or `changed`. A host is matched
on its address **and** on its asset, so a machine that took a new lease reads as
`moved` with both addresses rather than as one host gone and another appeared;
its ports and findings follow it. Only hosts are reported as `same`: an
unchanged port or finding is left out.

**How a version change is seen.** There is no per-scan copy of a result row: a
re-scan merges into the row that is already there. So the moment a scan
replaces a service's state, name, product or version, the previous value is
written to `service_changes` before it is lost, and `services_changed` reads
from there. That is what lets a version change be reported on a machine that
kept its address. Nothing is written when a re-scan finds the same thing.

**What a diff cannot see.** A comparison reaching back before this history
existed has no previous values to read, and says so in `caveats` rather than
reporting that nothing changed. Presence is worked out from `last_scan_id`
together with `first_seen` and the end time of the scan that stamped the row,
which assumes a scan of a network covers the whole network. `caveats` says all
of this in the response itself.

## Moving a whole mission

`GET /api/missions/{id}/bundle` (member)
`POST /api/missions/import?name=&create_users=` (administrator)

The other exports are readings of the results. This one is the results: every
row of every table the mission owns, so an engagement can be taken off a
machine that is about to be wiped and put back later. It carries the networks,
the scans with their pending work units and their logs, the hosts, services,
assets with every address each machine has held, the findings, the
segmentation results, the service change history, and every triage status and
note with its author.

It does not carry the audit log, which belongs to the installation and whose
entries can name work on another client, and it never carries a password hash.

The download is gzipped JSON. It states the bundle format and the schema
version it came from, and carries a SHA-256 of its own contents, so a
truncated or edited file is refused rather than restored as a partial
engagement. An import reads a compressed or an uncompressed file.

Accounts are matched by username, the only name a person keeps across two
databases. With `create_users`, the ones this installation does not have are
recreated disabled and with no password that can sign in, so the work keeps
its author without opening a way in. Without it, their statuses and notes come
back unattributed and the response names them.

An import always creates a new mission. It never merges into one that is
already here, so restoring the same file twice gives two copies rather than a
reconciliation nobody asked for. Whoever imported it is added to its members.
The response says how many rows of each table came back, which accounts were
recreated or not matched, and which columns this build had no place for.

## Results

`GET /api/missions/{id}/hosts?network_id=&ip=&sort=&dir=`
`GET /api/missions/{id}/services?network_id=&host_id=&port=&protocol=&q=&ip=&sort=&dir=&triage=&limit=&offset=&include_skipped=`
(`triage` takes a comma separated list of statuses)
`GET /api/missions/{id}/findings?network_id=&host_id=&ip=&sort=&dir=&triage=&include_skipped=`
`GET /api/missions/{id}/assets?ip=&sort=&dir=`
`GET /api/assets/{id}` · `PATCH /api/assets/{id}` `{label?, notes?, tags?, kind?, status?, note?}`
`POST /api/assets/{id}/merge` `{source_id}`
`GET /api/hosts/{id}` - host plus its services, asset and findings
`GET /api/missions/{id}/matrix?include_skipped=` - `{networks: [...], cells: [...], techniques: [...]}`
`GET /api/missions/{id}/reach?source_network_id=&include_skipped=`

**Filtering by address.** `ip` takes a single address or a CIDR prefix, IPv4
or IPv6: `ip=10.20.0.7` is that one address, `ip=10.20.0.0/24` is the subnet
and `ip=2001:db8::/32` the v6 one. A prefix written with host bits set is the
subnet it names (`10.20.0.7/24` means `10.20.0.0/24`). On the assets listing it
keeps the machines that answer at a matching address. Anything that is not an
address or a prefix is refused with a 400 saying so, rather than quietly
matching nothing.

Addresses are stored as text, which can neither be ordered numerically nor cut
on a bit boundary, so every table carrying one also carries `ip_sort`: the same
address as a family tag plus fixed-width hex. A prefix is the range between the
keys of its first and last address, and an address sort is `ORDER BY ip_sort`.
The column is filled on every write and was backfilled by migration 5.

**Sorting.** `sort` names a column and `dir` is `asc` (the default) or `desc`.
The sort runs in SQL over the whole listing, not over the page that came back,
and a stable tiebreaker on the primary key means paging through a sorted
listing never repeats or skips a row. A `sort` the server does not know falls
back to the listing's own order rather than failing, so an old bookmark still
works.

| Listing | `sort` accepts |
|---|---|
| hosts | `ip`, `hostname`, `mac`, `os`, `status`, `network`, `last_seen` |
| services | `ip`, `port`, `service`, `product`, `state`, `status`, `network`, `last_seen` |
| findings | `severity` (by rank, so `critical` is above `low`), `ip`, `check`, `title`, `status`, `network`, `last_seen` |
| assets | `label`, `kind`, `os`, `domain`, `ips` (how many addresses), `status`, `last_seen` |

**Exports are not filtered.** An export is the whole mission, so `ip`, `sort`
and `dir` are not read by `/export`: a report must not quietly drop a machine
because a screen filter was left on.

**Skipped hosts.** By default the service, finding, reachability and matrix
listings leave out the rows of a host whose triage status is `skipped`, and the
mission summary counts them the same way. `include_skipped=true` turns that off
and brings the rows back, each with its own triage untouched. A row with no
host (`host_id` / `target_host_id` of 0) is never hidden. The hosts listing
itself always shows skipped hosts: that is where they are put back in scope.

## Triage

A scan says what is exposed and which checks fired; deciding whether each
service, and each finding, is really a problem is manual work. These endpoints
track that pass so a long engagement keeps its place, and a re-scan never
erases it. Services, findings, hosts and machines work the same way throughout.

Statuses: `todo` (default), `in_progress`, `done`, `flagged`, `false_positive`,
`skipped`.

The last two are both ways of setting a row aside, and they are not the same
judgement: `skipped` says the operator is not spending time on it, while
`false_positive` says they looked and the check is wrong. The mission summary
leaves both out of its counters, so the overview reports what is left to deal
with rather than everything ever raised.

A host and a machine only ever use `todo` and `skipped`: nobody declares a
whole machine "done", so the interface offers it as in scope or out.

| Method | Path | Body |
|---|---|---|
| GET | `/api/services/{id}` | - |
| PATCH | `/api/services/{id}` | `{status?, note?}`, either or both; a field left out is left alone |
| POST | `/api/missions/{id}/services/triage` | `{service_ids: [], status}`, one status for a selection |
| GET | `/api/findings/{id}` | - |
| PATCH | `/api/findings/{id}` | `{status?, note?}`, same rules as a service |
| POST | `/api/missions/{id}/findings/triage` | `{finding_ids: [], status}`, one status for a selection |
| GET | `/api/hosts/{id}` | - |
| PATCH | `/api/hosts/{id}` | `{status?, note?}`, same rules as a service |
| POST | `/api/missions/{id}/hosts/triage` | `{host_ids: [], status}`, one status for a selection |
| PATCH | `/api/assets/{id}` | `{status?, note?}` beside the other fields; the status reaches every host of the machine |
| POST | `/api/missions/{id}/assets/triage` | `{asset_ids: [], status}`, one status for a selection, hosts included |
| GET | `/api/missions/{id}/triage?network_id=&include_skipped=` | counts per status, plus `total` and `reviewed` |

Every triage route needs a role that may write; reading one needs only access
to the mission.

**Skipping a machine.** Setting a status on an asset applies it to every host
currently attached to it (`hosts.asset_id`), because an asset is a machine and
a host is one of its addresses. A host the correlator attaches later to a
machine that is `skipped` is skipped with it, so a device that changes IP
mid-engagement stays out of scope instead of returning as a new host. A host
can also be skipped on its own without touching its machine. The note stays
where it was written and is never copied.

**Skipping never writes to what hangs off a host.** The services, findings and
segmentation results of a skipped host are filtered out of the listings above,
not modified: whatever the operator had already recorded against each one is
still there when the host goes back in scope.

Triage is carried on every service, finding, host and asset object under
`triage`:

```jsonc
"triage": {
  "status": "flagged",
  "note": "SMB signing not required, relay confirmed from the office VLAN",
  "updated_by": 2, "updated_by_name": "martina",
  "updated_at": "2026-11-04T09:30:00Z"
}
```

The summary counts the passes separately, because they are done separately:
the services stay at the top level and the findings and hosts sit beside them.
The service and finding counts leave out the rows of a skipped host, exactly as
the listings do, so a progress bar always adds up to the table under it.
`hidden` says what that left out, which is what the UI's banner reads.

```jsonc
{
  "counts": {"todo": 42, "done": 7, ...}, "total": 49, "reviewed": 7,
  "statuses": ["todo", "in_progress", "done", "flagged", "false_positive", "skipped"],
  "findings": {"counts": {"todo": 3, ...}, "total": 3, "reviewed": 0},
  "hosts": {"counts": {"todo": 11, "skipped": 1, ...}, "total": 12, "reviewed": 1},
  "hidden": {
    "hosts": 1, "host_labels": ["ws-042"],
    "services": 14, "findings": 3, "reach": 21
  }
}
```

Triage is never written by a scan, and it is exported in the hosts, services,
findings and machines CSVs, the Excel workbook, the JSON dump and the reports.

## Exports

`GET /api/missions/{id}/export?format=<id>&network_id=&scan_id=&against=` -
streams a file with `Content-Disposition`.
`GET /api/export-formats` - `[{id, title, extension, content_type}]`

Formats: `json`, `csv-hosts`, `csv-services`, `csv-findings`, `csv-reach`,
`csv-assets`, `csv-matrix`, `csv-diff`, `nmap-xml`, `gnmap`, `targets-txt`,
`markdown`, `html`, `xlsx`.

**The diff travels with the export.** `csv-diff` is the sheet of what changed,
and the JSON dump carries the same thing under `diff`. `scan_id` and `against`
name the two scans; with neither, it is the last completed scan of the mission
against the one before it on the same network. A mission scanned only once has
no diff, and `csv-diff` comes out with its header alone.

**Exports are complete.** Unlike the listings, an export carries every row of
the mission, skipped hosts and their services, findings and segmentation
results included. A report that quietly dropped a machine because it was parked
on screen would be a report that lies; the triage columns travel with the rows
instead, so a reader can see which ones were out of scope.

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
