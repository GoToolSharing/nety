# NETY architecture and contracts

NETY is a single static Go binary (Linux, `CGO_ENABLED=0`) for internal-network
pentests. It serves an authenticated web platform (React SPA embedded with
`go:embed`) and drives native Go scanning engines, with **no nmap or masscan
subprocess**, everything is implemented in-process so results stream out as
they are found.

## Workflow

1. Operator plugs into VLAN A and creates a *Network* "VLAN A" in the mission.
   NETY auto-detects interface/IP/prefix/gateway/DNS/DHCP and passively sniffs
   CDP/LLDP/DTP/STP/802.1Q to learn about the switch port.
2. Launches a *discovery* scan: host discovery → port scan → service
   fingerprinting → identity collection → asset correlation → light checks.
3. Repeats on VLAN B, C, …
4. Launches *segmentation* scans: plugged on VLAN B, NETY replays every service
   discovered on the other networks using several techniques and fills a
   source→target reachability matrix.
5. *Assets* give machines a stable identity across days, IPs and VLANs, so a
   re-scan the next day does not produce a brand-new inventory.
6. Everything exports to JSON, CSV, Nmap XML, gnmap, Markdown, HTML, XLSX, txt.

## Non-negotiable requirements

### R1. Live results
No result may wait for the end of a scan. Every host, port, service, finding
and reachability result is **persisted and broadcast the moment it is known**:

- engines stream through callbacks (`out func(...)`) and never return bulk slices;
- the runner writes each result to SQLite immediately (batched by a short
  flush window, ≤ 250 ms) and publishes a `model.Event` on the bus;
- the API pushes events to the SPA over WebSocket, so tables fill up live;
- progress (`scan.progress`, `scan.phase`) is updated continuously.

### R2. Pause / resume / stop, crash-safe
A scan is split into persisted **work units** (`model.WorkUnit`) per phase
(`model.WorkPhase`). The runner claims units, executes them, marks them done.
Consequences:

- *pause* stops claiming new units and lets in-flight ones finish → status
  `paused`; *resume* continues exactly where it stopped;
- *stop* is a cancel; already-collected data stays;
- if the process dies mid-scan, units left `running` are reset to `pending` at
  startup and the scan can be resumed the next day: nothing is lost and
  nothing is redone;
- phases generate the units of the next phase as they produce results
  (discovery → port scan → fingerprint → …), so a resume replays only the
  pending tail.

Work units are sized so one unit is seconds-to-a-minute of work (e.g. 4096
host×port probes, one service to fingerprint, one reachability test).

### R3. Triage belongs to the operator, not to a scan

A scan reports what is exposed and which checks fired. Working out whether
each service, and each finding, is actually a problem is manual, one at a
time, and on a week-long engagement that pass has to survive everything else.
So each service, each finding, each host and each asset carries a
`model.Triage` (status plus a free-text note) which:

- is written only through the triage endpoints, never by `UpsertService` or
  `UpsertFinding`, so re-running a scan refreshes the observation and leaves
  the manual work on top of it intact (there is a test for exactly that);
- is exported next to the identity of the row in the CSVs and the Excel
  workbook, because those sheets are what end up in the client's tracker;
- drives the progress readout and the status filter on the services and the
  findings screens.

They are deliberately identical, down to the endpoint shapes and the controls:
moving from one screen to the other should not mean learning anything new.

### R3b. Skipping a machine is a filter, not a cascade

There is always a machine that is out of scope: a client workstation, the
pentester's own laptop, a device nobody may touch. It is parked by skipping its
host, or its asset, and an asset applies the status to every host attached to
it, including the ones the correlator attaches later (so an address change does
not bring it back).

What hangs off a skipped host is **hidden, never written to**. The service,
finding and reachability listings exclude those rows in SQL (`NOT EXISTS`
against `hosts`), and the counts that have to agree with them (the mission
summary, the triage summary, the matrix cells) are filtered the same way. The
operator may already have triaged some of those services by hand, and that work
has to be exactly where they left it when the host goes back in scope. Rows
with no host are never hidden, `include_skipped=true` turns the filter off, and
exports never apply it: a deliverable carries everything that was found.

### R4. No tooling installed on the operator's workstation
All builds, tests and integration labs run in **Docker** (`Dockerfile`,
`docker-compose.yml`, `make` targets). The repo never requires installing Go,
Node, nmap or anything else on the host.

## Package ownership

| Package | Content | Constructor |
|---|---|---|
| `internal/model` | shared domain types (frozen contract) | - |
| `internal/engine` | engine interfaces (frozen contract) | - |
| `internal/ports` | port spec parsing, top-N lists, port→name | `ports.Parse(spec, proto)` |
| `internal/rawnet` | AF_PACKET / raw socket helpers, rate limiting, cookies, permutation | free-form |
| `internal/discovery` | ARP/ICMP/TCP/UDP host discovery | `discovery.New(log) engine.Discoverer` |
| `internal/portscan` | stateless SYN scan + connect scan + UDP | `portscan.New(log) engine.PortScanner` |
| `internal/fingerprint` | service/version detection, TLS/HTTP/SSH | `fingerprint.New(log) engine.Fingerprinter` |
| `internal/oui` | MAC vendor lookup | `oui.Lookup(mac) string` |
| `internal/identity` | identity evidence collectors + asset correlator | `identity.NewCollector(log)`, `identity.NewCorrelator()` |
| `internal/checks` | light misconfiguration checks | `checks.New(log) engine.Checker` |
| `internal/netif` | interfaces, routes, VLAN sub-interfaces, L2 sniffing | `netif.New(log) engine.NetInspector` |
| `internal/segment` | inter-VLAN reachability & bypass techniques | `segment.New(log, ps, ni) engine.SegmentTester` |
| `internal/export` | export formats | `export.New() engine.Exporter` |
| `internal/store` | SQLite persistence (modernc, pure Go) | `store.Open(path) (*store.Store, error)` |
| `internal/bus` | in-process event bus → WebSocket | `bus.New()` |
| `internal/jobs` | scan runner: work units, phases, pause/resume | `jobs.New(...)` |
| `internal/auth` | users, sessions, password hashing, RBAC | - |
| `internal/api` | REST + WebSocket handlers | - |
| `internal/server` | HTTP server, TLS, embedded SPA | - |
| `internal/config` | configuration & flags | - |
| `cmd/nety` | entrypoint & wiring | - |
| `web/` | React + TS + Vite + Tailwind SPA → `internal/server/dist` | - |

## Rules for all code

- `CGO_ENABLED=0`; production target `GOOS=linux` (amd64 + arm64). Code must
  also compile on darwin: Linux-only files use `//go:build linux` with a
  `_other.go` stub returning `engine.ErrUnsupported`. Connect-mode scanning
  works everywhere.
- Structured logging with `log/slog`; no `fmt.Println` in library code.
- Contexts everywhere; cancellation stops work quickly and cleans up (sockets
  closed, routes and sub-interfaces removed, always, including on panic).
- Results stream through callbacks; callbacks are called concurrently and must
  be safe to call from several goroutines.
- Bounded memory: a /16 × 1000 ports scan must not allocate the whole space
  (use the permutation iterator, not a materialised list).
- Unit tests for pure logic (`go test ./...`), run in Docker.
- `model` and `engine` are frozen contracts: coordinate before changing them.
- Nothing is installed on the host: use the `make` targets, which run Docker.
