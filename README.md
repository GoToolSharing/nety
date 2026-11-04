# NETY

**Internal network mapping and VLAN segmentation testing, as a shareable web
platform.**

NETY is the tool you plug into a client's switch port. It maps what is on that
VLAN, fingerprints every service it finds, gives each machine a stable identity
that survives a DHCP reshuffle overnight, and then — once you have mapped
several VLANs — tells you exactly which flows actually cross the segmentation
boundary, plain routing or bypass technique alike.

It is one static Go binary. Everything is implemented natively in-process:
no `nmap`, no `masscan`, no subprocess to parse.

---

## Why it exists

A segmentation review usually goes like this: plug into VLAN A, run a port
scan, wait, copy the output somewhere, plug into VLAN B, repeat, then try to
reconcile the files by hand and work out what can reach what. Three things hurt:

1. **Results arrive at the end.** A long scan that dies at 80 % leaves nothing.
2. **Nothing is resumable.** Come back the next day and you start over.
3. **Machines lose their identity.** DHCP moved everything; yesterday's
   inventory no longer lines up with today's.

NETY is built around fixing exactly those three:

- **Live results.** Every host, port, service, finding and reachability result
  is written to the database and pushed to the browser the instant it is found.
  You watch the tables fill while the scan runs.
- **Pause, resume, survive a crash.** A scan is a queue of persisted work
  units. Pause it, close the laptop, reboot the machine, resume the next
  morning: it continues exactly where it stopped, and nothing is redone.
- **Stable identities.** NETY collects evidence that outlives an IP change
  (SMB server GUID, SNMP engine ID, SSH host keys, NetBIOS adapter MAC,
  certificates, FQDNs…) and correlates observations into long-lived *assets*,
  so the same machine seen on a new address tomorrow is still the same machine.

And it is a **platform, not a CLI**: it serves an authenticated HTTPS web
interface, so a colleague on the same VLAN opens your IP in a browser, logs in
with their own account and watches the same scan live.

---

## What it does

**Per network (VLAN):**
- auto-detects interface, addressing, gateway, DNS and DHCP server
- passively listens for CDP/LLDP/DTP/STP and 802.1Q tags, so you learn what the
  switch port is configured for — a port that offers to negotiate a trunk is a
  finding in itself
- host discovery (ARP, ICMP echo and timestamp, TCP SYN and ACK, UDP payloads)
- stateless SYN port scanning in the style of masscan, or a connect scan when
  raw sockets are not available
- UDP scanning with ~35 real protocol payloads, not empty datagrams
- service and version fingerprinting: TLS (full certificate detail), HTTP
  (title, headers, auth schemes, technologies, favicon hash), SSH (host keys
  and algorithms), the `nmap-service-probes` database when it is installed, and
  a fallback banner/port heuristic
- 44 safe, read-only checks for the usual internal hygiene problems

**Over Wi-Fi as over cable:** everything that rides on IP behaves identically.
NETY detects a wireless interface and skips only what cannot exist on an access
point association — the passive switch-port recon and the 802.1Q/DTP
techniques — saying so plainly instead of failing obscurely.

**Across networks:**
- replays every service discovered elsewhere from where you are now
- distinguishes *reachable* from *port closed* from *filtered* from *no route* —
  which is the whole point of the exercise
- 15 techniques, from plain routing to source-port tricks, IPv6, alternate
  next hops and fragmentation, plus opt-in layer-2 techniques (802.1Q
  sub-interfaces, DTP trunk negotiation, double tagging) that stay **off by
  default** because they can disturb a switch
- fills a source × target matrix, the table the client reads first

**Exports:** JSON, CSV (hosts, services, findings, segmentation, assets,
matrix), Nmap XML, greppable Nmap, a bare `ip:port` list, Markdown, a
self-contained HTML report and an Excel workbook.

---

## Quick start

Nothing is installed on your machine: every target runs in Docker.

```bash
make build          # static linux/amd64 + linux/arm64 binaries in ./dist
make test           # the whole test suite
make image          # runtime container image
```

Run it on the laptop you plug into the client network:

```bash
sudo ./dist/nety-linux-amd64 serve --data /var/lib/nety
```

On first start it creates an administrator account and prints the password
once. The log also lists the URLs your colleagues can reach you on.

Raw sockets are needed for SYN scanning, ARP discovery and the layer-2
techniques. Either run as root, or grant the capabilities to the binary:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ./nety
```

Without them NETY still works — it falls back to connect scanning and says so
in the interface — but it is slower and cannot do layer-2 work.

In a container:

```bash
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v nety-data:/data -p 8443:8443 nety:latest
```

### Version detection

If `nmap` is installed on the machine, point NETY at its probe database for
much sharper version detection (the file is never bundled, for licensing
reasons):

```bash
nety serve --nmap-probes /usr/share/nmap/nmap-service-probes
```

### A typical engagement

1. Plug into the first VLAN. **Networks → New**, pick the interface, hit
   detect, name it (`VLAN 10 — offices`), save.
2. **Scans → New**, profile *Standard*, start. Watch it live.
3. Unplug, move to the next VLAN, repeat.
4. Back on any VLAN, start a **segmentation** scan. NETY replays every service
   it knows about on the other VLANs and fills the matrix.
5. Export the HTML or Excel report.

Long scan? Pause it, resume it tomorrow. Interrupted by a reboot? It comes back
as *paused*, resumable, with everything collected so far intact.

---

## The lab

To try it without a client network, there is a three-"VLAN" Docker lab:

```bash
make lab-up
docker compose -f build/lab/docker-compose.yml logs -f nety   # admin password
open https://localhost:8443/
```

NETY is attached to `lab_vlan10` only, so a segmentation scan should find the
other two unreachable. To watch a crossing appear in the matrix:

```bash
docker network connect lab_vlan20 nety-lab
```

Tear it down with `make lab-down`.

---

## Development

Every `make` target runs inside the toolchain container, so Go and Node stay out
of your machine.

```bash
make toolchain   # build the Go + Node image (once)
make test        # go test ./...
make vet         # go vet + gofmt check
make web         # build the SPA only
make build-go    # rebuild the binary without rebuilding the SPA
make shell       # a shell inside the toolchain
```

Architecture, package ownership and the rules every package follows are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). The HTTP contract is in
[`docs/API.md`](docs/API.md).

---

## Scope and safety

NETY is built for **authorised** internal security assessments.

- Every check is read-only. Nothing writes, nothing exploits, and the only
  credential attempts are a short, curated vendor-default list that is **off**
  unless you turn it on, capped at three tries so nothing gets locked out.
- The layer-2 techniques change switch-port state and are off by default,
  behind an explicit toggle with a warning.
- Everything NETY changes on your machine — routes, sub-interfaces, trunk
  negotiation — is tracked and reverted when a test ends, when it is cancelled,
  and again on shutdown.
- Your own address is always excluded from the scope, along with anything in
  the mission's exclusion list.
- Every action is written to an audit log: who ran what, against which client,
  from where.

Get written authorisation before you point this at anything.

---

## Licence

Internal tooling. Not for distribution outside Vaadata without approval.
