# Running NETY on an engagement

This is the field manual: how to deploy it, what privileges it needs, how to
share it with a colleague, and what to do when something does not work.

## Deploying

NETY is one static binary with no runtime dependency. Put it on the laptop you
plug into the client's network.

```bash
make build                       # dist/nety-linux-amd64, dist/nety-linux-arm64
scp dist/nety-linux-amd64 pentest-laptop:/usr/local/bin/nety
```

On the laptop:

```bash
sudo mkdir -p /var/lib/nety && sudo chown "$USER" /var/lib/nety
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/local/bin/nety
nety serve --data /var/lib/nety --listen :8443
```

First start prints an administrator password once. Change it at first login.

### Privileges

| Capability | Needed for | Without it |
|---|---|---|
| `CAP_NET_RAW` | SYN scanning, ARP discovery, ICMP, L2 sniffing | falls back to connect scanning, no ARP, no passive L2 recon |
| `CAP_NET_ADMIN` | routes, 802.1Q sub-interfaces, DTP, forced socket buffers | the route and layer-2 bypass techniques are unavailable |
| `CAP_NET_BIND_SERVICE` | source ports below 1024 | the source-port techniques fall back to the port scanner and lose the closed-vs-filtered distinction |

`GET /api/status` reports which engines are live, and the interface says so too.
Running as root works but the capabilities are enough and preferable.

Unprivileged ICMP additionally needs:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

### Kernel RSTs during a SYN scan

The stateless SYN scanner sends packets the kernel knows nothing about, so the
kernel answers the SYN-ACKs with a RST. This is harmless - the scanner reads
the replies off AF_PACKET before the kernel acts - but it is noisy on the wire.
To suppress it, drop outgoing RSTs from the scan source port:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# remember to remove it afterwards
```

### Systemd

```ini
[Unit]
Description=NETY
After=network.target

[Service]
ExecStart=/usr/local/bin/nety serve --data /var/lib/nety --listen :8443
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/nety
PrivateTmp=yes
Restart=on-failure
User=nety

[Install]
WantedBy=multi-user.target
```

A restart is safe: scans that were running come back as **paused** and
resumable, with everything collected so far intact.

## Wi-Fi or cable

Both work, and NETY picks the right behaviour on its own.

Over Wi-Fi the kernel presents the association as an ordinary Ethernet link,
so **host discovery, ARP, SYN and connect port scanning, UDP probing, service
fingerprinting, identity collection, the checks and the routed segmentation
techniques all behave exactly as they do on a cable** - same engines, same
rates, same results.

Three things only exist on a wired switch port, and NETY detects a wireless
interface and skips them with an explicit message instead of failing against
the driver:

| Feature | On a cable | Over Wi-Fi |
|---|---|---|
| Passive CDP / LLDP / DTP / STP recon | yes | skipped - an access point does not relay these |
| 802.1Q sub-interface and double tagging | yes | skipped - an AP does not carry tagged frames to a station |
| DTP trunk negotiation | yes | skipped - there is no switch port to negotiate with |

The interface picker marks wireless NICs with *(Wi-Fi)* and explains this
inline, the scan log records the decision, and the segmentation matrix is
unaffected for every technique that does apply.

Practical notes:

- Wi-Fi is slower and loses packets more readily. Lower the rate (the *Low and
  slow* profile is a good starting point) and add a retry; a SYN scan at
  20 000 pps over the air will under-report.
- Client isolation on the AP will make every other station look filtered. That
  is a real segmentation finding, not a NETY limitation - but say so in the
  report rather than presenting it as VLAN separation.
- To test VLAN tagging you need a cable. If the client's assessment covers
  trunking, ask for a wired port.

## Sharing it with a colleague

NETY serves HTTPS on every interface, so a colleague on the same VLAN just
opens your address. The startup log lists the URLs.

```
level=INFO msg="NETY is listening" url=https://localhost:8443/
level=INFO msg="reachable from the local network" url=https://10.10.10.42:8443/
```

The certificate is self-signed and generated into the data directory on first
start; its SHA-256 is logged so you can tell your colleague which fingerprint
to expect in the browser warning. Give them their own account:

```bash
nety user add alice -role operator
nety user add client-observer -role viewer
```

Then add them to the mission in **Mission → Members**. A `viewer` can read
everything on their missions but cannot launch or change anything.

To use a real certificate instead:

```bash
nety serve --tls-cert /path/cert.pem --tls-key /path/key.pem
```

## Sharper version detection

If `nmap` is installed, point NETY at its probe database. The file is read at
runtime and never bundled (licensing):

```bash
nety serve --nmap-probes /usr/share/nmap/nmap-service-probes
```

Without it, detection still works through TLS/HTTP/SSH inspection, the
fingerprintx plugins and banner heuristics - just less precisely on exotic
services.

## Tuning a scan

| Situation | What to do |
|---|---|
| Fragile network, IPS in the way | *Low and slow* profile: connect scan, 300 pps, extra retries |
| Large scope, time-boxed | *Standard*, raise the rate; pause it when you need the link |
| Overnight full sweep | *Full* (all 65535 TCP). Start it, go home, resume it if it is interrupted |
| Only want the inventory | Turn off checks and identity collection |
| Scanning through a firewall | Keep host discovery **off**: the firewall will swallow the ping and NETY would skip live hosts |

The rate ceiling is a server setting (`--max-rate`, default 200000) so nobody
can accidentally flood a client network from the web interface.

## Segmentation testing

1. Map each VLAN with a discovery scan first - segmentation has nothing to
   replay otherwise.
2. Plug into the VLAN you want to test *from*, select it, and start a
   **segmentation** scan.
3. The layer-2 techniques (802.1Q sub-interfaces, DTP trunk negotiation,
   double tagging) are **off by default**. They change switch-port state and
   can disturb a switch, so enable them deliberately, ideally with the client
   on the phone.

Everything NETY changes on your machine is reverted when the test ends,
including on cancellation and on shutdown. If the process is killed with
`SIGKILL` it cannot clean up; check with `ip link` and `ip route` and remove
any leftover `*.<vlan>` interface by hand.

## Troubleshooting

**"raw sockets are not available"** - the capabilities are missing. See above.
Scanning still works, in connect mode.

**A scan is stuck in `running` after a crash** - it is not: restart NETY and
`Recover` moves it to `paused`, then press Resume. Work units that were in
flight are returned to the queue.

**A scan failed with "no target to scan"** - the network has no known prefix
and automatic targets was on with no explicit target. Set the prefixes on the
network, or give targets.

**The browser says the connection is not private** - expected with the
self-signed certificate. Compare the fingerprint with the one in the log.

**Events stop updating in the interface** - the WebSocket dropped. The page
reconnects on its own; if it reports dropped events it refetches the tables.
Nothing is lost either way: the database is the source of truth, the stream is
only a notification channel.

**The database is getting large** - it is a single SQLite file in the data
directory. Archive the mission, or copy the file; it is self-contained and safe
to move once the process is stopped.

## Data handling

The database holds a complete map of a client's internal network. Treat it as
client-confidential:

- the data directory is created `0700`, the TLS key `0600`;
- every action is written to an audit log (who, what, which mission, from
  where) - readable by administrators under **Admin → Audit**;
- delete the mission, or the whole data directory, at the end of the
  engagement, per your retention policy.
