import { useMemo } from 'react'
import { useTechniques } from '@/lib/queries'
import { BYPASS_TECHNIQUES, type TechniqueInfo } from '@/types/api'

/**
 * The auditor-facing notes about each segmentation technique: why it gets
 * through where plain routing does not, what a hit means for the client, and
 * how to reproduce it by hand.
 *
 * The server owns the title, the description and the flags (GET
 * /api/techniques); this file only adds what the UI has to explain. Both the
 * Help page and the segmentation matrix read it, so there is a single source
 * of truth for the wording.
 */
export interface TechniqueNotes {
  /** One line, used where there is no room for the full description. */
  short: string
  /** Why the packet gets through when a plain connection does not. */
  why: string
  /** What a positive result means for the client. */
  positive: string
  /** The equivalent manual steps, one entry per command or action. */
  manual: string[]
  /** Fallback title, used only when /api/techniques is unreachable. */
  title: string
}

const SRC_PORT = (port: number, service: string, why: string, positive: string): TechniqueNotes => ({
  title: `Source port ${port} (${service})`,
  short: `The same connection, sent from source port ${port}.`,
  why,
  positive,
  manual: [
    `sudo nmap -Pn -sS --source-port ${port} -p <port> <target>`,
    `sudo hping3 -S -s ${port} -k -p <port> <target>`,
  ],
})

export const TECHNIQUE_NOTES: Record<string, TechniqueNotes> = {
  direct: {
    title: 'Direct connection',
    short: 'A plain connection with the machine as it stands.',
    why:
      'Nothing is bypassed here: this is the reference measurement every other technique is compared against. It separates three outcomes that are often confused: a refused connection (the packet was routed, the port is shut), a silent drop (a filter ate it) and an ICMP unreachable (no route, or administratively prohibited).',
    positive:
      'The two networks are not separated at all for this service. Whatever the policy says, the flow is permitted.',
    manual: ['nc -vz -w 3 <target> <port>', 'nmap -Pn -sT -p <port> <target>'],
  },
  icmp: {
    title: 'ICMP echo',
    short: 'A ping to the host rather than to one of its services.',
    why:
      'ACLs are routinely written for TCP and UDP and leave ICMP permitted for troubleshooting. The host answers even when every one of its services is filtered.',
    positive:
      'The boundary forwards traffic between the two networks; only the service ports are filtered. Host enumeration across the boundary is possible, and the filter is a port list rather than real isolation.',
    manual: ['ping -c 3 <target>', 'nmap -sn -PE <target>'],
  },
  'src-port-53': SRC_PORT(
    53,
    'DNS',
    'A stateless ACL written to let DNS replies back in matches on the source port instead of on connection state. Any packet leaving from port 53 then matches the permit rule, whatever its destination port.',
    'The filtering rule set is stateless, or has a DNS exception wide enough to carry any traffic. An attacker only has to bind a low port to walk straight through it.',
  ),
  'src-port-88': SRC_PORT(
    88,
    'Kerberos',
    'Domain controllers attract blanket permit rules so that authentication never breaks. Those rules are often written on the source port, so anything sent from port 88 inherits them.',
    'The exception carved out for domain authentication is broader than authentication. Any traffic towards the permitted range crosses the boundary.',
  ),
  'src-port-123': SRC_PORT(
    123,
    'NTP',
    'NTP is one of the most commonly permitted services on a boundary, in both directions, and the rule is usually matched on the source port.',
    'The time-synchronisation exception is a general-purpose hole. It is also one of the easiest to tighten, since NTP only needs to reach the time servers.',
  ),
  'src-port-20': SRC_PORT(
    20,
    'FTP-data',
    'Legacy rule sets permit source port 20 so that active-mode FTP transfers work. The rule long outlives the FTP server it was written for.',
    'A rule kept for a protocol nobody uses any more still opens the boundary. This usually points at an ACL that has never been reviewed.',
  ),
  'src-port-67': SRC_PORT(
    67,
    'DHCP',
    'Permitting source port 67 lets a DHCP relay answer clients on the other side of the boundary; a stateless rule cannot tell a relay apart from anything else using that port.',
    'The DHCP relay exception is not restricted to the relay itself. Any host on the segment can use it.',
  ),
  'src-port-500': SRC_PORT(
    500,
    'IKE',
    'Source port 500 is opened so that VPN endpoints can negotiate tunnels, and the rule is rarely bound to the endpoint addresses.',
    'The VPN exception applies to the whole segment rather than to the VPN concentrator, so it can be reused by anything on the network.',
  ),
  ipv6: {
    title: 'IPv6',
    short: 'The same service, reached over the target host IPv6 address.',
    why:
      'Filtering is written for IPv4 and the IPv6 stack is forgotten, while modern operating systems enable IPv6 by default and autoconfigure a link-local, and often a global, address. The v6 path is then completely unfiltered.',
    positive:
      'The segmentation policy only exists on IPv4. Everything the ACL blocks is reachable over IPv6, which is the single most common way a correctly written policy is defeated.',
    manual: [
      'ping6 -c 3 ff02::1%<iface>   # enumerate the IPv6 neighbours on the segment',
      'nmap -6 -Pn -p <port> <target-v6>',
      'nc -6 -vz -w 3 <target-v6> <port>',
    ],
  },
  'gateway-route': {
    title: 'Route via the local gateway',
    short: 'A route to the target network is installed through the local default gateway.',
    why:
      'A client with no route to the other network cannot reach it, which looks exactly like filtering. Adding the route shows whether the router would in fact forward the traffic. Very often it would, and the only thing separating the networks was the absence of a route on the client.',
    positive:
      'The two networks are not separated by any filtering at all. The router forwards between them; the isolation was an accident of the routing table. Anyone who can set a static route, or receives a different DHCP option, crosses the boundary.',
    manual: [
      'sudo ip route add <target-net>/<len> via <local-gateway> dev <iface>',
      'nc -vz -w 3 <target> <port>',
      'sudo ip route del <target-net>/<len> via <local-gateway> dev <iface>',
    ],
  },
  'alt-gateway': {
    title: 'Route via another next hop',
    short: 'The route test repeated through every other router seen on the segment.',
    why:
      'The default gateway is usually the one with an ACL on it. Other routers, firewalls managed by another team, or a multi-homed server with forwarding enabled, sit on the same segment and forward without the same rules.',
    positive:
      'A second path exists around the filtering. The policy is enforced on one device while another one forwards the same traffic, so the boundary is only as strong as the next hop the client happens to pick.',
    manual: [
      'ip neigh show; sudo nmap -sn <local-net>/<len>   # find the other candidate next hops',
      'sudo ip route add <target-net>/<len> via <other-next-hop> dev <iface>',
      'nc -vz -w 3 <target> <port>',
      'sudo ip route del <target-net>/<len> via <other-next-hop> dev <iface>',
    ],
  },
  'ip-fragment': {
    title: 'Fragmented SYN',
    short: 'A TCP SYN split across several IP fragments.',
    why:
      'The TCP header lands in the second fragment, so a filter that only inspects the first one never sees the destination port it is supposed to match on. Devices that do not reassemble before filtering let the fragments through, and the target reassembles them into a valid SYN.',
    positive:
      'The filtering device does not reassemble fragments before applying its rules. Every port-based rule on it can be evaded, so the rule set gives much less protection than it appears to.',
    manual: [
      'sudo nmap -Pn -sS -f -f -p <port> <target>',
      'sudo hping3 -S -f -p <port> <target>',
    ],
  },
  'dot1q-subif': {
    title: '802.1Q sub-interface',
    short: 'A tagged sub-interface is created for the target VLAN and tested from inside it.',
    why:
      'The test stops going through the boundary at all: if the switch port carries tagged traffic (it is a trunk, or an access port with a voice VLAN), the machine can simply join the target VLAN and become a local host there. No router, no ACL.',
    positive:
      'The switch port hands out more than one VLAN. Anything plugged into that socket, including a visitor in a meeting room, can place itself inside the VLAN and talk to it as a local member. The boundary is irrelevant because the traffic never crosses it.',
    manual: [
      'sudo ip link add link <iface> name <iface>.<vlan> type vlan id <vlan>',
      'sudo ip link set <iface>.<vlan> up',
      'sudo dhclient <iface>.<vlan>   # or set a static address in the VLAN prefix',
      'nc -vz -w 3 <target> <port>',
      'sudo ip link del <iface>.<vlan>',
    ],
  },
  'dtp-trunk': {
    title: 'DTP trunk negotiation',
    short: 'The switch port is asked to become a trunk, then tested through a sub-interface.',
    why:
      'Cisco switch ports left in the default dynamic mode will negotiate a trunk with whatever asks. Once the port is a trunk it carries every VLAN it is allowed to, and the machine can tag its way into any of them.',
    positive:
      'The switch port was left negotiating. An attacker turns a single access socket into a trunk and reaches every VLAN that trunk carries at once. This is a finding on its own, independent of any ACL.',
    manual: [
      'sudo yersinia -I   # or: sudo yersinia dtp -attack 1 -interface <iface>',
      'sudo ip link add link <iface> name <iface>.<vlan> type vlan id <vlan>',
      'sudo ip link set <iface>.<vlan> up; sudo dhclient <iface>.<vlan>',
      'switchport mode access + switchport nonegotiate is the fix to recommend',
    ],
  },
  'double-tag': {
    title: '802.1Q double tagging',
    short: 'A frame carrying two VLAN tags, injected straight into the target VLAN.',
    why:
      'A trunk strips only the outer tag. A frame tagged first with the native VLAN and then with the target VLAN comes out of the switch as a frame tagged for the target VLAN, and is delivered inside it. Nothing is routed, so no ACL is consulted.',
    positive:
      'Frames can be injected into the target VLAN without any routing. Delivery is one way, so this proves injection rather than a two-way session: enough to spoof, flood or trigger something in the target VLAN. The fix is to make the native VLAN an unused one and to prune the trunk.',
    manual: [
      'sudo python3 -c "from scapy.all import *; sendp(Ether(dst=\'ff:ff:ff:ff:ff:ff\')/Dot1Q(vlan=<native>)/Dot1Q(vlan=<target>)/IP(dst=\'<target-ip>\')/ICMP(), iface=\'<iface>\')"',
      'capture inside the target VLAN to confirm delivery: no answer ever comes back on this path',
    ],
  },
}

export interface TechniqueGuide extends TechniqueInfo {
  notes: TechniqueNotes | null
  /** True when a hit through this technique is a segmentation bypass. */
  bypass: boolean
}

/** Server-written prose uses typographic dashes; the UI uses plain hyphens. */
function plainDashes(s: string): string {
  return s.replace(/[\u2013\u2014]/g, '-')
}

function guideFor(info: TechniqueInfo): TechniqueGuide {
  const notes = TECHNIQUE_NOTES[info.id] ?? null
  return {
    ...info,
    title: plainDashes(info.title || notes?.title || info.id),
    description: plainDashes(info.description || notes?.short || ''),
    notes,
    bypass: BYPASS_TECHNIQUES.has(info.id),
  }
}

/** A guide for a technique the server did not list (an older or newer build). */
function fallback(id: string): TechniqueGuide {
  const notes = TECHNIQUE_NOTES[id] ?? null
  return {
    id,
    title: notes?.title ?? id,
    description: notes?.short ?? '',
    l2_active: id === 'dot1q-subif' || id === 'dtp-trunk' || id === 'double-tag',
    one_way: id === 'double-tag',
    default: false,
    notes,
    bypass: BYPASS_TECHNIQUES.has(id),
  }
}

/**
 * Every technique the server knows about, merged with the notes above, plus a
 * lookup that never returns undefined for a known technique id.
 */
export function useTechniqueGuides(): {
  list: TechniqueGuide[]
  byId: (id: string) => TechniqueGuide
  isLoading: boolean
} {
  const query = useTechniques()
  return useMemo(() => {
    const list = (query.data ?? []).map(guideFor)
    const index = new Map(list.map((t) => [t.id, t]))
    return {
      list,
      byId: (id: string) => index.get(id) ?? fallback(id),
      isLoading: query.isLoading,
    }
  }, [query.data, query.isLoading])
}

/** The anchor of a technique's entry on the Help page. */
export function techniqueAnchor(id: string): string {
  return `technique-${id}`
}

export function techniqueHelpHref(id: string): string {
  return `/help#${techniqueAnchor(id)}`
}
