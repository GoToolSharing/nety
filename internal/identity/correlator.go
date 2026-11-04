package identity

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

// MatchThreshold is the minimum score for an observation to be attached to
// an existing asset.
const MatchThreshold = 70

// Key weights (0..100): how much a single matching key proves identity.
const (
	wSMBGUID      = 95
	wSNMPEngineID = 95
	wSSHHostKey   = 90
	wMACNBStat    = 85
	wMACSameL2    = 80
	wMACRandom    = 30
	wFQDN         = 70
	wNetBIOSPair  = 70
	wTLSUnique    = 60
	wTLSShared    = 10
	wHostname     = 40
	wRDNS         = 30
	wFavicon      = 5
	wSameIP       = 20

	// contradictionPenalty is subtracted per strong key kind present on both
	// sides with disjoint values.
	contradictionPenalty = 50
)

type correlator struct{}

// NewCorrelator returns the asset correlator (pure, no I/O).
func NewCorrelator() engine.Correlator { return correlator{} }

// obsKey is a normalized key extracted from an observation.
type obsKey struct {
	kind   model.EvidenceKind
	value  string
	source string
	conf   int
	random bool // locally administered MAC
	shared bool // shared TLS certificate
	nbstat bool // MAC learned from NBSTAT
}

// normalize canonicalizes a key value for comparison. It returns "" for
// values that must be ignored.
func normalize(kind model.EvidenceKind, v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	switch kind {
	case model.EvHostname, model.EvFQDN, model.EvDomain, model.EvNetBIOSName, model.EvNetBIOSDomain,
		model.EvReverseDNS, model.EvMDNSName, model.EvSNMPSysName:
		return strings.ToLower(strings.TrimRight(v, "."))
	case model.EvMAC:
		return canonicalMAC(v)
	case model.EvSMBGUID:
		return strings.ToLower(strings.Trim(v, "{}"))
	case model.EvSNMPEngineID, model.EvTLSCert:
		v = strings.ToLower(v)
		v = strings.TrimPrefix(v, "0x")
		return strings.NewReplacer(":", "", " ", "", "-", "").Replace(v)
	default:
		return v
	}
}

// canonicalMAC returns "aa:bb:cc:dd:ee:ff" for any common MAC notation, or
// "" when the input is not a valid unicast, non-zero 48-bit MAC.
func canonicalMAC(s string) string {
	var hex []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			hex = append(hex, c)
		case c >= 'A' && c <= 'F':
			hex = append(hex, c+('a'-'A'))
		case c == ':' || c == '-' || c == '.' || c == ' ':
		default:
			return ""
		}
	}
	if len(hex) != 12 {
		return ""
	}
	if string(hex) == "000000000000" || string(hex) == "ffffffffffff" {
		return ""
	}
	first := hexVal(hex[0])<<4 | hexVal(hex[1])
	if first&0x01 != 0 { // multicast / broadcast
		return ""
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.Write(hex[i : i+2])
	}
	return b.String()
}

func hexVal(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

func macIsRandom(m string) bool {
	if len(m) < 2 {
		return false
	}
	return (hexVal(m[0])<<4|hexVal(m[1]))&0x02 != 0
}

// observationKeys extracts the usable normalized keys of an observation.
func observationKeys(obs model.HostObservation) []obsKey {
	var keys []obsKey
	seen := map[string]int{}
	add := func(k obsKey) {
		id := string(k.kind) + "\x00" + k.value
		if i, ok := seen[id]; ok {
			if k.conf > keys[i].conf {
				keys[i].conf = k.conf
				keys[i].source = k.source
			}
			keys[i].nbstat = keys[i].nbstat || k.nbstat
			keys[i].shared = keys[i].shared && k.shared
			return
		}
		seen[id] = len(keys)
		keys = append(keys, k)
	}
	for _, e := range obs.Evidence {
		if e.Confidence <= 0 {
			continue
		}
		v := normalize(e.Kind, e.Value)
		if v == "" {
			continue
		}
		k := obsKey{kind: e.Kind, value: v, source: e.Source, conf: e.Confidence}
		switch e.Kind {
		case model.EvMAC:
			k.nbstat = e.Attributes["source"] == "nbstat" || strings.HasPrefix(e.Source, "nbstat")
			if !obs.SameL2 && !k.nbstat {
				continue // MAC of the last router hop, not the host's
			}
			k.random = macIsRandom(v)
		case model.EvTLSCert:
			k.shared = e.Attributes["shared"] == "true"
		}
		add(k)
	}
	if obs.SameL2 {
		if m := canonicalMAC(obs.Host.MAC); m != "" {
			add(obsKey{kind: model.EvMAC, value: m, source: "host", conf: 90, random: macIsRandom(m)})
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].value < keys[j].value
	})
	return keys
}

// scale applies the evidence confidence to a key weight. Confidence >= 80
// counts as full weight.
func scale(weight, conf int) float64 {
	if conf >= 80 || conf <= 0 {
		return float64(weight)
	}
	return float64(weight) * float64(conf) / 80
}

// assetIndex is a lookup view of an existing asset.
type assetIndex struct {
	keys  map[model.EvidenceKind]map[string]bool
	names map[string]bool // short hostnames (lowercase)
}

func indexAsset(a model.Asset) assetIndex {
	idx := assetIndex{keys: map[model.EvidenceKind]map[string]bool{}, names: map[string]bool{}}
	for _, k := range a.Keys {
		v := normalize(k.Kind, k.Value)
		if v == "" {
			continue
		}
		if idx.keys[k.Kind] == nil {
			idx.keys[k.Kind] = map[string]bool{}
		}
		idx.keys[k.Kind][v] = true
		if n := shortNameKey(k.Kind, v); n != "" {
			idx.names[n] = true
		}
	}
	if a.Hostname != "" && !isIPLiteral(a.Hostname) {
		idx.names[strings.ToLower(shortName(a.Hostname))] = true
	}
	return idx
}

// shortNameKey returns the short host name implied by a name-ish key.
func shortNameKey(kind model.EvidenceKind, v string) string {
	switch kind {
	case model.EvHostname, model.EvNetBIOSName, model.EvFQDN, model.EvMDNSName, model.EvSNMPSysName:
		if isIPLiteral(v) {
			return ""
		}
		return strings.ToLower(shortName(v))
	}
	return ""
}

type candidate struct {
	idx            int
	id             int64
	score          int
	raw            int
	reasons        []string
	contradictions int
}

// strong unique key kinds; disjoint values on both sides are contradictions.
var strongKinds = []model.EvidenceKind{model.EvSMBGUID, model.EvSNMPEngineID, model.EvSSHHostKey, model.EvMAC}

func scoreAsset(a model.Asset, obs model.HostObservation, keys []obsKey) candidate {
	idx := indexAsset(a)
	c := candidate{id: a.ID}
	var weights []float64

	byKind := map[model.EvidenceKind][]obsKey{}
	for _, k := range keys {
		byKind[k.kind] = append(byKind[k.kind], k)
	}

	// Exact matches of discriminating keys.
	type exact struct {
		kind  model.EvidenceKind
		label string
	}
	strongMatched := false
	for _, ex := range []exact{
		{model.EvSMBGUID, "smb-server-guid"},
		{model.EvSNMPEngineID, "snmp-engineid"},
		{model.EvSSHHostKey, "ssh-hostkey"},
		{model.EvMAC, "mac"},
		{model.EvTLSCert, "tls-cert"},
		{model.EvHTTPFavicon, "http-favicon"},
	} {
		best, bestVal := 0.0, ""
		for _, k := range byKind[ex.kind] {
			if !idx.keys[ex.kind][k.value] {
				continue
			}
			var w int
			switch ex.kind {
			case model.EvSMBGUID:
				w = wSMBGUID
			case model.EvSNMPEngineID:
				w = wSNMPEngineID
			case model.EvSSHHostKey:
				w = wSSHHostKey
			case model.EvMAC:
				switch {
				case k.random:
					w = wMACRandom
				case k.nbstat:
					w = wMACNBStat
				default:
					w = wMACSameL2
				}
			case model.EvTLSCert:
				w = wTLSUnique
				if k.shared {
					w = wTLSShared
				}
			case model.EvHTTPFavicon:
				w = wFavicon
			}
			if s := scale(w, k.conf); s > best {
				best, bestVal = s, k.value
			}
		}
		if best > 0 {
			weights = append(weights, best)
			c.reasons = append(c.reasons, fmt.Sprintf("%s match (%s)", ex.label, bestVal))
			if ex.kind == model.EvSMBGUID || ex.kind == model.EvSNMPEngineID || ex.kind == model.EvSSHHostKey {
				strongMatched = true
			}
		}
	}

	// Name family: FQDN / NetBIOS pair / short hostname / reverse DNS. These
	// carry the same information, so only the best one counts.
	nameW, nameReason := 0.0, ""
	consider := func(w float64, reason string) {
		if w > nameW {
			nameW, nameReason = w, reason
		}
	}
	for _, k := range byKind[model.EvFQDN] {
		if idx.keys[model.EvFQDN][k.value] {
			consider(scale(wFQDN, k.conf), "fqdn match ("+k.value+")")
		}
	}
	for _, n := range byKind[model.EvNetBIOSName] {
		if !idx.keys[model.EvNetBIOSName][n.value] {
			continue
		}
		for _, d := range byKind[model.EvNetBIOSDomain] {
			if idx.keys[model.EvNetBIOSDomain][d.value] {
				consider(scale(wNetBIOSPair, min(n.conf, d.conf)), "netbios name+domain match ("+n.value+"/"+d.value+")")
			}
		}
	}
	for _, k := range keys {
		n := shortNameKey(k.kind, k.value)
		if n != "" && idx.names[n] {
			consider(scale(wHostname, k.conf), "hostname match ("+n+")")
		}
	}
	for _, k := range byKind[model.EvReverseDNS] {
		if idx.keys[model.EvReverseDNS][k.value] || idx.keys[model.EvFQDN][k.value] {
			consider(scale(wRDNS, k.conf), "rdns match ("+k.value+")")
		}
	}
	if nameW > 0 {
		weights = append(weights, nameW)
		c.reasons = append(c.reasons, nameReason)
	}

	// Contradictions on strong unique keys.
	for _, kind := range strongKinds {
		obsVals := byKind[kind]
		assetVals := idx.keys[kind]
		if len(obsVals) == 0 || len(assetVals) == 0 {
			continue
		}
		overlap := false
		usable := false
		for _, k := range obsVals {
			if kind == model.EvMAC && k.random {
				continue
			}
			usable = true
			if assetVals[k.value] {
				overlap = true
			}
		}
		if !usable || overlap {
			continue
		}
		if kind == model.EvMAC {
			// Multi-homed hosts have several NICs: a different MAC is only
			// a contradiction when no strong key confirms the identity.
			if strongMatched {
				continue
			}
			// All asset MACs random: not reliable either.
			allRandom := true
			for v := range assetVals {
				if !macIsRandom(v) {
					allRandom = false
				}
			}
			if allRandom {
				continue
			}
		}
		c.contradictions++
		c.reasons = append(c.reasons, fmt.Sprintf("conflict: %s differs", kind))
	}

	// Same IP on the same network: weak hint, ignored when contradicted.
	if c.contradictions == 0 && obs.Host.IP != "" {
		for _, ip := range a.IPs {
			if ip.IP == obs.Host.IP && ip.NetworkID == obs.NetworkID {
				weights = append(weights, wSameIP)
				c.reasons = append(c.reasons, "same ip on same network ("+ip.IP+")")
				break
			}
		}
	}

	p := 1.0
	for _, w := range weights {
		p *= 1 - math.Min(w, 100)/100
	}
	c.raw = int(math.Round((1 - p) * 100))
	c.score = c.raw - c.contradictions*contradictionPenalty
	if c.score < 0 {
		c.score = 0
	}
	if c.score > 100 {
		c.score = 100
	}
	return c
}

// Resolve decides which existing asset the observation belongs to and returns
// the merged asset. Pure and deterministic.
func (correlator) Resolve(existing []model.Asset, obs model.HostObservation) model.AssetDecision {
	keys := observationKeys(obs)

	cands := make([]candidate, 0, len(existing))
	for i, a := range existing {
		c := scoreAsset(a, obs, keys)
		c.idx = i
		cands = append(cands, c)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		if cands[i].id != cands[j].id {
			return cands[i].id < cands[j].id
		}
		return cands[i].idx < cands[j].idx
	})

	var dec model.AssetDecision
	chosen := -1
	if len(cands) > 0 && cands[0].score >= MatchThreshold {
		chosen = 0
		best := cands[0]
		dec.Matched = true
		dec.Score = best.score
		dec.Reasons = append([]string(nil), best.reasons...)
		dec.Asset = mergeAsset(cloneAsset(existing[best.idx]), obs, keys)
	} else {
		dec.Asset = mergeAsset(model.Asset{MissionID: obs.MissionID}, obs, keys)
		if len(cands) > 0 && cands[0].raw > 0 {
			dec.Score = cands[0].score
			dec.Reasons = append(dec.Reasons, fmt.Sprintf("new asset: best candidate asset %d scored %d (< %d)", cands[0].id, cands[0].score, MatchThreshold))
			for _, r := range cands[0].reasons {
				dec.Reasons = append(dec.Reasons, fmt.Sprintf("asset %d: %s", cands[0].id, r))
			}
		} else {
			dec.Reasons = append(dec.Reasons, "new asset: no matching key")
		}
	}

	seen := map[int64]bool{}
	for i, c := range cands {
		if i == chosen {
			continue
		}
		if c.score > 0 || (c.contradictions > 0 && c.raw > 0) {
			if c.id != 0 && !seen[c.id] && (chosen < 0 || c.id != cands[chosen].id) {
				seen[c.id] = true
				dec.Conflicts = append(dec.Conflicts, c.id)
			}
		}
	}
	sort.Slice(dec.Conflicts, func(i, j int) bool { return dec.Conflicts[i] < dec.Conflicts[j] })
	return dec
}

func cloneAsset(a model.Asset) model.Asset {
	a.Keys = append([]model.AssetKey(nil), a.Keys...)
	a.IPs = append([]model.AssetIP(nil), a.IPs...)
	a.Tags = append([]string(nil), a.Tags...)
	if len(a.Tags) == 0 {
		a.Tags = nil
	}
	return a
}

func minTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// mergeAsset folds an observation into an asset.
func mergeAsset(a model.Asset, obs model.HostObservation, keys []obsKey) model.Asset {
	seenAt := obs.SeenAt
	if seenAt.IsZero() {
		seenAt = obs.Host.LastSeen
	}
	if a.MissionID == 0 {
		a.MissionID = obs.MissionID
	}

	// Keys.
	pos := map[string]int{}
	for i, k := range a.Keys {
		pos[string(k.Kind)+"\x00"+normalize(k.Kind, k.Value)] = i
	}
	for _, k := range keys {
		id := string(k.kind) + "\x00" + k.value
		if i, ok := pos[id]; ok {
			ak := &a.Keys[i]
			ak.FirstSeen = minTime(ak.FirstSeen, seenAt)
			ak.LastSeen = maxTime(ak.LastSeen, seenAt)
			if k.conf > ak.Confidence {
				ak.Confidence = k.conf
				ak.Source = k.source
			}
			if ak.Source == "" {
				ak.Source = k.source
			}
			continue
		}
		pos[id] = len(a.Keys)
		a.Keys = append(a.Keys, model.AssetKey{
			Kind: k.kind, Value: k.value, Source: k.source, Confidence: k.conf,
			FirstSeen: seenAt, LastSeen: seenAt,
		})
	}
	sort.SliceStable(a.Keys, func(i, j int) bool {
		if a.Keys[i].Kind != a.Keys[j].Kind {
			return a.Keys[i].Kind < a.Keys[j].Kind
		}
		return a.Keys[i].Value < a.Keys[j].Value
	})
	if a.Keys == nil {
		a.Keys = []model.AssetKey{}
	}

	// IPs.
	if obs.Host.IP != "" {
		found := false
		for i := range a.IPs {
			if a.IPs[i].IP == obs.Host.IP && a.IPs[i].NetworkID == obs.NetworkID {
				a.IPs[i].FirstSeen = minTime(a.IPs[i].FirstSeen, seenAt)
				a.IPs[i].LastSeen = maxTime(a.IPs[i].LastSeen, seenAt)
				found = true
				break
			}
		}
		if !found {
			a.IPs = append(a.IPs, model.AssetIP{IP: obs.Host.IP, NetworkID: obs.NetworkID, FirstSeen: seenAt, LastSeen: seenAt})
		}
	}
	sort.SliceStable(a.IPs, func(i, j int) bool {
		if a.IPs[i].NetworkID != a.IPs[j].NetworkID {
			return a.IPs[i].NetworkID < a.IPs[j].NetworkID
		}
		return a.IPs[i].IP < a.IPs[j].IP
	})
	if a.IPs == nil {
		a.IPs = []model.AssetIP{}
	}

	// Descriptive fields: newer observation values win when present.
	d := deriveFields(obs.Services, obs.Evidence)
	switch {
	case d.Hostname != "":
		a.Hostname = d.Hostname
	case a.Hostname == "" && obs.Host.Hostname != "":
		a.Hostname = obs.Host.Hostname
	}
	switch {
	case d.Domain != "":
		a.Domain = d.Domain
	case a.Domain == "" && obs.Host.Domain != "":
		a.Domain = obs.Host.Domain
	}
	switch {
	case d.OS != "":
		a.OS = d.OS
	case a.OS == "" && obs.Host.OS != "":
		a.OS = obs.Host.OS
	}

	// Kind: never downgrade a specific kind to unknown.
	vendor := obs.Host.Vendor
	if vendor == "" {
		vendor = d.Vendor
	}
	if k := InferKind(obs.Services, obs.Evidence, vendor); k != model.AssetUnknown {
		a.Kind = k
	} else if a.Kind == "" {
		a.Kind = model.AssetUnknown
	}

	a.FirstSeen = minTime(a.FirstSeen, seenAt)
	a.LastSeen = maxTime(a.LastSeen, seenAt)
	a.Label = assetLabel(a, d)
	return a
}

// assetLabel picks FQDN > hostname > most recent IP.
func assetLabel(a model.Asset, d derived) string {
	if d.FQDN != "" {
		return d.FQDN
	}
	var best *model.AssetKey
	for i := range a.Keys {
		k := &a.Keys[i]
		if k.Kind != model.EvFQDN || !strings.Contains(k.Value, ".") {
			continue
		}
		if best == nil || k.LastSeen.After(best.LastSeen) || (k.LastSeen.Equal(best.LastSeen) && k.Value < best.Value) {
			best = k
		}
	}
	if best != nil {
		if a.Hostname == "" || strings.EqualFold(shortName(best.Value), a.Hostname) {
			return best.Value
		}
	}
	if a.Hostname != "" {
		return a.Hostname
	}
	if best != nil {
		return best.Value
	}
	var ip *model.AssetIP
	for i := range a.IPs {
		x := &a.IPs[i]
		if ip == nil || x.LastSeen.After(ip.LastSeen) || (x.LastSeen.Equal(ip.LastSeen) && x.IP < ip.IP) {
			ip = x
		}
	}
	if ip != nil {
		return ip.IP
	}
	return a.Label
}
