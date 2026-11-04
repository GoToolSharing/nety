package udpprobe

import "strconv"

// rpcXID is the fixed, synthetic ONC-RPC transaction id, echoed verbatim in
// the reply.
const rpcXID uint32 = 0x4e455459 // "NETY"

const (
	rpcProgPortmap = 100000
	rpcProcDump    = 4
	maxRPCEntries  = 256
)

// rpcDumpPayload is a portmapper (PMAPPROC_DUMP, program 100000 version 2,
// procedure 4) call with AUTH_NULL credentials. It takes no arguments and
// returns the whole registration table, which is far more useful than GETPORT
// and just as cheap.
func rpcDumpPayload() []byte {
	b := make([]byte, 0, 40)
	put32 := func(v uint32) {
		b = append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	put32(rpcXID)
	put32(0)              // message type: CALL
	put32(2)              // RPC version
	put32(rpcProgPortmap) // program: portmapper
	put32(2)              // program version
	put32(rpcProcDump)    // procedure: DUMP
	put32(0)              // credentials: AUTH_NULL
	put32(0)              // credential body length
	put32(0)              // verifier: AUTH_NULL
	put32(0)              // verifier body length
	return b
}

var rpcPrograms = map[uint32]string{
	100000: "portmapper", 100001: "rstatd", 100002: "rusersd", 100003: "nfs",
	100004: "ypserv", 100005: "mountd", 100007: "ypbind", 100008: "walld",
	100009: "yppasswdd", 100011: "rquotad", 100012: "sprayd", 100020: "llockmgr",
	100021: "nlockmgr", 100024: "status", 100026: "bootparam", 100028: "ypupdated",
	100068: "cmsd", 100069: "ypxfrd", 100083: "ttdbserverd", 100087: "admind",
	100099: "autofsd", 100133: "nsm_addrand", 100227: "nfs_acl", 100229: "metad",
	100230: "metamhd", 100242: "rpc.mdcommd", 100249: "snmpXdmid",
	150001: "pcnfsd", 300019: "amd", 391002: "sgi_fam", 391004: "sgi_mediad",
	805306368: "dmispd", 1073741824: "fypxfrd",
}

// decodeRPC reads a portmapper DUMP reply.
func decodeRPC(resp []byte) *Result {
	xid, ok := u32(resp, 0)
	if !ok || xid != rpcXID {
		return nil
	}
	msgType, ok := u32(resp, 4)
	if !ok || msgType != 1 { // REPLY
		return nil
	}
	replyStat, ok := u32(resp, 8)
	if !ok {
		return nil
	}

	r := newResult("rpcbind", 90)
	r.Product = "RPC portmapper"

	if replyStat != 0 { // MSG_DENIED
		r.set("rpc.reply", "denied")
		if why, okWhy := u32(resp, 12); okWhy {
			r.set("rpc.reject", strconv.FormatUint(uint64(why), 10))
		}
		r.ExtraInfo = "portmapper present, call denied"
		return r
	}

	// MSG_ACCEPTED: verifier (flavor + length + body), then accept state.
	off := 12
	flavorLen, ok := u32(resp, off+4)
	if !ok {
		return nil
	}
	if flavorLen > 400 { // RFC 5531 caps opaque auth bodies at 400 bytes
		return nil
	}
	off += 8 + int(flavorLen)
	// Pad to a 4-byte boundary.
	if pad := int(flavorLen) % 4; pad != 0 {
		off += 4 - pad
	}
	acceptStat, ok := u32(resp, off)
	if !ok {
		return nil
	}
	off += 4
	if acceptStat != 0 { // SUCCESS == 0
		r.set("rpc.accept_status", strconv.FormatUint(uint64(acceptStat), 10))
		r.ExtraInfo = "portmapper present, DUMP not accepted"
		return r
	}

	var entries []string
	seen := make(map[string]bool, 32)
	count := 0
	for count < maxRPCEntries {
		more, okMore := u32(resp, off)
		if !okMore || more == 0 {
			break
		}
		prog, ok1 := u32(resp, off+4)
		vers, ok2 := u32(resp, off+8)
		proto, ok3 := u32(resp, off+12)
		port, ok4 := u32(resp, off+16)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			break
		}
		off += 20
		count++
		if port > 65535 || vers > 1024 {
			continue
		}
		protoName := "unknown"
		switch proto {
		case 6:
			protoName = "tcp"
		case 17:
			protoName = "udp"
		}
		name := rpcPrograms[prog]
		if name == "" {
			name = strconv.FormatUint(uint64(prog), 10)
		}
		key := name + ":" + strconv.FormatUint(uint64(port), 10) + "/" + protoName
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, key)
	}

	r.set("rpc.entry_count", itoa(count))
	if len(entries) > 0 {
		r.set("rpc.programs", joinCapped(entries))
		r.ExtraInfo = joinCapped(entries)
	}
	for _, e := range entries {
		if len(e) >= 4 && e[:4] == "nfs:" {
			r.set("rpc.nfs", "true")
			break
		}
	}
	return r
}
