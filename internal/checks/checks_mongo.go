package checks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("mongodb-no-auth", "MongoDB accessible without authentication", model.SevCritical,
			[]string{"mongodb"},
			"The MongoDB server runs commands such as listDatabases without authentication. Anyone on the network can read, modify or delete every database."),
		Remediation: "Enable access control (security.authorization: enabled), create authenticated users with least privilege, bind MongoDB to trusted interfaces (net.bindIp) and firewall port 27017.",
		References:  []string{"https://www.mongodb.com/docs/manual/administration/security-checklist/"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"mongodb", "mongod"}, 27017, 27018, 27019)
		},
		Run: runMongo,
	})
}

// --- minimal BSON ----------------------------------------------------------

type mongoKV struct {
	K string
	V any // int32, float64, string, mongoDoc
}

type mongoDoc []mongoKV

func mongoEncode(d mongoDoc) []byte {
	b := []byte{0, 0, 0, 0}
	for _, kv := range d {
		switch v := kv.V.(type) {
		case int32:
			b = append(b, 0x10)
			b = append(b, kv.K...)
			b = append(b, 0)
			b = binary.LittleEndian.AppendUint32(b, uint32(v))
		case float64:
			b = append(b, 0x01)
			b = append(b, kv.K...)
			b = append(b, 0)
			b = binary.LittleEndian.AppendUint64(b, math.Float64bits(v))
		case bool:
			b = append(b, 0x08)
			b = append(b, kv.K...)
			b = append(b, 0)
			if v {
				b = append(b, 1)
			} else {
				b = append(b, 0)
			}
		case string:
			b = append(b, 0x02)
			b = append(b, kv.K...)
			b = append(b, 0)
			b = binary.LittleEndian.AppendUint32(b, uint32(len(v)+1))
			b = append(b, v...)
			b = append(b, 0)
		case mongoDoc:
			b = append(b, 0x03)
			b = append(b, kv.K...)
			b = append(b, 0)
			b = append(b, mongoEncode(v)...)
		}
	}
	b = append(b, 0)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

var errMongoBSON = errors.New("mongodb: malformed BSON")

// mongoDecode decodes one BSON document into a map. Arrays are decoded as []any. Depth is
// bounded.
func mongoDecode(b []byte, depth int) (map[string]any, int, error) {
	if depth > 16 || len(b) < 5 {
		return nil, 0, errMongoBSON
	}
	l := int(binary.LittleEndian.Uint32(b))
	if l < 5 || l > len(b) || b[l-1] != 0 {
		return nil, 0, errMongoBSON
	}
	out := map[string]any{}
	p := 4
	for p < l-1 {
		typ := b[p]
		p++
		end := p
		for end < l && b[end] != 0 {
			end++
		}
		if end >= l {
			return nil, 0, errMongoBSON
		}
		key := string(b[p:end])
		p = end + 1
		need := func(n int) bool { return n >= 0 && p+n <= l }
		switch typ {
		case 0x01:
			if !need(8) {
				return nil, 0, errMongoBSON
			}
			out[key] = math.Float64frombits(binary.LittleEndian.Uint64(b[p:]))
			p += 8
		case 0x02, 0x0d, 0x0e:
			if !need(4) {
				return nil, 0, errMongoBSON
			}
			n := int(int32(binary.LittleEndian.Uint32(b[p:])))
			p += 4
			if n < 1 || !need(n) {
				return nil, 0, errMongoBSON
			}
			out[key] = string(b[p : p+n-1])
			p += n
		case 0x03, 0x04:
			sub, n, err := mongoDecode(b[p:l], depth+1)
			if err != nil {
				return nil, 0, err
			}
			if typ == 0x04 {
				keys := make([]string, 0, len(sub))
				for k := range sub {
					keys = append(keys, k)
				}
				sort.Slice(keys, func(i, j int) bool {
					if len(keys[i]) != len(keys[j]) {
						return len(keys[i]) < len(keys[j])
					}
					return keys[i] < keys[j]
				})
				arr := make([]any, 0, len(keys))
				for _, k := range keys {
					arr = append(arr, sub[k])
				}
				out[key] = arr
			} else {
				out[key] = sub
			}
			p += n
		case 0x05:
			if !need(5) {
				return nil, 0, errMongoBSON
			}
			n := int(int32(binary.LittleEndian.Uint32(b[p:])))
			if n < 0 || !need(5+n) {
				return nil, 0, errMongoBSON
			}
			p += 5 + n
		case 0x06, 0x0a, 0xff, 0x7f:
		case 0x07:
			if !need(12) {
				return nil, 0, errMongoBSON
			}
			p += 12
		case 0x08:
			if !need(1) {
				return nil, 0, errMongoBSON
			}
			out[key] = b[p] != 0
			p++
		case 0x09, 0x11, 0x12:
			if !need(8) {
				return nil, 0, errMongoBSON
			}
			v := int64(binary.LittleEndian.Uint64(b[p:]))
			if typ == 0x12 {
				out[key] = v
			}
			p += 8
		case 0x0b:
			for k := 0; k < 2; k++ {
				for p < l && b[p] != 0 {
					p++
				}
				p++
			}
			if p > l {
				return nil, 0, errMongoBSON
			}
		case 0x0c:
			if !need(4) {
				return nil, 0, errMongoBSON
			}
			n := int(int32(binary.LittleEndian.Uint32(b[p:])))
			if n < 0 || !need(4+n+12) {
				return nil, 0, errMongoBSON
			}
			p += 4 + n + 12
		case 0x0f:
			if !need(4) {
				return nil, 0, errMongoBSON
			}
			n := int(int32(binary.LittleEndian.Uint32(b[p:])))
			if n < 4 || !need(n) {
				return nil, 0, errMongoBSON
			}
			p += n
		case 0x10:
			if !need(4) {
				return nil, 0, errMongoBSON
			}
			out[key] = int32(binary.LittleEndian.Uint32(b[p:]))
			p += 4
		case 0x13:
			if !need(16) {
				return nil, 0, errMongoBSON
			}
			p += 16
		default:
			return nil, 0, errMongoBSON
		}
	}
	return out, l, nil
}

func mongoNum(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// --- wire protocol ---------------------------------------------------------

const (
	mongoOpReply = 1
	mongoOpQuery = 2004
	mongoOpMsg   = 2013
)

func mongoOpMsgPacket(reqID int32, doc mongoDoc) []byte {
	body := mongoEncode(doc)
	b := make([]byte, 16, 16+5+len(body))
	binary.LittleEndian.PutUint32(b[4:], uint32(reqID))
	binary.LittleEndian.PutUint32(b[12:], mongoOpMsg)
	b = append(b, 0, 0, 0, 0, 0) // flagBits + section kind 0
	b = append(b, body...)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

func mongoOpQueryPacket(reqID int32, coll string, doc mongoDoc) []byte {
	body := mongoEncode(doc)
	b := make([]byte, 16, 16+len(coll)+13+len(body))
	binary.LittleEndian.PutUint32(b[4:], uint32(reqID))
	binary.LittleEndian.PutUint32(b[12:], mongoOpQuery)
	b = append(b, 0, 0, 0, 0) // flags
	b = append(b, coll...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)          // numberToSkip
	b = binary.LittleEndian.AppendUint32(b, 0xffffffff) // numberToReturn -1
	b = append(b, body...)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

// mongoReadReply reads one wire message and returns the first document.
func mongoReadReply(r io.Reader) (map[string]any, error) {
	var h [16]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	l := int(binary.LittleEndian.Uint32(h[:]))
	if l < 16 || l > 16<<20 {
		return nil, errMongoBSON
	}
	if l > 4<<20 {
		return nil, errors.New("mongodb: reply too large")
	}
	body := make([]byte, l-16)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	switch binary.LittleEndian.Uint32(h[12:]) {
	case mongoOpMsg:
		p := 4
		for p < len(body) {
			kind := body[p]
			p++
			if kind == 0 {
				d, _, err := mongoDecode(body[p:], 0)
				return d, err
			}
			if kind != 1 || p+4 > len(body) {
				return nil, errMongoBSON
			}
			n := int(binary.LittleEndian.Uint32(body[p:]))
			if n < 4 || p+n > len(body) {
				return nil, errMongoBSON
			}
			p += n
		}
		return nil, errMongoBSON
	case mongoOpReply:
		if len(body) < 20 {
			return nil, errMongoBSON
		}
		if binary.LittleEndian.Uint32(body[16:]) == 0 {
			return nil, errors.New("mongodb: empty reply")
		}
		d, _, err := mongoDecode(body[20:], 0)
		return d, err
	}
	return nil, errors.New("mongodb: unexpected opcode")
}

func mongoListDatabases(ctx context.Context, t *Target, legacy bool) (map[string]any, error) {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if isTLS(t.Service) {
		c = svcTLSClient(c)
	}
	var pkt []byte
	if legacy {
		pkt = mongoOpQueryPacket(1, "admin.$cmd", mongoDoc{{"listDatabases", int32(1)}, {"nameOnly", true}})
	} else {
		pkt = mongoOpMsgPacket(1, mongoDoc{{"listDatabases", int32(1)}, {"nameOnly", true}, {"$db", "admin"}})
	}
	if _, err := c.Write(pkt); err != nil {
		return nil, err
	}
	return mongoReadReply(c)
}

func runMongo(ctx context.Context, t *Target) []model.Finding {
	doc, err := mongoListDatabases(ctx, t, false)
	legacy := false
	if err != nil {
		var ne net.Error
		if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) {
			return nil
		}
		// MongoDB < 3.6 does not understand OP_MSG and closes the connection.
		doc, err = mongoListDatabases(ctx, t, true)
		legacy = true
		if err != nil {
			t.Log.Debug("mongodb probe failed", "err", err)
			return nil
		}
	}
	return mongoFindings(t, doc, legacy)
}

func mongoFindings(t *Target, doc map[string]any, legacy bool) []model.Finding {
	ok, _ := mongoNum(doc["ok"])
	if ok != 1 {
		return nil
	}
	arr, isArr := doc["databases"].([]any)
	if !isArr {
		return nil
	}
	var names []string
	for _, x := range arr {
		if m, ok := x.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				names = append(names, printable([]byte(n), 64))
			}
		}
	}
	sort.Strings(names)
	proto := "OP_MSG"
	if legacy {
		proto = "OP_QUERY"
	}
	ev := fmt.Sprintf("listDatabases (%s) succeeded without authentication: %d databases", proto, len(names))
	if len(names) > 0 {
		ev += ": " + strings.Join(limitStrings(names, 30), ", ")
	}
	return []model.Finding{t.Finding(ev)}
}
