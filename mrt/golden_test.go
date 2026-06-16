package mrt

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bgptools/fgbgp/messages"
)

var update = flag.Bool("update", false, "update golden files")

type goldenRecord struct {
	Type      string          `json:"type"`
	Timestamp int64           `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

func mrtToJSON(m Mrt) goldenRecord {
	switch v := m.(type) {
	case *MrtBGP4MP_Msg_AS4:
		return bgp4mpMsgToJSON(v)
	case *MrtBGP4MP_StateChange_AS4:
		return bgp4mpStateChangeToJSON(v)
	case *MrtTableDumpV2_PeerIndex:
		return peerIndexToJSON(v)
	case *MrtTableDumpV2_Rib:
		return ribToJSON(v)
	case MrtTableDumpV1_Rib:
		return td1ToJSON(v)
	default:
		return goldenRecord{Type: "UNKNOWN", Timestamp: 0}
	}
}

func bgp4mpMsgToJSON(m *MrtBGP4MP_Msg_AS4) goldenRecord {
	ts := int64(0)
	if !m.Timestamp.IsZero() {
		ts = m.Timestamp.Unix()
	}
	d := map[string]interface{}{
		"peer_as":         m.PeerAS,
		"local_as":        m.LocalAS,
		"interface_index": m.IfaceIndex,
		"peer_ip":         ipToStr(m.PeerIP),
		"local_ip":        ipToStr(m.LocalIP),
		"message":         messageToMap(m.Message),
	}
	raw, _ := json.Marshal(d)
	return goldenRecord{Type: "BGP4MP_MSG_AS4", Timestamp: ts, Data: raw}
}

func bgp4mpStateChangeToJSON(m *MrtBGP4MP_StateChange_AS4) goldenRecord {
	ts := int64(0)
	if !m.Timestamp.IsZero() {
		ts = m.Timestamp.Unix()
	}
	d := map[string]interface{}{
		"peer_as":         m.PeerAS,
		"local_as":        m.LocalAS,
		"interface_index": m.IfaceIndex,
		"peer_ip":         ipToStr(m.PeerIP),
		"local_ip":        ipToStr(m.LocalIP),
		"old_state":       stateToStr(m.OldState),
		"new_state":       stateToStr(m.NewState),
	}
	raw, _ := json.Marshal(d)
	return goldenRecord{Type: "BGP4MP_STATE_CHANGE_AS4", Timestamp: ts, Data: raw}
}

func peerIndexToJSON(m *MrtTableDumpV2_PeerIndex) goldenRecord {
	ts := int64(0)
	if !m.Timestamp.IsZero() {
		ts = m.Timestamp.Unix()
	}
	peers := make([]map[string]interface{}, len(m.Peers))
	for i, p := range m.Peers {
		peers[i] = map[string]interface{}{
			"id":  ipToStr(p.Id),
			"ip":  ipToStr(p.IP),
			"asn": p.ASN,
		}
	}
	d := map[string]interface{}{
		"collector_id": ipToStr(m.CollectorId),
		"view_name":    m.ViewName,
		"peers":        peers,
	}
	raw, _ := json.Marshal(d)
	return goldenRecord{Type: "TABLE_DUMPV2_PEER_INDEX", Timestamp: ts, Data: raw}
}

func ribToJSON(m *MrtTableDumpV2_Rib) goldenRecord {
	ts := int64(0)
	if !m.Timestamp.IsZero() {
		ts = m.Timestamp.Unix()
	}
	entries := make([]map[string]interface{}, len(m.RibEntries))
	for i, e := range m.RibEntries {
		attrs := attributesToSlice(e.Attributes)
		ots := int64(0)
		if !e.OrigTime.IsZero() {
			ots = e.OrigTime.Unix()
		}
		entries[i] = map[string]interface{}{
			"peer_index": e.PeerIndex,
			"orig_time":  ots,
			"attributes": attrs,
		}
	}
	d := map[string]interface{}{
		"sequence_number": m.SequenceNumber,
		"afi":             m.Afi,
		"safi":            m.Safi,
		"nlri":            nlriToMap(m.NLRI),
		"rib_entries":     entries,
	}
	raw, _ := json.Marshal(d)
	return goldenRecord{Type: "TABLE_DUMPV2_RIB", Timestamp: ts, Data: raw}
}

func td1ToJSON(m MrtTableDumpV1_Rib) goldenRecord {
	ts := int64(0)
	if !m.Timestamp.IsZero() {
		ts = m.Timestamp.Unix()
	}
	ots := int64(0)
	if !m.OriginatedTime.IsZero() {
		ots = m.OriginatedTime.Unix()
	}
	attrs := attributesToSlice(m.Attributes)
	d := map[string]interface{}{
		"view_number":     m.ViewNumber,
		"sequence_number": m.SequenceNumber,
		"prefix":          m.Prefix.String(),
		"status":          m.Status,
		"originated_time": ots,
		"peer_ip":         ipToStr(m.PeerIP),
		"peer_as":         m.PeerAS,
		"attributes":      attrs,
	}
	raw, _ := json.Marshal(d)
	return goldenRecord{Type: "TABLE_DUMPV1_RIB", Timestamp: ts, Data: raw}
}

func messageToMap(s messages.SerializableInterface) map[string]interface{} {
	switch v := s.(type) {
	case *messages.BGPMessageOpen:
		return openToMap(v)
	case *messages.BGPMessageUpdate:
		return updateToMap(v)
	case *messages.BGPMessageKeepAlive:
		return map[string]interface{}{"type": "KEEPALIVE"}
	case *messages.BGPMessageNotification:
		return notificationToMap(v)
	case *messages.BGPMessageRouteRefresh:
		return routeRefreshToMap(v)
	default:
		return map[string]interface{}{"type": fmt.Sprintf("UNKNOWN:%T", s)}
	}
}

func openToMap(m *messages.BGPMessageOpen) map[string]interface{} {
	params := make([]map[string]interface{}, len(m.Parameters))
	for i, p := range m.Parameters {
		pm := map[string]interface{}{
			"type": p.Type,
		}
		if p.Data != nil {
			pm["data"] = capabilitiesToSlice(p.Data)
		}
		params[i] = pm
	}
	return map[string]interface{}{
		"type":       "OPEN",
		"version":    m.Version,
		"asn":        m.ASN,
		"hold_time":  m.HoldTime,
		"identifier": ipToStr(m.Identifier),
		"parameters": params,
	}
}

func capabilitiesToSlice(c messages.BGPCapabilityIf) interface{} {
	switch v := c.(type) {
	case messages.BGPCapabilities:
		capas := make([]map[string]interface{}, len(v.BGPCapabilities))
		for i, capa := range v.BGPCapabilities {
			capas[i] = capabilityToMap(capa)
		}
		return capas
	default:
		return capabilityToMap(c)
	}
}

func capabilityToMap(c messages.BGPCapabilityIf) map[string]interface{} {
	switch v := c.(type) {
	case messages.BGPCapability_MP:
		return map[string]interface{}{
			"type": "MP",
			"afi":  v.Afi,
			"safi": v.Safi,
		}
	case messages.BGPCapability_ASN:
		return map[string]interface{}{
			"type": "ASN",
			"asn":  v.ASN,
		}
	case messages.BGPCapability_ADDPATH:
		aps := make([]map[string]interface{}, len(v.AddPathList))
		for i, ap := range v.AddPathList {
			aps[i] = map[string]interface{}{
				"afi":  ap.Afi,
				"safi": ap.Safi,
				"txrx": ap.TxRx,
			}
		}
		return map[string]interface{}{
			"type":      "ADDPATH",
			"add_paths": aps,
		}
	case messages.BGPCapability_ROUTEREFRESH:
		return map[string]interface{}{
			"type": "ROUTEREFRESH",
		}
	default:
		return map[string]interface{}{
			"type": fmt.Sprintf("UNKNOWN:%T", c),
		}
	}
}

func updateToMap(m *messages.BGPMessageUpdate) map[string]interface{} {
	withdrawn := make([]map[string]interface{}, len(m.WithdrawnRoutes))
	for i, w := range m.WithdrawnRoutes {
		withdrawn[i] = nlriToMap(w)
	}
	attrs := attributesToSlice(m.PathAttributes)
	nlris := make([]map[string]interface{}, len(m.NLRI))
	for i, n := range m.NLRI {
		nlris[i] = nlriToMap(n)
	}
	return map[string]interface{}{
		"type":             "UPDATE",
		"withdrawn_routes": withdrawn,
		"path_attributes":  attrs,
		"nlri":             nlris,
	}
}

func notificationToMap(m *messages.BGPMessageNotification) map[string]interface{} {
	return map[string]interface{}{
		"type":          "NOTIFICATION",
		"error_code":    m.ErrorCode,
		"error_subcode": m.ErrorSubcode,
		"data":          fmt.Sprintf("%x", m.Data),
	}
}

func routeRefreshToMap(m *messages.BGPMessageRouteRefresh) map[string]interface{} {
	return map[string]interface{}{
		"type": "ROUTEREFRESH",
		"afi":  m.AfiSafi.Afi,
		"safi": m.AfiSafi.Safi,
	}
}

func attributesToSlice(attrs []messages.BGPAttributeIf) []map[string]interface{} {
	result := make([]map[string]interface{}, len(attrs))
	for i, a := range attrs {
		result[i] = attributeToMap(a)
	}
	return result
}

func attributeToMap(a messages.BGPAttributeIf) map[string]interface{} {
	switch v := a.(type) {
	case messages.BGPAttribute_ORIGIN:
		return map[string]interface{}{
			"code":   messages.ATTRIBUTE_ORIGIN,
			"name":   "ORIGIN",
			"origin": v.Origin,
		}
	case messages.BGPAttribute_ASPATH:
		segs := make([]map[string]interface{}, len(v.Segments))
		for j, seg := range v.Segments {
			segs[j] = map[string]interface{}{
				"type":    seg.SType,
				"as_path": seg.ASPath,
			}
		}
		return map[string]interface{}{
			"code":     messages.ATTRIBUTE_ASPATH,
			"name":     "AS_PATH",
			"segments": segs,
		}
	case messages.BGPAttribute_NEXTHOP:
		return map[string]interface{}{
			"code":    messages.ATTRIBUTE_NEXTHOP,
			"name":    "NEXT_HOP",
			"nexthop": v.NextHop.String(),
		}
	case messages.BGPAttribute_MED:
		return map[string]interface{}{
			"code": messages.ATTRIBUTE_MED,
			"name": "MULTI_EXIT_DISC",
			"med":  v.Med,
		}
	case messages.BGPAttribute_LOCPREF:
		return map[string]interface{}{
			"code":     messages.ATTRIBUTE_LOCPREF,
			"name":     "LOCAL_PREF",
			"loc_pref": v.LocPref,
		}
	case messages.BGPAttribute_COMMUNITIES:
		return map[string]interface{}{
			"code":        messages.ATTRIBUTE_COMMUNITIES,
			"name":        "COMMUNITY",
			"communities": v.Communities,
		}
	case messages.BGPAttribute_LARGECOMMUNITIES:
		coms := make([]map[string]interface{}, len(v.Communities))
		for j, c := range v.Communities {
			coms[j] = map[string]interface{}{
				"global_admin": c.GlobalAdmin,
				"local_data1":  c.LocalData1,
				"local_data2":  c.LocalData2,
			}
		}
		return map[string]interface{}{
			"code":        messages.ATTRIBUTE_LARGECOMMUNITIES,
			"name":        "LARGE_COMMUNITY",
			"communities": coms,
		}
	case messages.BGPAttribute_MP_REACH:
		nlris := make([]map[string]interface{}, len(v.NLRI))
		for j, n := range v.NLRI {
			nlris[j] = nlriToMap(n)
		}
		return map[string]interface{}{
			"code":    messages.ATTRIBUTE_REACH,
			"name":    "MP_REACH_NLRI",
			"afi":     v.Afi,
			"safi":    v.Safi,
			"nexthop": v.NextHop.String(),
			"nlri":    nlris,
		}
	case messages.BGPAttribute_MP_UNREACH:
		nlris := make([]map[string]interface{}, len(v.NLRI))
		for j, n := range v.NLRI {
			nlris[j] = nlriToMap(n)
		}
		return map[string]interface{}{
			"code": messages.ATTRIBUTE_UNREACH,
			"name": "MP_UNREACH_NLRI",
			"afi":  v.Afi,
			"safi": v.Safi,
			"nlri": nlris,
		}
	case messages.BGPAttribute_ATOMIC_AGGREGATE:
		return map[string]interface{}{
			"code": messages.ATTRIBUTE_ATOMIC_AGGREGATE,
			"name": "ATOMIC_AGGREGATE",
		}
	case messages.BGPAttribute_AGGREGATOR:
		return map[string]interface{}{
			"code":       messages.ATTRIBUTE_AGGREGATOR,
			"name":       "AGGREGATOR",
			"asn":        v.ASN,
			"identifier": ipToStr(v.Identifier),
		}
	case messages.BGPAttribute:
		return map[string]interface{}{
			"code":  v.Code,
			"name":  fmt.Sprintf("UNKNOWN_%d", v.Code),
			"flags": v.Flags,
			"data":  fmt.Sprintf("%x", v.Data),
		}
	default:
		return map[string]interface{}{
			"code": 0,
			"name": fmt.Sprintf("UNHANDLED:%T", a),
		}
	}
}

func nlriToMap(n messages.NLRI) map[string]interface{} {
	switch v := n.(type) {
	case messages.NLRI_IPPrefix:
		m := map[string]interface{}{
			"type":   "IP_PREFIX",
			"prefix": v.Prefix.String(),
		}
		if v.PathId != 0 {
			m["path_id"] = v.PathId
		}
		return m
	default:
		return map[string]interface{}{
			"type": fmt.Sprintf("UNKNOWN:%T", n),
		}
	}
}

func ipToStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func stateToStr(state uint16) string {
	switch state {
	case 1:
		return "IDLE"
	case 2:
		return "CONNECT"
	case 3:
		return "ACTIVE"
	case 4:
		return "OPENSENT"
	case 5:
		return "OPENCONFIRM"
	case 6:
		return "ESTABLISHED"
	default:
		return fmt.Sprintf("UNKNOWN_%d", state)
	}
}

func mrtFiles() []string {
	return []string{
		"32816bac-6a2a-41d6-a10e-2b9040fea5ea,oqrvcdrqj7,2026-06-16T11:23:59Z,sp.mrt.gz",
		"441e33f3-1dc9-453b-81eb-40b7a48c8b9d,ldy63elm7y,2026-06-16T11:23:08Z,sp.mrt.gz",
		"4842d06a-0a59-4df0-86bb-661bd4e6e214,s7sgfocykq,2026-06-16T11:17:38Z,ap.mrt.gz",
		"c05ff976-1f52-4b73-8825-8d462c12ce12,zgz6pbknvl,2026-06-16T11:22:58Z,sp.mrt.gz",
	}
}

func TestGoldenMRTDecode(t *testing.T) {
	flag.Parse()
	testdataDir := filepath.Join("testdata")
	goldenDir := filepath.Join("testdata", "golden")

	if *update {
		if err := os.MkdirAll(goldenDir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	for _, fname := range mrtFiles() {
		fname := fname
		t.Run(fname, func(t *testing.T) {
			fpath := filepath.Join(testdataDir, fname)
			f, err := os.Open(fpath)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			gr, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			defer gr.Close()

			var records []goldenRecord
			for {
				m, err := DecodeSingle(gr)
				if err != nil {
					break
				}
				records = append(records, mrtToJSON(m))
			}

			got, err := json.MarshalIndent(records, "", "  ")
			if err != nil {
				t.Fatal(err)
			}

			goldenPath := filepath.Join(goldenDir, sanitizeName(fname)+".json.gz")
			if *update {
				fh, err := os.Create(goldenPath)
				if err != nil {
					t.Fatal(err)
				}
				gw, err := gzip.NewWriterLevel(fh, gzip.BestCompression)
				if err != nil {
					fh.Close()
					t.Fatal(err)
				}
				if _, err := gw.Write(got); err != nil {
					gw.Close()
					fh.Close()
					t.Fatal(err)
				}
				if err := gw.Close(); err != nil {
					fh.Close()
					t.Fatal(err)
				}
				if err := fh.Close(); err != nil {
					t.Fatal(err)
				}
				t.Logf("updated golden file: %s", goldenPath)
				return
			}

			fh, err := os.Open(goldenPath)
			if err != nil {
				t.Fatalf("golden file %s not found (run with -update to create): %v", goldenPath, err)
			}
			grGolden, err := gzip.NewReader(fh)
			if err != nil {
				fh.Close()
				t.Fatal(err)
			}
			want, err := io.ReadAll(grGolden)
			grGolden.Close()
			fh.Close()
			if err != nil {
				t.Fatal(err)
			}

			if string(got) != string(want) {
				t.Fatalf("golden file %s mismatch (run with -update to update)", goldenPath)
			}
		})
	}
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, ",", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.TrimSuffix(name, ".gz")
	return name
}

func BenchmarkDecodeMRT(b *testing.B) {
	for _, fname := range mrtFiles() {
		fname := fname
		b.Run(fname, func(b *testing.B) {
			data := readGzipToBytes(b, filepath.Join("testdata", fname))

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				r := bytesReader(data)
				count := 0
				for {
					_, err := DecodeSingle(r)
					if err != nil {
						break
					}
					count++
				}
				_ = count
			}
		})
	}
}

func readGzipToBytes(b testing.TB, path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		b.Fatal(err)
	}
	defer gr.Close()

	data, err := io.ReadAll(gr)
	if err != nil {
		b.Fatal(err)
	}
	return data
}

func bytesReader(data []byte) *readCounter {
	return &readCounter{data: data}
}

type readCounter struct {
	data []byte
	pos  int
}

func (r *readCounter) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
