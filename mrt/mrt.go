package mrt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/bgptools/fgbgp/messages"
)

const (
	TYPE_OSPFV2       = 11
	TYPE_TABLE_DUMP   = 12
	TYPE_TABLE_DUMPV2 = 13

	TYPE_BGP4MP    = 16
	TYPE_BGP4MP_ET = 17

	TYPE_ISIS    = 32
	TYPE_ISIS_ET = 33

	TYPE_OSPFV3    = 48
	TYPE_OSPFV3_ET = 49

	SUBT_TABLE_DUMP_AFI_IPV4 = 1
	SUBT_TABLE_DUMP_AFI_IPV6 = 2

	SUBT_TABLE_DUMPV2_PEER_INDEX_TABLE         = 1
	SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST         = 2
	SUBT_TABLE_DUMPV2_RIB_IPV4_MULTICAST       = 3
	SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST         = 4
	SUBT_TABLE_DUMPV2_RIB_IPV6_MULTICAST       = 5
	SUBT_TABLE_DUMPV2_RIB_GENERIC              = 6
	SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST_ADDPATH = 8
	SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST_ADDPATH = 10

	SUBT_BGP4MP_STATE_CHANGE      = 0
	SUBT_BGP4MP_MESSAGE           = 1
	SUBT_BGP4MP_MESSAGE_AS4       = 4
	SUBT_BGP4MP_STATE_CHANGE_AS4  = 5
	SUBT_BGP4MP_MESSAGE_LOCAL     = 6
	SUBT_BGP4MP_MESSAGE_AS4_LOCAL = 7

	STATE_IDLE        = 1
	STATE_CONNECT     = 2
	STATE_ACTIVE      = 3
	STATE_OPENSENT    = 4
	STATE_OPENCONFIRM = 5
	STATE_ESTABLISHED = 6
)

type Mrt interface {
	Write(io.Writer)
	Len() int
}

func WriteCommonHeader(buf io.Writer, timestamp time.Time, mrttype uint16, subtype uint16, length uint32) {
	binary.Write(buf, binary.BigEndian, uint32(timestamp.Unix()))
	binary.Write(buf, binary.BigEndian, mrttype)
	binary.Write(buf, binary.BigEndian, subtype)
	binary.Write(buf, binary.BigEndian, length)
}

type Peer struct {
	Id  net.IP
	IP  net.IP
	ASN uint32
}

func (p *Peer) Write(buf io.Writer) {
	newip := p.IP
	firstbit := 1
	if tmpip := newip.To4(); tmpip != nil {
		newip = tmpip
		firstbit = 0
	}

	longasn := 1
	if p.ASN <= 0xffff {
		longasn = 0
	}

	firstbyte := byte(longasn<<2 | firstbit)
	binary.Write(buf, binary.BigEndian, firstbyte)

	binary.Write(buf, binary.BigEndian, p.Id.To4())

	binary.Write(buf, binary.BigEndian, newip)
	if longasn == 1 {
		binary.Write(buf, binary.BigEndian, p.ASN)
	} else {
		binary.Write(buf, binary.BigEndian, uint16(p.ASN))
	}
}

func (p *Peer) Len() int {
	iplen := 4
	newip := p.IP
	if tmpip := newip.To4(); tmpip == nil {
		iplen = 16
	}
	longasn := 4
	if p.ASN <= 0xffff {
		longasn = 2
	}
	return 1 + 4 + iplen + longasn
}

type MrtTableDumpV2_PeerIndex struct {
	Timestamp   time.Time
	CollectorId net.IP
	ViewName    string
	Peers       []*Peer
}

func NewMrtTableDumpV2_PeerIndex(collectorid net.IP, viewname string, ts time.Time) *MrtTableDumpV2_PeerIndex {
	return &MrtTableDumpV2_PeerIndex{
		Timestamp:   ts,
		CollectorId: collectorid,
		ViewName:    viewname,
		Peers:       make([]*Peer, 0),
	}
}

func (mrt *MrtTableDumpV2_PeerIndex) AddPeer(id net.IP, asn uint32, ip net.IP) uint16 {
	peer := &Peer{
		Id:  id.To4(),
		IP:  ip,
		ASN: asn,
	}
	mrt.Peers = append(mrt.Peers, peer)
	return uint16(len(mrt.Peers) - 1)
}

func (mrt *MrtTableDumpV2_PeerIndex) Write(buf io.Writer) {
	WriteCommonHeader(buf, mrt.Timestamp, TYPE_TABLE_DUMPV2, SUBT_TABLE_DUMPV2_PEER_INDEX_TABLE, uint32(mrt.Len()))
	binary.Write(buf, binary.BigEndian, mrt.CollectorId.To4())
	binary.Write(buf, binary.BigEndian, uint16(len(mrt.ViewName)))
	binary.Write(buf, binary.BigEndian,
		[]byte(mrt.ViewName))
	binary.Write(buf, binary.BigEndian, uint16(len(mrt.Peers)))
	for i := range mrt.Peers {
		mrt.Peers[i].Write(buf)
	}
}

func (mrt *MrtTableDumpV2_PeerIndex) Len() int {
	totallen := 4 + 2 + len(mrt.ViewName) + 2
	for i := range mrt.Peers {
		totallen += mrt.Peers[i].Len()
	}
	return totallen
}

type RibEntry struct {
	PeerIndex  uint16
	OrigTime   time.Time
	Attributes []messages.BGPAttributeIf
}

func (entry *RibEntry) Write(buf io.Writer) {
	binary.Write(buf, binary.BigEndian, entry.PeerIndex)
	binary.Write(buf, binary.BigEndian, uint32(entry.OrigTime.Unix()))

	var size uint16

	for i := range entry.Attributes {
		switch attribute := entry.Attributes[i].(type) {
		case *messages.BGPAttribute_MP_REACH:
			size += attribute.LenMrt()
		case *messages.BGPAttribute_MP_UNREACH:
		default:
			size += uint16(entry.Attributes[i].Len())
		}
	}

	binary.Write(buf, binary.BigEndian, size)

	for i := range entry.Attributes {
		switch attribute := entry.Attributes[i].(type) {
		case *messages.BGPAttribute_MP_REACH:
			attribute.WriteMrt(buf)
		case *messages.BGPAttribute_MP_UNREACH:
		default:
			entry.Attributes[i].Write(buf)
		}
	}
}

func (entry *RibEntry) Len() uint32 {
	size := uint32(2 + 4 + 2)
	// To optimize
	for i := range entry.Attributes {
		switch attribute := entry.Attributes[i].(type) {
		case *messages.BGPAttribute_MP_REACH:
			size += uint32(attribute.LenMrt())
		case *messages.BGPAttribute_MP_UNREACH:
		default:
			size += uint32(entry.Attributes[i].Len())
		}

	}
	return size
}

type MrtTableDumpV2_Rib struct {
	Timestamp      time.Time
	SequenceNumber uint32
	Afi            uint16
	Safi           byte
	NLRI           messages.NLRI
	RibEntries     []*RibEntry

	WriteAsAfiSafi bool
}

func NewMrtTableDumpV2_RibGeneric(seqnum uint32, afi uint16, safi byte, nlri messages.NLRI, ts time.Time) *MrtTableDumpV2_Rib {
	return &MrtTableDumpV2_Rib{
		Timestamp:      ts,
		SequenceNumber: seqnum,
		Afi:            afi,
		Safi:           safi,
		NLRI:           nlri,
		RibEntries:     make([]*RibEntry, 0),
	}
}

func NewMrtTableDumpV2_RibAfiSafi(seqnum uint32, afi uint16, safi byte, nlri messages.NLRI, ts time.Time) *MrtTableDumpV2_Rib {
	mrt := NewMrtTableDumpV2_RibGeneric(seqnum, afi, safi, nlri, ts)
	mrt.WriteAsAfiSafi = true
	return mrt
}

func (entry *RibEntry) EntryToUpdate() *messages.BGPMessageUpdate {
	update := &messages.BGPMessageUpdate{
		PathAttributes: entry.Attributes,
	}
	return update
}

func (mrt *MrtTableDumpV2_Rib) ConvertToUpdateIndex(index int) *messages.BGPMessageUpdate {
	re := mrt.RibEntries
	if index >= len(re) {
		return nil
	}
	entry := re[index]
	update := entry.EntryToUpdate()

	if mrt.NLRI.GetAfi() == messages.AFI_IPV6 {
		pa := update.PathAttributes
		var hasreach bool
		for i := range pa {
			switch pai := pa[i].(type) {
			case messages.BGPAttribute_MP_REACH:
				// Check NLRI already in
				var hasipinreach bool
				hasreach = true

				mpnlri := pai.NLRI
				for j := range mpnlri {
					if mrt.NLRI.Equals(mpnlri[j]) {
						hasipinreach = true
						break
					}
				}

				if !hasipinreach {
					pai.NLRI = append(pai.NLRI, mrt.NLRI)
				}

			}
		}
		if !hasreach {
			attr := &messages.BGPAttribute_MP_REACH{
				NLRI: []messages.NLRI{mrt.NLRI},
			}
			update.PathAttributes = append(update.PathAttributes, attr)
		}
	} else {
		update.NLRI = []messages.NLRI{mrt.NLRI}
	}
	return update
}
func (mrt *MrtTableDumpV2_Rib) ConvertToUpdate() []*messages.BGPMessageUpdate {
	updates := make([]*messages.BGPMessageUpdate, 0)
	re := mrt.RibEntries
	for i := range re {
		update := mrt.ConvertToUpdateIndex(i)
		if update != nil {
			updates = append(updates, update)
		}
	}
	return updates
}

func (mrt *MrtTableDumpV2_Rib) AddEntry(peerindex uint16, origtime time.Time, attributes []messages.BGPAttributeIf) {
	entry := &RibEntry{
		PeerIndex:  peerindex,
		OrigTime:   origtime,
		Attributes: attributes,
	}
	mrt.RibEntries = append(mrt.RibEntries, entry)
}

func (mrt *MrtTableDumpV2_Rib) GetSubtype() (bool, uint16) {
	subt := uint16(SUBT_TABLE_DUMPV2_RIB_GENERIC)
	force_generic := true

	if mrt.WriteAsAfiSafi {
		if mrt.Afi == messages.AFI_IPV4 && mrt.Safi == messages.SAFI_UNICAST {
			force_generic = false
			subt = SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST
		} else if mrt.Afi == messages.AFI_IPV4 && mrt.Safi == messages.SAFI_MULTICAST {
			force_generic = false
			subt = SUBT_TABLE_DUMPV2_RIB_IPV4_MULTICAST
		} else if mrt.Afi == messages.AFI_IPV6 && mrt.Safi == messages.SAFI_UNICAST {
			force_generic = false
			subt = SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST
		} else if mrt.Afi == messages.AFI_IPV6 && mrt.Safi == messages.SAFI_MULTICAST {
			force_generic = false
			subt = SUBT_TABLE_DUMPV2_RIB_IPV6_MULTICAST
		}
	}
	return force_generic, subt
}

func (mrt *MrtTableDumpV2_Rib) Write(buf io.Writer) {
	force_generic, subt := mrt.GetSubtype()

	WriteCommonHeader(buf, mrt.Timestamp, TYPE_TABLE_DUMPV2, subt, uint32(mrt.Len()))
	if force_generic {
		binary.Write(buf, binary.BigEndian, mrt.Afi)
		binary.Write(buf, binary.BigEndian, mrt.Safi)
	}

	binary.Write(buf, binary.BigEndian, mrt.SequenceNumber)
	mrt.NLRI.Write(buf, false)
	binary.Write(buf, binary.BigEndian, uint16(len(mrt.RibEntries)))
	for i := range mrt.RibEntries {
		mrt.RibEntries[i].Write(buf)
	}
}

func (mrt *MrtTableDumpV2_Rib) Len() int {
	force_generic, _ := mrt.GetSubtype()
	size := 4 + len(mrt.NLRI.Bytes(false)) + 2
	if force_generic {
		size += 2
	}
	for i := range mrt.RibEntries {
		size += int(mrt.RibEntries[i].Len())
	}
	return size
}

type MrtBGP4MP_Msg_AS4 struct {
	Timestamp  time.Time
	PeerAS     uint32
	LocalAS    uint32
	IfaceIndex uint16
	PeerIP     net.IP
	LocalIP    net.IP
	Message    messages.SerializableInterface
}

type MrtBGP4MP_StateChange_AS4 struct {
	Timestamp  time.Time
	PeerAS     uint32
	LocalAS    uint32
	IfaceIndex uint16
	PeerIP     net.IP
	LocalIP    net.IP
	OldState   uint16
	NewState   uint16
}

func NewMrtBGP4MP_StateChange_AS4(peeras uint32, localas uint32, iface uint16, peerip net.IP, localip net.IP, oldstate uint16, newstate uint16) *MrtBGP4MP_StateChange_AS4 {
	return &MrtBGP4MP_StateChange_AS4{
		Timestamp:  time.Now().UTC(),
		PeerAS:     peeras,
		LocalAS:    localas,
		IfaceIndex: iface,
		PeerIP:     peerip,
		LocalIP:    localip,
		OldState:   oldstate,
		NewState:   newstate,
	}
}

func (mrt *MrtBGP4MP_StateChange_AS4) IsIPv4() bool {
	return mrt.PeerIP.To4() != nil
}

func (mrt *MrtBGP4MP_StateChange_AS4) Len() int {
	ipsize := 4
	if !mrt.IsIPv4() {
		ipsize = 16
	}
	return 4 + 4 + 2 + 2 + 2*ipsize + 2 + 2
}

func (mrt *MrtBGP4MP_StateChange_AS4) Write(buf io.Writer) {
	WriteCommonHeader(buf, mrt.Timestamp, TYPE_BGP4MP, SUBT_BGP4MP_STATE_CHANGE_AS4, uint32(mrt.Len()))

	binary.Write(buf, binary.BigEndian, mrt.PeerAS)
	binary.Write(buf, binary.BigEndian, mrt.LocalAS)

	binary.Write(buf, binary.BigEndian, mrt.IfaceIndex)
	if mrt.IsIPv4() {
		binary.Write(buf, binary.BigEndian, uint16(messages.AFI_IPV4))
		binary.Write(buf, binary.BigEndian, mrt.PeerIP.To4())
		binary.Write(buf, binary.BigEndian, mrt.LocalIP.To4())
	} else {
		binary.Write(buf, binary.BigEndian, uint16(messages.AFI_IPV6))
		binary.Write(buf, binary.BigEndian, mrt.PeerIP)
		binary.Write(buf, binary.BigEndian, mrt.LocalIP)
	}

	binary.Write(buf, binary.BigEndian, mrt.OldState)
	binary.Write(buf, binary.BigEndian, mrt.NewState)
}

func NewMrtBGP4MP_Msg_AS4(peeras uint32, localas uint32, iface uint16, peerip net.IP, localip net.IP, message messages.SerializableInterface) *MrtBGP4MP_Msg_AS4 {
	return &MrtBGP4MP_Msg_AS4{
		Timestamp:  time.Now().UTC(),
		PeerAS:     peeras,
		LocalAS:    localas,
		IfaceIndex: iface,
		PeerIP:     peerip,
		LocalIP:    localip,
		Message:    message,
	}
}

func (mrt *MrtBGP4MP_Msg_AS4) IsIPv4() bool {
	return mrt.PeerIP.To4() != nil
}

func (mrt *MrtBGP4MP_Msg_AS4) Len() int {
	ipsize := 4
	if !mrt.IsIPv4() {
		ipsize = 16
	}
	return 4 + 4 + 2 + 2 + 2*ipsize + mrt.Message.Len()
}

func (mrt *MrtBGP4MP_Msg_AS4) Write(buf io.Writer) {
	WriteCommonHeader(buf, mrt.Timestamp, TYPE_BGP4MP, SUBT_BGP4MP_MESSAGE_AS4, uint32(mrt.Len()))

	binary.Write(buf, binary.BigEndian, mrt.PeerAS)
	binary.Write(buf, binary.BigEndian, mrt.LocalAS)

	binary.Write(buf, binary.BigEndian, mrt.IfaceIndex)
	if mrt.IsIPv4() {
		binary.Write(buf, binary.BigEndian, uint16(messages.AFI_IPV4))
		binary.Write(buf, binary.BigEndian, mrt.PeerIP.To4())
		binary.Write(buf, binary.BigEndian, mrt.LocalIP.To4())
	} else {
		binary.Write(buf, binary.BigEndian, uint16(messages.AFI_IPV6))
		binary.Write(buf, binary.BigEndian, mrt.PeerIP)
		binary.Write(buf, binary.BigEndian, mrt.LocalIP)
	}
	mrt.Message.Write(buf)
}

func DecodeBGP4MP(buf io.Reader, timestamp time.Time, subtype uint16, length uint32) (Mrt, error) {
	if length > MaxMrtLength {
		return nil, fmt.Errorf("BGP4MP record length %d exceeds maximum %d", length, MaxMrtLength)
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(buf, content); err != nil {
		return nil, err
	}
	return decodeBGP4MP(newByteReader(content), timestamp, subtype, length)
}

func decodeBGP4MP(r *byteReader, timestamp time.Time, subtype uint16, length uint32) (Mrt, error) {
	if length > MaxMrtLength {
		return nil, fmt.Errorf("BGP4MP record length %d exceeds maximum %d", length, MaxMrtLength)
	}
	switch subtype {
	case SUBT_BGP4MP_MESSAGE_AS4:
		peeras := r.ReadUint32()
		localas := r.ReadUint32()
		ifaceindex := r.ReadUint16()
		afi := r.ReadUint16()
		var sizeip int
		if afi == messages.AFI_IPV6 {
			sizeip = 16
		} else {
			sizeip = 4
		}
		peerip := r.ReadBytes(sizeip)
		localip := r.ReadBytes(sizeip)

		headerLen := uint32(4 + 4 + 2 + 2 + 2*uint32(sizeip))
		if length < headerLen {
			return nil, errors.New("DecodeBGP4MP: cannot decode message with negative length")
		}
		msgsize := length - headerLen
		msg := r.ReadBytes(int(msgsize))

		bgptype, bgplen, err1 := messages.ParsePacketHeader(msg)
		if err1 != nil {
			return nil, err1
		}
		if int(bgplen)+19 > len(msg) {
			return nil, errors.New("DecodeBGP4MP: BGP message length exceeds payload")
		}
		pktd, err2 := messages.ParsePacket(bgptype, msg[19:19+bgplen])

		mrt := &MrtBGP4MP_Msg_AS4{
			Timestamp:  timestamp,
			PeerAS:     peeras,
			LocalAS:    localas,
			IfaceIndex: ifaceindex,
			PeerIP:     net.IP(peerip),
			LocalIP:    net.IP(localip),
			Message:    pktd,
		}

		return mrt, err2
	case SUBT_BGP4MP_STATE_CHANGE_AS4:
		peeras := r.ReadUint32()
		localas := r.ReadUint32()
		ifaceindex := r.ReadUint16()
		afi := r.ReadUint16()
		var sizeip int
		if afi == messages.AFI_IPV6 {
			sizeip = 16
		} else {
			sizeip = 4
		}
		peerip := r.ReadBytes(sizeip)
		localip := r.ReadBytes(sizeip)
		oldstate := r.ReadUint16()
		newstate := r.ReadUint16()

		mrt := &MrtBGP4MP_StateChange_AS4{
			Timestamp:  timestamp,
			PeerAS:     peeras,
			LocalAS:    localas,
			IfaceIndex: ifaceindex,
			PeerIP:     net.IP(peerip),
			LocalIP:    net.IP(localip),
			OldState:   oldstate,
			NewState:   newstate,
		}

		return mrt, nil
	default:
		return nil, fmt.Errorf("Decoding of subtype %v of BGP4MP not implemented", subtype)
	}
}

func decodeNLRI(r *byteReader, afi uint16, safi byte) (messages.NLRI, error) {
	if afi != messages.AFI_IPV4 && afi != messages.AFI_IPV6 {
		return nil, fmt.Errorf("Could not decode NLRI for Afi: %v", afi)
	}
	if safi != messages.SAFI_UNICAST && safi != messages.SAFI_MULTICAST {
		return nil, fmt.Errorf("Could not decode NLRI for Safi: %v", safi)
	}

	l := r.ReadUint8()

	size := l / 8
	if l%8 != 0 {
		size++
	}
	b := r.ReadBytes(int(size))

	newb := append([]byte{l}, b...)
	nlri, err := messages.ParseNLRI(newb, afi, safi, false)

	if len(nlri) == 1 {
		return nlri[0], err
	} else {
		return nil, fmt.Errorf("Could not decode NLRI %v (%v/%v) (number of results != 1): %v", newb, afi, safi, err)
	}
}

func decodeAttributes(r *byteReader, attrlen uint16) ([]messages.BGPAttributeIf, error) {
	b := r.ReadBytes(int(attrlen))
	return messages.ParsePathAttribute(b, nil, false)
}

func decodeAttributes2B(r *byteReader, attrlen uint16) ([]messages.BGPAttributeIf, error) {
	b := r.ReadBytes(int(attrlen))
	return messages.ParsePathAttribute(b, nil, true)
}

func decodeRibEntries(r *byteReader) (*RibEntry, error) {
	peerindex := r.ReadUint16()
	origints := r.ReadUint32()
	attrlen := r.ReadUint16()
	attrs, err := decodeAttributes(r, attrlen)
	origintsP := time.Unix(int64(origints), 0)
	re := &RibEntry{
		OrigTime:   origintsP,
		PeerIndex:  peerindex,
		Attributes: attrs,
	}
	return re, err
}

func decodeRibEntriesAddPath(r *byteReader) (*RibEntry, error) {
	peerindex := r.ReadUint16()
	origints := r.ReadUint32()
	r.ReadUint32()
	attrlen := r.ReadUint16()
	attrs, err := decodeAttributes(r, attrlen)
	origintsP := time.Unix(int64(origints), 0)
	re := &RibEntry{
		OrigTime:   origintsP,
		PeerIndex:  peerindex,
		Attributes: attrs,
	}
	return re, err
}

func decodeBGP4TD2RIBSpec(r *byteReader, subtype uint16, timestamp time.Time, addpath bool) (Mrt, error) {
	var afi uint16
	var safi byte
	switch subtype {
	case SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST, SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST_ADDPATH:
		afi = messages.AFI_IPV4
		safi = messages.SAFI_UNICAST
	case SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST, SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST_ADDPATH:
		afi = messages.AFI_IPV6
		safi = messages.SAFI_UNICAST
	case SUBT_TABLE_DUMPV2_RIB_IPV4_MULTICAST:
		afi = messages.AFI_IPV4
		safi = messages.SAFI_MULTICAST
	case SUBT_TABLE_DUMPV2_RIB_IPV6_MULTICAST:
		afi = messages.AFI_IPV6
		safi = messages.SAFI_MULTICAST
	default:
		return nil, errors.New("Cannot decode as Rib Afi/Safi specific")
	}

	seqnum := r.ReadUint32()
	preflen := r.ReadUint8()

	size := preflen / 8
	if preflen%8 != 0 {
		size++
	}
	prefix := r.ReadBytes(int(size))

	newb := append([]byte{preflen}, prefix...)
	nlri, err := messages.ParseNLRI(newb, afi, safi, false)

	mrt := &MrtTableDumpV2_Rib{
		Timestamp:      timestamp,
		Afi:            afi,
		Safi:           safi,
		SequenceNumber: seqnum,
		WriteAsAfiSafi: true,
	}

	if len(nlri) == 1 {
		mrt.NLRI = nlri[0]
	} else {
		return mrt, fmt.Errorf("Could not decode NLRI %v (%v/%v) (number of results != 1): %v", newb, afi, safi, err)
	}

	if err != nil {
		return mrt, err
	}

	entrycount := r.ReadUint16()
	entries := make([]*RibEntry, entrycount)
	var errentry error
	for i := 0; i < int(entrycount); i++ {
		if addpath {
			entries[i], errentry = decodeRibEntriesAddPath(r)
		} else {
			entries[i], errentry = decodeRibEntries(r)
		}
	}
	mrt.RibEntries = entries
	return mrt, errentry
}

type MrtTableDumpV1_Rib struct {
	Timestamp      time.Time
	OriginatedTime time.Time
	ViewNumber     uint16
	SequenceNumber uint16
	Prefix         net.IPNet
	NLRI           messages.NLRI
	Status         uint8
	PeerIP         net.IP
	PeerAS         uint16
	Attributes     []messages.BGPAttributeIf
	WriteAsAfiSafi bool
}

func (mrt MrtTableDumpV1_Rib) Len() int {
	log.Fatalf("unsupported: (mrt *MrtTableDumpV1_Rib) Len() ")
	return 0
}

func (mrt MrtTableDumpV1_Rib) Write(io.Writer) {
	log.Fatalf("unsupported: (mrt *MrtTableDumpV1_Rib) Write() ")
}

func decodeBGP4TD1(r *byteReader, timestamp time.Time, subtype uint16, length uint32) (Mrt, error) {
	out := MrtTableDumpV1_Rib{}
	out.Timestamp = timestamp
	out.ViewNumber = r.ReadUint16()
	out.SequenceNumber = r.ReadUint16()
	var rawPrefix []byte
	var mask []byte
	switch subtype {
	case SUBT_TABLE_DUMP_AFI_IPV4:
		rawPrefix = r.ReadBytes(4)
	case SUBT_TABLE_DUMP_AFI_IPV6:
		rawPrefix = r.ReadBytes(16)
	}
	prefixLen := r.ReadUint8()
	switch subtype {
	case SUBT_TABLE_DUMP_AFI_IPV4:
		if prefixLen == 32 || prefixLen > 32 {
			prefixLen = 31
		}
		mask = messages.MaskV4[prefixLen]
	case SUBT_TABLE_DUMP_AFI_IPV6:
		if prefixLen == 128 || prefixLen > 128 {
			prefixLen = 127
		}
		mask = messages.MaskV6[prefixLen]
	}
	pfx := net.IPNet{
		IP:   rawPrefix,
		Mask: mask,
	}
	out.Prefix = pfx

	status := r.ReadUint8()
	_ = status
	originUnixTime := r.ReadUint32()
	out.OriginatedTime = time.Unix(int64(originUnixTime), 0)

	switch subtype {
	case SUBT_TABLE_DUMP_AFI_IPV4:
		out.PeerIP = net.IP(r.ReadBytes(4))
	case SUBT_TABLE_DUMP_AFI_IPV6:
		out.PeerIP = net.IP(r.ReadBytes(16))
	}
	out.PeerAS = r.ReadUint16()
	attrlen := r.ReadUint16()
	attrs, err := decodeAttributes2B(r, attrlen)
	if err != nil {
		return out, err
	}
	out.Attributes = attrs
	return out, nil
}

func DecodeBGP4TD2(buf io.Reader, timestamp time.Time, subtype uint16, length uint32) (Mrt, error) {
	if length > MaxMrtLength {
		return nil, fmt.Errorf("BGP4TD2 record length %d exceeds maximum %d", length, MaxMrtLength)
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(buf, content); err != nil {
		return nil, err
	}
	return decodeBGP4TD2(newByteReader(content), timestamp, subtype, length)
}

func decodeBGP4TD2(r *byteReader, timestamp time.Time, subtype uint16, length uint32) (Mrt, error) {
	if length > MaxMrtLength {
		return nil, fmt.Errorf("BGP4TD2 record length %d exceeds maximum %d", length, MaxMrtLength)
	}
	switch subtype {
	case SUBT_TABLE_DUMPV2_PEER_INDEX_TABLE:
		collid := r.ReadBytes(4)
		viewnamelen := r.ReadUint16()
		viewname := r.ReadBytes(int(viewnamelen))
		peercount := r.ReadUint16()

		peers := make([]*Peer, peercount)

		for i := 0; i < int(peercount); i++ {
			peertype := r.ReadUint8()
			bgpid := r.ReadBytes(4)

			sizeip := 4
			sizeasn := 2
			if peertype&0x2 != 0 {
				sizeasn = 4
			}
			if peertype&0x1 != 0 {
				sizeip = 16
			}
			peerip := r.ReadBytes(sizeip)
			tmpasn := r.ReadBytes(sizeasn)

			var asn uint32
			if sizeasn == 2 {
				asn = uint32(binary.BigEndian.Uint16(tmpasn))
			} else {
				asn = binary.BigEndian.Uint32(tmpasn)
			}

			peers[i] = &Peer{
				Id:  bgpid,
				IP:  peerip,
				ASN: asn,
			}
		}

		mrt := &MrtTableDumpV2_PeerIndex{
			Timestamp:   timestamp,
			CollectorId: collid,
			ViewName:    string(viewname),
			Peers:       peers,
		}
		return mrt, nil

	case SUBT_TABLE_DUMPV2_RIB_GENERIC:
		seqnum := r.ReadUint32()
		afi := r.ReadUint16()
		safi := r.ReadUint8()

		nlri, err := decodeNLRI(r, afi, safi)

		mrt := &MrtTableDumpV2_Rib{
			Timestamp:      timestamp,
			Afi:            afi,
			Safi:           safi,
			SequenceNumber: seqnum,
			NLRI:           nlri,
		}
		if err != nil {
			return mrt, err
		}

		entrycount := r.ReadUint16()
		entries := make([]*RibEntry, entrycount)
		var errentry error
		for i := 0; i < int(entrycount); i++ {
			entries[i], errentry = decodeRibEntries(r)
		}
		mrt.RibEntries = entries
		return mrt, errentry
	case SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST:
		return decodeBGP4TD2RIBSpec(r, subtype, timestamp, false)
	case SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST:
		return decodeBGP4TD2RIBSpec(r, subtype, timestamp, false)
	case SUBT_TABLE_DUMPV2_RIB_IPV4_MULTICAST:
		return decodeBGP4TD2RIBSpec(r, subtype, timestamp, false)
	case SUBT_TABLE_DUMPV2_RIB_IPV6_MULTICAST:
		return decodeBGP4TD2RIBSpec(r, subtype, timestamp, false)
	case SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST_ADDPATH:
		return decodeBGP4TD2RIBSpec(r, subtype, timestamp, true)
	case SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST_ADDPATH:
		return decodeBGP4TD2RIBSpec(r, subtype, timestamp, true)
	default:
		return nil, fmt.Errorf("Decoding of subtype %v of BGP4TableDumpV2 not implemented", subtype)
	}
}

const MaxMrtLength = 1 << 20 // 1MB

func DecodeSingle(buf io.Reader) (Mrt, error) {
	var header [12]byte
	if _, err := io.ReadFull(buf, header[:]); err != nil {
		return nil, fmt.Errorf("Decoding of type 0 not implemented")
	}
	timestamp := binary.BigEndian.Uint32(header[0:4])
	mrttype := binary.BigEndian.Uint16(header[4:6])
	mrtsubtype := binary.BigEndian.Uint16(header[6:8])
	mrtlength := binary.BigEndian.Uint32(header[8:12])

	if mrtlength > MaxMrtLength {
		return nil, fmt.Errorf("Decoding of type 0 not implemented")
	}

	timestampP := time.Unix(int64(timestamp), 0)

	content := make([]byte, mrtlength)
	if _, err := io.ReadFull(buf, content); err != nil {
		return nil, fmt.Errorf("Decoding of type 0 not implemented")
	}
	r := newByteReader(content)

	var mrt Mrt
	var err error
	switch mrttype {
	case TYPE_BGP4MP:
		if mrtsubtype == SUBT_BGP4MP_MESSAGE_AS4 || mrtsubtype == SUBT_BGP4MP_STATE_CHANGE_AS4 {
			mrt, err = decodeBGP4MP(r, timestampP, mrtsubtype, mrtlength)
		}
	case TYPE_TABLE_DUMPV2:
		mrt, err = decodeBGP4TD2(r, timestampP, mrtsubtype, mrtlength)
	case TYPE_TABLE_DUMP:
		mrt, err = decodeBGP4TD1(r, timestampP, mrtsubtype, mrtlength)
	default:
		err = fmt.Errorf("Decoding of type %v not implemented", mrttype)
	}

	return mrt, err
}
