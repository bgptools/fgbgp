package messages

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type BGPAttribute_NEXTHOP struct {
	NextHop net.IP
}

type BGPAttribute_ORIGIN struct {
	Origin byte
}

type BGPAttribute_MED struct {
	Med uint32
}

type BGPAttribute_LOCPREF struct {
	LocPref uint32
}

type BGPAttribute_COMMUNITIES struct {
	Communities []uint32
}

type BGPAttribute_LARGECOMMUNITIES struct {
	Communities []LargeCommunity
}

type LargeCommunity struct {
	GlobalAdmin uint32
	LocalData1  uint32
	LocalData2  uint32
}

type ASPath_Segment struct {
	SType  byte
	ASPath []uint32
}

type BGPAttribute_ASPATH struct {
	Segments  []ASPath_Segment
	Enc2Bytes bool
}

type BGPAttribute_MP_UNREACH struct {
	Afi  uint16
	Safi byte
	NLRI []NLRI

	EnableAddPath bool
}

type BGPAttribute_MP_REACH struct {
	Afi     uint16
	Safi    byte
	NextHop net.IP
	NLRI    []NLRI

	EnableAddPath bool
}

type BGPAttribute_ATOMIC_AGGREGATE struct {
}

type BGPAttribute_AGGREGATOR struct {
	ASN        uint32
	Identifier []byte
	Enc2Bytes  bool
}

type BGPAttributeIf SerializableInterface

type BGPAttribute struct {
	Flags byte
	Code  byte
	Data  []byte
}

type BGPMessageUpdate struct {
	BGPMessageHead
	WithdrawnRoutes []NLRI
	PathAttributes  []BGPAttributeIf
	NLRI            []NLRI

	EnableAddPath bool
}

func (m BGPAttribute_ORIGIN) String() string {
	return fmt.Sprintf("Origin: %v", m.Origin)
}

func (m BGPAttribute_AGGREGATOR) String() string {
	id := net.IP(m.Identifier)
	return fmt.Sprintf("Aggregator: ASN: %v / Id: %v", m.ASN, id)
}

func (m BGPAttribute_ATOMIC_AGGREGATE) String() string {
	return "Atomic aggregate"
}

func (m BGPAttribute_MED) String() string {
	return fmt.Sprintf("Med: %v", m.Med)
}

func (m BGPAttribute_LOCPREF) String() string {
	return fmt.Sprintf("LocPref: %v", m.LocPref)
}

func (m BGPAttribute_ASPATH) String() string {
	return fmt.Sprintf("ASPath: %v", m.Segments)
}

func (m ASPath_Segment) String() string {
	return fmt.Sprintf("Segment (type: %v | len: %v): %v", m.SType, len(m.ASPath), m.ASPath)
}

func (m BGPAttribute_COMMUNITIES) String() string {
	var comlist string
	for i := range m.Communities {
		comlist += fmt.Sprintf("%v:%v, ", m.Communities[i]&0xFFFF0000>>16, m.Communities[i]&0xFFFF)
	}

	return fmt.Sprintf("Communities: [ %v]", comlist)
}

func (m BGPAttribute_LARGECOMMUNITIES) String() string {
	sb := strings.Builder{}
	for i := range m.Communities {
		sb.WriteString(fmt.Sprintf("%v:%v:%v, ", m.Communities[i].GlobalAdmin, m.Communities[i].LocalData1, m.Communities[i].LocalData2))
	}

	return fmt.Sprintf("Large Communities: [ %v]", sb.String())
}

func (m BGPAttribute_MP_REACH) String() string {
	var NLRI string
	for i := range m.NLRI {
		NLRI += m.NLRI[i].String() + ", "
	}

	return fmt.Sprintf("MP Reach: %v-%v (%v) (%v) / Nexthop: %v / NLRI: [ %v]", AfiToStr[m.Afi], SafiToStr[m.Safi], m.Afi, m.Safi, m.NextHop, NLRI)
}

func (m BGPAttribute_MP_UNREACH) String() string {
	var NLRI string
	for i := range m.NLRI {
		NLRI += m.NLRI[i].String() + ", "
	}

	return fmt.Sprintf("MP Unreach: %v-%v (%v) (%v) / NLRI: [ %v]", AfiToStr[m.Afi], SafiToStr[m.Safi], m.Afi, m.Safi, NLRI)
}

func (m BGPAttribute_NEXTHOP) String() string {
	return fmt.Sprintf("Nexthop %v", m.NextHop.String())
}

func (m BGPAttribute) String() string {
	str := "%b %v (%v): %v"
	return fmt.Sprintf(str, m.Flags, BgpAttributes[int(m.Code)], m.Code, m.Data)
}

func (m BGPMessageUpdate) String() string {
	// To be completed
	return fmt.Sprintf("BGP Update: Withdraw: %v / PathAttributes: %v / NLRI: %v", m.WithdrawnRoutes, m.PathAttributes, m.NLRI)
}

func (m BGPMessageUpdate) LenWithdrawn() int {
	var sumW int
	for i := range m.WithdrawnRoutes {
		sumW += m.WithdrawnRoutes[i].Len(m.EnableAddPath)
	}
	return sumW
}

func (m BGPMessageUpdate) LenPathAttribute() int {
	var sumPA int
	for i := range m.PathAttributes {
		sumPA += m.PathAttributes[i].Len()
	}
	return sumPA
}

func (m BGPMessageUpdate) LenContent() int {
	sumW := m.LenWithdrawn()
	sumPA := m.LenPathAttribute()

	var sumA int
	for i := range m.NLRI {
		sumA += m.NLRI[i].Len(m.EnableAddPath)
	}

	return 2 + sumW + 2 + sumPA + sumA
}

func (m BGPMessageUpdate) Len() int {
	return GetBGPHeaderLen() + m.LenContent()
}

func (m BGPMessageUpdate) Write(bw io.Writer) {
	WriteBGPHeader(MESSAGE_UPDATE, uint16(m.LenContent()), bw)

	binary.Write(bw, binary.BigEndian, uint16(m.LenWithdrawn()))
	for i := range m.WithdrawnRoutes {
		m.WithdrawnRoutes[i].Write(bw, m.EnableAddPath)
	}

	binary.Write(bw, binary.BigEndian, uint16(m.LenPathAttribute()))
	for i := range m.PathAttributes {
		m.PathAttributes[i].Write(bw)
	}

	for i := range m.NLRI {
		m.NLRI[i].Write(bw, m.EnableAddPath)
	}
}

func (m BGPAttribute_ORIGIN) Len() int {
	return AttributeHeaderLen(1) + 1
}

func (m BGPAttribute_ORIGIN) Write(bw io.Writer) {
	binary.Write(bw, binary.BigEndian, byte(ATTRIBUTE_TRANSITIVE))
	binary.Write(bw, binary.BigEndian, byte(ATTRIBUTE_ORIGIN))
	binary.Write(bw, binary.BigEndian, byte(1))
	binary.Write(bw, binary.BigEndian, m.Origin)
}

func (m BGPAttribute_AGGREGATOR) Len() int {
	return AttributeHeaderLen(8) + 8
}

func (m BGPAttribute_AGGREGATOR) Write(bw io.Writer) {
	// May cause issue as ASN is 32 bits

	binary.Write(bw, binary.BigEndian, byte(ATTRIBUTE_OPTIONAL))
	binary.Write(bw, binary.BigEndian, byte(ATTRIBUTE_AGGREGATOR))
	binary.Write(bw, binary.BigEndian, byte(8))
	binary.Write(bw, binary.BigEndian, m.ASN)
	binary.Write(bw, binary.BigEndian, m.Identifier)
}

func (m BGPAttribute_ATOMIC_AGGREGATE) Len() int {
	return AttributeHeaderLen(0)
}

func (m BGPAttribute_ATOMIC_AGGREGATE) Write(bw io.Writer) {
	WriteAttributeHeader(bw, 0, ATTRIBUTE_OPTIONAL, ATTRIBUTE_ATOMIC_AGGREGATE)
}

func (m BGPAttribute_MED) Len() int {
	return AttributeHeaderLen(4) + 4
}

func (m BGPAttribute_MED) Write(bw io.Writer) {
	binary.Write(bw, binary.BigEndian, byte(ATTRIBUTE_OPTIONAL))
	binary.Write(bw, binary.BigEndian, byte(ATTRIBUTE_MED))
	binary.Write(bw, binary.BigEndian, byte(4))
	binary.Write(bw, binary.BigEndian, m.Med)
}

func (m BGPAttribute_LOCPREF) Len() int {
	return AttributeHeaderLen(4) + 4
}

func (m BGPAttribute_LOCPREF) Write(bw io.Writer) {
	WriteAttributeHeader(bw, 4, ATTRIBUTE_OPTIONAL, ATTRIBUTE_LOCPREF)
	binary.Write(bw, binary.BigEndian, m.LocPref)
}

func (m BGPAttribute_ASPATH) Len() int {
	var size int
	for i := range m.Segments {
		size += m.Segments[i].LenContent(m.Enc2Bytes)
	}
	return AttributeHeaderLen(size) + size
}

func (m BGPAttribute_ASPATH) Write(bw io.Writer) {
	WriteAttributeHeader(bw, m.LenContent(), ATTRIBUTE_TRANSITIVE, ATTRIBUTE_ASPATH)
	if len(m.Segments) == 0 {
		return
	}

	for i := range m.Segments {
		m.Segments[i].Write(bw, m.Enc2Bytes)
	}
}

func (m BGPAttribute_ASPATH) LenContent() int {
	var size int
	for i := range m.Segments {
		size += m.Segments[i].LenContent(m.Enc2Bytes)
	}
	return size
}

func (m ASPath_Segment) LenSets() int {
	aspathlen := len(m.ASPath)
	itera := aspathlen / 0xff
	if aspathlen%0xff != 0 {
		itera += 1
	}
	return itera
}

func (m ASPath_Segment) LenContent(enc2bytes bool) int {
	if len(m.ASPath) == 0 {
		return 0
	}

	numsets := m.LenSets()
	if enc2bytes {
		return 2*numsets + 2*len(m.ASPath)
	}
	return 2*numsets + 4*len(m.ASPath)
}

func (m ASPath_Segment) Write(bw io.Writer, enc2bytes bool) {
	if len(m.ASPath) == 0 {
		return
	}

	itera := m.LenSets()
	var cursetlen byte

	for i := 0; i < itera; i++ {
		cursetlen = 0xff
		if i == itera-1 {
			cursetlen = byte(len(m.ASPath) % 0xff)
		}
		binary.Write(bw, binary.BigEndian, m.SType)
		binary.Write(bw, binary.BigEndian, byte(cursetlen))
		for j := 0xff * i; j < len(m.ASPath) && j < 0xff*(i+1); j++ {
			if enc2bytes {
				binary.Write(bw, binary.BigEndian, uint16(m.ASPath[j]))
			} else {
				binary.Write(bw, binary.BigEndian, m.ASPath[j])
			}
		}
	}
}

func AttributeHeaderLen(size int) int {
	if size > 0xff {
		return 4
	} else {
		return 3
	}
}

func IPtoBytes(ip net.IP) []byte {
	if ip.To4() == nil {
		return ip.To16()
	}
	return ip.To4()
}

func WriteAttributeHeader(bw io.Writer, size int, attrflag byte, attrcode byte) {
	var extended byte
	if size > 0xff {
		extended = ATTRIBUTE_EXTENDED
	}
	binary.Write(bw, binary.BigEndian, byte((attrflag&^ATTRIBUTE_EXTENDED)|extended))
	binary.Write(bw, binary.BigEndian, attrcode)
	if extended != 0 {
		binary.Write(bw, binary.BigEndian, byte((size&0xff00)>>8))
	}
	binary.Write(bw, binary.BigEndian, byte(size&0xff))
}

func (m BGPAttribute_COMMUNITIES) LenContent() int {
	return 4 * len(m.Communities)
}

func (m BGPAttribute_COMMUNITIES) Len() int {
	size := m.LenContent()
	return AttributeHeaderLen(size) + size
}

func (m BGPAttribute_COMMUNITIES) Write(bw io.Writer) {
	WriteAttributeHeader(bw, m.LenContent(), ATTRIBUTE_TRANSITIVEOPT, ATTRIBUTE_COMMUNITIES)
	for i := range m.Communities {
		binary.Write(bw, binary.BigEndian, m.Communities[i])
	}
}

func (m BGPAttribute_LARGECOMMUNITIES) LenContent() int {
	return 12 * len(m.Communities)
}

func (m BGPAttribute_LARGECOMMUNITIES) Len() int {
	size := m.LenContent()
	return AttributeHeaderLen(size) + size
}

func (m BGPAttribute_LARGECOMMUNITIES) Write(bw io.Writer) {
	WriteAttributeHeader(bw, m.LenContent(), ATTRIBUTE_TRANSITIVEOPT, ATTRIBUTE_LARGECOMMUNITIES)
	for i := range m.Communities {
		binary.Write(bw, binary.BigEndian, m.Communities[i])
	}
}

func (m BGPAttribute_MP_REACH) LenMrt() uint16 {
	ip := IPtoBytes(m.NextHop)
	return 2 + 1 + 1 + uint16(len(ip))
}

func (m BGPAttribute_MP_REACH) WriteMrt(buf io.Writer) {
	binary.Write(buf, binary.BigEndian, byte(ATTRIBUTE_OPTIONAL))
	binary.Write(buf, binary.BigEndian, byte(ATTRIBUTE_REACH))

	nhb := IPtoBytes(m.NextHop)
	lengthnh := len(nhb)

	binary.Write(buf, binary.BigEndian, byte(1+lengthnh))
	binary.Write(buf, binary.BigEndian, byte(lengthnh))
	binary.Write(buf, binary.BigEndian, nhb)
}

func (m BGPAttribute_MP_REACH) GetNextHopLen() int {
	return len(IPtoBytes(m.NextHop))
}

func (m BGPAttribute_MP_REACH) ContentLen() int {
	var sum int
	for i := range m.NLRI {
		sum += m.NLRI[i].Len(m.EnableAddPath)
	}

	size := 4 + m.GetNextHopLen() + 1 + sum
	return size
}

func (m BGPAttribute_MP_REACH) Len() int {
	size := m.ContentLen()
	return AttributeHeaderLen(size) + size
}

func (m BGPAttribute_MP_REACH) Write(bw io.Writer) {
	WriteAttributeHeader(bw, m.ContentLen(), ATTRIBUTE_OPTIONAL, ATTRIBUTE_REACH)

	binary.Write(bw, binary.BigEndian, m.Afi)
	binary.Write(bw, binary.BigEndian, m.Safi)
	binary.Write(bw, binary.BigEndian, byte(m.GetNextHopLen()))
	binary.Write(bw, binary.BigEndian, IPtoBytes(m.NextHop))
	binary.Write(bw, binary.BigEndian, byte(0))
	for i := range m.NLRI {
		m.NLRI[i].Write(bw, m.EnableAddPath)
	}
}
func (m BGPAttribute_MP_UNREACH) ContentLen() int {
	var sum int
	for i := range m.NLRI {
		sum += m.NLRI[i].Len(m.EnableAddPath)
	}
	size := 3 + sum
	return size
}

func (m BGPAttribute_MP_UNREACH) Len() int {
	size := m.ContentLen()
	return AttributeHeaderLen(size) + size
}

func (m BGPAttribute_MP_UNREACH) Write(bw io.Writer) {
	WriteAttributeHeader(bw, m.ContentLen(), ATTRIBUTE_OPTIONAL, ATTRIBUTE_UNREACH)

	binary.Write(bw, binary.BigEndian, m.Afi)
	binary.Write(bw, binary.BigEndian, m.Safi)
	for i := range m.NLRI {
		m.NLRI[i].Write(bw, m.EnableAddPath)
	}
}

func (m BGPAttribute_NEXTHOP) ContentLen() int {
	ip := IPtoBytes(m.NextHop)
	return len(ip)
}

func (m BGPAttribute_NEXTHOP) Len() int {
	size := m.ContentLen()
	return AttributeHeaderLen(size) + size
}

func (m BGPAttribute_NEXTHOP) Write(bw io.Writer) {
	WriteAttributeHeader(bw, m.ContentLen(), ATTRIBUTE_TRANSITIVE, ATTRIBUTE_NEXTHOP)

	ip := IPtoBytes(m.NextHop)
	binary.Write(bw, binary.BigEndian, ip)
}

func (m BGPAttribute) Len() int {
	size := len(m.Data)
	return AttributeHeaderLen(size) + size
}

func (m BGPAttribute) Write(bw io.Writer) {
	WriteAttributeHeader(bw, len(m.Data), m.Flags, m.Code)
	binary.Write(bw, binary.BigEndian, m.Data)
}

/*func (m *BGPMessageUpdate) AddASNToPath(asn uint32) {
    for i := range(m.PathAttributes) {
        if v,ok := m.PathAttributes[i].(BGPAttribute_ASPATH); ok {
            v.ASPath = append(v.ASPath, asn)
            m.PathAttributes[i] = v
            return
        }
    }
    m.PathAttributes = append(m.PathAttributes, BGPAttribute_ASPATH{
        SType: 2,
        ASPath: []uint32{asn,},
        })
}*/

func ParseNLRI(b []byte, afi uint16, safi byte, path bool) ([]NLRI, error) {
	if afi != AFI_IPV4 && afi != AFI_IPV6 {
		return nil, fmt.Errorf("ParseNLRI: cannot decode this Afi/Safi %v/%v", afi, safi)
	}

	var masks [][]byte
	asize := 4
	if afi == AFI_IPV6 {
		masks = MaskV6[:]
		asize = 16
	} else {
		masks = MaskV4[:]
	}

	i := 0
	prefixlist := make([]NLRI, 0, len(b)/(1+asize/2))

	for i < len(b) {
		var pathid uint32
		if path {
			if len(b)-i < 5 {
				return nil, fmt.Errorf("ParseNLRI: wrong NLRI size with add-path: %v < 5", len(b))
			}
			pathid = uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
			i += 4
		}

		bits := int(b[i])
		i++
		if bits > len(masks)-1 {
			return prefixlist, fmt.Errorf("ParseNLRI: invalid prefix length %v for afi %v", bits, afi)
		}
		byteLen := bits / 8
		if bits%8 != 0 {
			byteLen++
		}
		if i+byteLen > len(b) {
			return prefixlist, fmt.Errorf("ParseNLRI: wrong NLRI size: %v > %v", i+byteLen, len(b))
		}
		prefix := b[i : i+byteLen]

		ip := make([]byte, asize)
		copy(ip, prefix)
		ipnet := net.IPNet{
			IP:   ip,
			Mask: masks[bits],
		}
		prefixlist = append(prefixlist, NLRI_IPPrefix{
			Prefix: ipnet,
			PathId: pathid,
		})

		i += byteLen
	}
	return prefixlist, nil
}

func ParsePathAttribute(b []byte, addpathlist []AfiSafi, enc2bytes bool) ([]BGPAttributeIf, error) {
	attributes := make([]BGPAttributeIf, 0)
	i := 0
	for i < len(b) {
		if len(b)-i < 3 {
			return attributes, fmt.Errorf("ParsePathAttribute: attribute size (need 3 bytes, got %v)", len(b)-i)
		}
		attrflag := b[i]
		attrcode := b[i+1]
		extended := byte((attrflag & ATTRIBUTE_EXTENDED) >> 4)
		length := int(b[i+2])

		if extended != 0 && i+3 > len(b)-1 {
			return attributes, fmt.Errorf("ParsePathAttribute: wrong extended size: %v > %v", i+3, len(b)-1)
		}

		offset := 0
		if extended != 0 {
			length = int(uint16(b[i+2])<<8 | uint16(b[i+3]))
			offset = 1
		}
		if i+offset+3+length > len(b) || i+offset+3 > len(b) {
			return attributes, fmt.Errorf("ParsePathAttribute: wrong size: %v > %v or %v > %v (ext: %v / %v)", i+offset+3+length, len(b), i+offset+3, len(b), i, extended)
		}

		data := b[i+offset+3 : i+offset+3+length]

		if i+3+offset+length > len(b) {
			return attributes, fmt.Errorf("ParsePathAttribute: wrong attribute size: %v > %v", i+3+length, len(b))
		}

		var intf SerializableInterface

		switch attrcode {
		case ATTRIBUTE_ORIGIN:
			o := byte(2)
			if len(data) > 0 {
				o = data[0]
			} else {
				return attributes, fmt.Errorf("ParsePathAttribute: empty data for ORIGIN attribute")
			}
			a := BGPAttribute_ORIGIN{
				Origin: o,
			}
			intf = a
		case ATTRIBUTE_MED:
			if len(data) < 4 {
				return attributes, fmt.Errorf("ParsePathAttribute: MED data too short")
			}
			a := BGPAttribute_MED{
				Med: uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]),
			}
			intf = a
		case ATTRIBUTE_AGGREGATOR:
			a := BGPAttribute_AGGREGATOR{}
			if len(data) == 8 && !enc2bytes {
				a.ASN = uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
				a.Identifier = data[4:8]
			} else if len(data) == 6 && enc2bytes {
				a.ASN = uint32(uint16(data[0])<<8 | uint16(data[1]))
				a.Identifier = data[2:6]
			}
			a.Enc2Bytes = enc2bytes
			intf = a
		case ATTRIBUTE_ATOMIC_AGGREGATE:
			a := BGPAttribute_ATOMIC_AGGREGATE{}
			intf = a
		case ATTRIBUTE_LOCPREF:
			if len(data) < 4 {
				return attributes, fmt.Errorf("ParsePathAttribute: LOCPREF data too short")
			}
			a := BGPAttribute_LOCPREF{
				LocPref: uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]),
			}
			intf = a
		case ATTRIBUTE_ASPATH:
			a := BGPAttribute_ASPATH{Segments: make([]ASPath_Segment, 0)}
			pos := 0
			for pos < len(data) {
				if pos >= len(data) {
					break
				}
				stype := data[pos]
				pos++
				if pos >= len(data) {
					break
				}
				aslen := data[pos]
				pos++

				s := ASPath_Segment{SType: stype, ASPath: make([]uint32, aslen)}

				if !enc2bytes {
					for j := 0; j < int(aslen) && pos+4 <= len(data); j++ {
						s.ASPath[j] = uint32(data[pos])<<24 | uint32(data[pos+1])<<16 | uint32(data[pos+2])<<8 | uint32(data[pos+3])
						pos += 4
					}
				} else {
					for j := 0; j < int(aslen) && pos+2 <= len(data); j++ {
						s.ASPath[j] = uint32(uint16(data[pos])<<8 | uint16(data[pos+1]))
						pos += 2
					}
				}
				a.Segments = append(a.Segments, s)
			}
			a.Enc2Bytes = enc2bytes
			intf = a
		case ATTRIBUTE_NEXTHOP:
			if len(data) < 4 {
				return nil, fmt.Errorf("ParsePathAttribute: ATTRIBUTE_NEXTHOP corrupted, wrong size (%d expected 4)", len(data))
			}
			intf = BGPAttribute_NEXTHOP{NextHop: data[0:4]}
		case ATTRIBUTE_COMMUNITIES:
			a := BGPAttribute_COMMUNITIES{Communities: make([]uint32, length/4)}
			for j := 0; j < length/4; j++ {
				off := j * 4
				a.Communities[j] = uint32(data[off])<<24 | uint32(data[off+1])<<16 | uint32(data[off+2])<<8 | uint32(data[off+3])
			}
			intf = a
		case ATTRIBUTE_LARGECOMMUNITIES:
			a := BGPAttribute_LARGECOMMUNITIES{Communities: make([]LargeCommunity, length/12)}
			for j := 0; j < length/12; j++ {
				off := j * 12
				a.Communities[j] = LargeCommunity{
					GlobalAdmin: uint32(data[off])<<24 | uint32(data[off+1])<<16 | uint32(data[off+2])<<8 | uint32(data[off+3]),
					LocalData1:  uint32(data[off+4])<<24 | uint32(data[off+5])<<16 | uint32(data[off+6])<<8 | uint32(data[off+7]),
					LocalData2:  uint32(data[off+8])<<24 | uint32(data[off+9])<<16 | uint32(data[off+10])<<8 | uint32(data[off+11]),
				}
			}
			intf = a
		case ATTRIBUTE_REACH:
			a := BGPAttribute_MP_REACH{}
			pos := 0
			if len(data) < 4 {
				return attributes, fmt.Errorf("ParsePathAttribute: MP_REACH data too short (%d bytes)", len(data))
			}
			a.Afi = uint16(data[pos])<<8 | uint16(data[pos+1])
			pos += 2
			a.Safi = data[pos]
			pos++
			nhlen := int(data[pos])
			pos++
			if pos+nhlen > len(data) {
				return attributes, fmt.Errorf("ParsePathAttribute: MP_REACH next hop length %d exceeds data (%d)", nhlen, len(data))
			}
			nh := make([]byte, nhlen)
			copy(nh, data[pos:pos+nhlen])
			a.NextHop = nh
			pos += nhlen
			pos++
			if pos > len(data) {
				return attributes, fmt.Errorf("ParsePathAttribute: MP_REACH no NLRI data after next hop")
			}
			parseinfo := InAfiSafi(a.Afi, a.Safi, addpathlist)
			a.NLRI, _ = ParseNLRI(data[pos:], a.Afi, a.Safi, parseinfo)
			a.EnableAddPath = parseinfo
			intf = a
		case ATTRIBUTE_UNREACH:
			a := BGPAttribute_MP_UNREACH{}
			pos := 0
			if len(data) < 3 {
				return attributes, fmt.Errorf("ParsePathAttribute: MP_UNREACH data too short (%d bytes)", len(data))
			}
			a.Afi = uint16(data[pos])<<8 | uint16(data[pos+1])
			pos += 2
			a.Safi = data[pos]
			pos++
			parseinfo := InAfiSafi(a.Afi, a.Safi, addpathlist)
			a.NLRI, _ = ParseNLRI(data[pos:], a.Afi, a.Safi, parseinfo)
			intf = a
		default:
			intf = BGPAttribute{
				attrflag,
				attrcode,
				data,
			}
		}

		attributes = append(attributes, intf)

		i += 3 + length + offset
	}
	return attributes, nil
}

func ParseUpdate(b []byte, addpathlist []AfiSafi, enc2bytes bool) (*BGPMessageUpdate, error) {
	m := &BGPMessageUpdate{}
	var err error

	addpath_ipv4uni := InAfiSafi(AFI_IPV4, SAFI_UNICAST, addpathlist)
	m.EnableAddPath = addpath_ipv4uni

	if len(b) < 4 {
		return nil, fmt.Errorf("ParseUpdate: wrong withdrawn routes size: %v < 4", len(b))
	}

	wdrouteslen := int(uint16(b[0])<<8 | uint16(b[1]))

	if wdrouteslen+4 > len(b) {
		return nil, fmt.Errorf("ParseUpdate: wrong withdrawn routes size: %v > %v", wdrouteslen+4, len(b))
	}
	offset := 2
	withdrawnroutes := b[offset : offset+wdrouteslen]
	m.WithdrawnRoutes, err = ParseNLRI(withdrawnroutes, AFI_IPV4, SAFI_UNICAST, addpath_ipv4uni)
	if err != nil {
		return nil, err
	}
	offset += wdrouteslen

	tplen := int(uint16(b[offset])<<8 | uint16(b[offset+1]))
	offset += 2

	if tplen+offset > len(b) {
		return nil, fmt.Errorf("ParseUpdate: wrong total path size: %v > %v", tplen+offset, len(b))
	}
	pathattributes := b[offset : offset+tplen]
	m.PathAttributes, err = ParsePathAttribute(pathattributes, addpathlist, enc2bytes)
	if err != nil {
		return m, err
	}

	offset += tplen
	NLRI := b[offset:]
	m.NLRI, err = ParseNLRI(NLRI, AFI_IPV4, SAFI_UNICAST, addpath_ipv4uni)
	if err != nil {
		return m, err
	}

	return m, nil
}

func CraftUpdateMessage() *BGPMessageUpdate {
	//_, prefix, _ := net.ParseCIDR("8.8.8.8/24")

	_, prefixtest, _ := net.ParseCIDR("2001::/46")
	ip := net.ParseIP("2002::1")
	pa := []BGPAttributeIf{
		BGPAttribute_ORIGIN{
			Origin: 2,
		},
		BGPAttribute_ASPATH{
			Segments: []ASPath_Segment{ASPath_Segment{ASPath: []uint32{65001}}},
		},
		BGPAttribute_COMMUNITIES{
			Communities: []uint32{0x7b0929},
		},
		//BGPAttribute_NEXTHOP{
		//    NextHop: []byte{1,2,3,4},
		//},
		BGPAttribute_MP_REACH{
			Afi:     AFI_IPV6,
			Safi:    SAFI_UNICAST,
			NextHop: ip,
			//enableAddPath: true,
			NLRI: []NLRI{
				NLRI_IPPrefix{
					PathId: uint32(time.Now().UTC().Unix()),
					Prefix: *prefixtest,
				},
			},
		},
	}

	m := &BGPMessageUpdate{
		//NLRI: []NLRI{NLRI{Prefix: *prefix,PathId:123,},},
		PathAttributes: pa,
	}

	return m
}
