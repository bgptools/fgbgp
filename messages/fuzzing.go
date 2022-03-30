package messages

func Fuzz(blob []byte) int {

	bgptype, _, err := ParsePacketHeader(blob)
	if err == nil {
		if bgptype == MESSAGE_UPDATE {
			_, err1 := ParseUpdate(blob[16+3:], nil, false)
			_, err2 := ParseUpdate(blob[16+3:], []AfiSafi{AfiSafi{1, 1}}, false)
			_, err3 := ParseUpdate(blob[16+3:], []AfiSafi{AfiSafi{2, 2}}, false)
			if err1 == nil || err2 == nil || err3 == nil {
				return 1
			}

			return 0
		} else if bgptype == MESSAGE_OPEN {
			pkt, err := ParseOpen(blob[16+3:])
			if err != nil {
				return 0
			}
			pkt.Len()
			return 1
		} else if bgptype == MESSAGE_NOTIFICATION {
			_, err := ParseNotification(blob[16:])
			if err != nil {
				return 0
			}
			return 1

		} else {
			return 0
		}

	}
	return 0
}
