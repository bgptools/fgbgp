//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func main() {
	fh, err := os.Open("ben-v6.mrt.gz")
	if err != nil {
		panic(err)
	}
	defer fh.Close()

	gr, err := gzip.NewReader(fh)
	if err != nil {
		panic(err)
	}

	allData, err := io.ReadAll(gr)
	if err != nil {
		panic(err)
	}

	r := bytes.NewReader(allData)
	var recordCount, bgp4MpCount, updateCount, openCount int

	for r.Len() > 0 {
		var timestamp uint32
		var mrttype uint16
		var mrtsubtype uint16
		var mrtlength uint32

		if err := binary.Read(r, binary.BigEndian, &timestamp); err != nil {
			break
		}
		binary.Read(r, binary.BigEndian, &mrttype)
		binary.Read(r, binary.BigEndian, &mrtsubtype)
		binary.Read(r, binary.BigEndian, &mrtlength)

		if mrtlength == 0 || mrtlength > 1<<20 {
			io.CopyN(io.Discard, r, int64(mrtlength))
			continue
		}

		content := make([]byte, mrtlength)
		io.ReadFull(r, content)

		recordCount++

		if mrttype == 16 && mrtsubtype == 4 { // BGP4MP_AS4
			bgp4MpCount++
			// Read BGP message from BGP4MP body
			br := bytes.NewReader(content)
			var peeras, localas uint32
			var ifaceindex, afi uint16
			binary.Read(br, binary.BigEndian, &peeras)
			binary.Read(br, binary.BigEndian, &localas)
			binary.Read(br, binary.BigEndian, &ifaceindex)
			binary.Read(br, binary.BigEndian, &afi)
			sizeip := 4
			if afi == 2 {
				sizeip = 16
			}
			peerip := make([]byte, sizeip)
			localip := make([]byte, sizeip)
			binary.Read(br, binary.BigEndian, peerip)
			binary.Read(br, binary.BigEndian, localip)

			bgpMsg, _ := io.ReadAll(br)
			if len(bgpMsg) < 19 {
				continue
			}

			msgType := bgpMsg[18]
			if msgType == 2 {
				updateCount++
				if updateCount <= 5 {
					fmt.Printf("// MRT BGP4MP UPDATE #%d - full MRT record (len=%d)\n", updateCount, len(content)+12)
					var hdrBuf bytes.Buffer
					binary.Write(&hdrBuf, binary.BigEndian, timestamp)
					binary.Write(&hdrBuf, binary.BigEndian, mrttype)
					binary.Write(&hdrBuf, binary.BigEndian, mrtsubtype)
					binary.Write(&hdrBuf, binary.BigEndian, mrtlength)
					hdrBuf.Write(content)
					record := hdrBuf.Bytes()
					fmt.Printf("mrtRecord%d := []byte{", updateCount)
					for i, b := range record {
						if i > 0 {
							fmt.Printf(", ")
						}
						fmt.Printf("0x%02x", b)
					}
					fmt.Println("}")

					fmt.Printf("// BGP UPDATE message body (without 19-byte header)\n")
					fmt.Printf("updateBody%d := []byte{", updateCount)
					for i, b := range bgpMsg[19:] {
						if i > 0 {
							fmt.Printf(", ")
						}
						fmt.Printf("0x%02x", b)
					}
					fmt.Println("}")

					fmt.Printf("// Full BGP UPDATE message (with header)\n")
					fmt.Printf("updateFull%d := []byte{", updateCount)
					for i, b := range bgpMsg {
						if i > 0 {
							fmt.Printf(", ")
						}
						fmt.Printf("0x%02x", b)
					}
					fmt.Println("}")
					fmt.Println()
				}
			} else if msgType == 1 {
				openCount++
				if openCount <= 2 {
					fmt.Printf("// BGP OPEN message (with header)\n")
					fmt.Printf("openFull%d := []byte{", openCount)
					for i, b := range bgpMsg {
						if i > 0 {
							fmt.Printf(", ")
						}
						fmt.Printf("0x%02x", b)
					}
					fmt.Println("}")
					fmt.Println()
				}
			}
		}
	}

	fmt.Printf("// Summary: %d total records, %d BGP4MP, %d UPDATE, %d OPEN\n", recordCount, bgp4MpCount, updateCount, openCount)
}
