package mrt

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"embed"
	"fmt"
	"log"
	"testing"
	"time"
)

//go:embed *.bz2 *.gz
var testData embed.FS

func TestTDv1(t *testing.T) {
	uf, _ := testData.Open("rib.20030503.1429.bz2")
	f := bzip2.NewReader(uf)

	for {
		record, err := DecodeSingle(f)
		if err != nil {
			log.Printf("Stopping now due to %s", err.Error())
			if err.Error() != "Decoding of type 0 not implemented" {
				t.FailNow()
			}
			break
		}

		switch rtype := record.(type) {
		case MrtTableDumpV1_Rib:
			a := record.(MrtTableDumpV1_Rib)
			log.Printf("%v", a.Prefix.String())
		default:
			fmt.Printf("I don't know about type %T!\n", rtype)
			t.FailNow()
		}
	}

}

func TestBenV6(t *testing.T) {
	f, err := testData.Open("ben-v6.mrt.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

	var count int
	for {
		record, err := DecodeSingle(gr)
		if err != nil {
			break
		}
		count++
		switch record.(type) {
		case *MrtBGP4MP_Msg_AS4:
		default:
			t.Fatalf("unexpected record type at record %d", count)
		}
	}
	if count != 5344 {
		t.Fatalf("expected 5344 records, got %d", count)
	}
}

func TestDecodeBGP4MP_SliceBounds(t *testing.T) {
	blob := []byte{0x00, 0x00, 0xfb, 0xf4, 0x00, 0x00, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x27, 0x01, 0x04, 0xfd, 0xe9, 0x00, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x02, 0x08, 0x41, 0x04, 0x00, 0x00, 0xfd, 0xe9, 0x02, 0x00}
	r := bytes.NewReader(blob)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := DecodeBGP4MP(r, now, SUBT_BGP4MP_MESSAGE_AS4, uint32(len(blob)))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
