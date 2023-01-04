package mrt

import (
	"compress/bzip2"
	"embed"
	"fmt"
	"log"
	"testing"
)

//go:embed *.bz2
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
