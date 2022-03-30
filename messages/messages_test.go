package messages

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestAddPathWrite(t *testing.T) {
	a := BGPCapability_ADDPATH{
		AddPathList: []AddPath{
			{
				Afi:  1,
				Safi: 1,
				TxRx: 2,
			},
			{
				Afi:  2,
				Safi: 1,
				TxRx: 2,
			},
		},
	}

	buf := &bytes.Buffer{}
	a.Write(buf)

	expected := "\x45\x08\x00\x01\x01\x02\x00\x02\x01\x02"

	if !bytes.Equal(buf.Bytes(), []byte(expected)) {
		t.FailNow()
	}
}

func TestDecode(t *testing.T) {
	blob := []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\x00\x3a\x02\x00\x00\x00\x1f\x40\x01\x01\x00\x40\x02\x0a\x02\x02" +
		"\x00\x00\x88\x26\x00\x00\xba\xdc\x40\x03\x04\x02\x38\x0b\x01\xc0" +
		"\x08\x04\x88\x26\x03\xe9\x16\xb9\xa1\x58")

	if Fuzz(blob) != 1 {
		t.FailNow()
	}
}

func Test4ByteASNOpen(t *testing.T) {
	blob := []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\x00\x3b\x01\x04\x5b\xa0\x00\xf0\x67\x69\x31\x64\x1e\x02\x1c\x01" +
		"\x04\x00\x01\x00\x01\x01\x04\x00\x02\x00\x01\x02\x00\x40\x02\x00" +
		"\x78\x41\x04\x00\x03\x28\x4c\x46\x00\x47\x00")

	if Fuzz(blob) != 1 {
		t.FailNow()
	}
}

func TestBadATTRIBUTE_NEXTHOPDecode(t *testing.T) {
	blob := []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x000\x02\x00" +
		"\x00\x00#\x000\x040000\xe00\x04000000\x00" +
		"\x010\x000\x040000\x010\x00\x000\x00\x8c\x03\x00")

	if Fuzz(blob) != 0 {
		t.FailNow()
	}
}

func TestBadCapLengthDecode(t *testing.T) {
	blob := []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x000\x010" +
		"00000000a000000\x0200X0" +
		"00000000000000000000" +
		"00000000000000000000" +
		"00000000000000000000" +
		"00000000000000000000" +
		"000000")

	if Fuzz(blob) != 0 {
		t.FailNow()
	}
}

func TestBadDecode(t *testing.T) {
	blob := []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x000\x010" +
		"00000000\b0\x00\x02\x030\x0300")

	if Fuzz(blob) != 0 {
		t.FailNow()
	}
	// return 0
}

func TestBlatEntireCorpus(t *testing.T) {
	files, err := os.ReadDir("./corpus")
	if err != nil {
		return
	}

	for _, v := range files {
		b, err := os.ReadFile(fmt.Sprintf("./corpus/%s", v.Name()))
		if err == nil {
			Fuzz(b)
		}
	}

	// return 0

}

func TestBlatEntireCrashers(t *testing.T) {
	files, err := os.ReadDir("./crashers")
	if err != nil {
		return
	}

	for _, v := range files {
		b, err := os.ReadFile(fmt.Sprintf("./crashers/%s", v.Name()))
		if err == nil {
			Fuzz(b)
		}
	}

	// return 0

}
