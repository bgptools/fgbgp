package mrt

import (
	"encoding/binary"
	"io"
)

type byteReader struct {
	b   []byte
	pos int
	err error
}

func newByteReader(b []byte) *byteReader {
	return &byteReader{b: b, pos: 0}
}

func (r *byteReader) Len() int {
	return len(r.b) - r.pos
}

func (r *byteReader) Ok() bool {
	return r.err == nil
}

func (r *byteReader) ReadUint8() byte {
	if r.err != nil {
		return 0
	}
	if r.pos+1 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *byteReader) ReadUint16() uint16 {
	if r.err != nil {
		return 0
	}
	if r.pos+2 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *byteReader) ReadUint32() uint32 {
	if r.err != nil {
		return 0
	}
	if r.pos+4 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

func (r *byteReader) ReadBytes(n int) []byte {
	v := make([]byte, n)
	if r.err != nil {
		return v
	}
	if r.pos+n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return v
	}
	copy(v, r.b[r.pos:r.pos+n])
	r.pos += n
	return v
}

func (r *byteReader) Remaining() []byte {
	return r.b[r.pos:]
}
