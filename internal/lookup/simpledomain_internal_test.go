package lookup

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLowerASCII64_allBytesAndLanes(t *testing.T) {
	t.Parallel()

	for b := range 256 {
		wantByte := byte(b)
		if wantByte >= 'A' && wantByte <= 'Z' {
			wantByte += 'a' - 'A'
		}

		// Test every byte value in every one of the 8 lanes, surrounded by
		// high-bit and boundary bytes to catch any cross-lane carry.
		for lane := range 8 {
			in := uint64(0xff807f5b5a414000)
			shift := uint(lane * 8)
			in = (in &^ (0xff << shift)) | (uint64(b) << shift)

			got := lowerASCII64(in)
			gotByte := byte(got >> shift)
			assert.Equalf(t, wantByte, gotByte, "byte=0x%02x lane=%d", b, lane)
		}
	}
}

func TestHashDomain_bytesStringParity(t *testing.T) {
	t.Parallel()

	// Exercise all length buckets (0..255) with mixed ASCII case and non-ASCII
	// bytes to verify hashDomainBytes == hashDomainString == lowercased hash.
	for n := range 256 {
		buf := make([]byte, n)
		for i := range n {
			switch i % 5 {
			case 0:
				buf[i] = byte('A' + (i+n)%26)
			case 1:
				buf[i] = byte('a' + (i+n)%26)
			case 2:
				buf[i] = byte('0' + (i+n)%10)
			case 3:
				buf[i] = '.'
			default:
				buf[i] = byte(0x80 + (i+n)%0x7f)
			}
		}

		lower := make([]byte, n)
		for i, c := range buf {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			lower[i] = c
		}

		hb := hashDomainBytes(buf)
		hs := hashDomainString(string(buf))
		hl := hashDomainBytes(lower)

		assert.Equalf(t, hb, hs, "len=%d bytes vs string mismatch", n)
		assert.Equalf(t, hl, hb, "len=%d case-folding mismatch", n)
	}
}
