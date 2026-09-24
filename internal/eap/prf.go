package eap

import (
	"crypto/sha1"
	"encoding/binary"
	"math/bits"
)

// This file implements the pseudo-random function referenced by RFC 4187
// section 7 and reproduced in RFC 4187 Appendix A. It is the SHA-1 based PRF
// from FIPS 186-2 change notice 1 (Algorithm 1, with the "mod q" term
// omitted); the crucial difference from plain SHA-1 is that the function G
// applies only the compression function to a single block, without the usual
// Merkle-Damgard length padding.

// fips186PRF derives m 320-bit outputs x_0..x_{m-1} from a 160-bit seed.
// Each x_j is the concatenation w_0 | w_1 as described in RFC 4187
// Appendix A step 3.2.
func fips186PRF(xkey [20]byte, m int) []byte {
	out := make([]byte, 0, m*40)
	for j := 0; j < m; j++ {
		w0 := sha1BlockCompress(xkey)
		xkey = add160(xkey, w0)
		w1 := sha1BlockCompress(xkey)
		xkey = add160(xkey, w1)
		out = append(out, w0[:]...)
		out = append(out, w1[:]...)
	}
	return out
}

// sha1BlockCompress applies the SHA-1 compression function to one 512-bit
// block built from c followed by 44 zero octets, starting from the standard
// SHA-1 initial hash value. RFC 4187 Appendix A names this G(t, XVAL).
func sha1BlockCompress(c [20]byte) [20]byte {
	var block [64]byte
	copy(block[:], c[:])

	h := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}

	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
	}
	for i := 16; i < 80; i++ {
		w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
	}

	a, b, cc, d, e := h[0], h[1], h[2], h[3], h[4]
	for i := 0; i < 80; i++ {
		var f, k uint32
		switch {
		case i < 20:
			f = (b & cc) | (^b & d)
			k = 0x5A827999
		case i < 40:
			f = b ^ cc ^ d
			k = 0x6ED9EBA1
		case i < 60:
			f = (b & cc) | (b & d) | (cc & d)
			k = 0x8F1BBCDC
		default:
			f = b ^ cc ^ d
			k = 0xCA62C1D6
		}
		tmp := bits.RotateLeft32(a, 5) + f + e + k + w[i]
		e = d
		d = cc
		cc = bits.RotateLeft32(b, 30)
		b = a
		a = tmp
	}
	h[0] += a
	h[1] += b
	h[2] += cc
	h[3] += d
	h[4] += e

	var out [20]byte
	binary.BigEndian.PutUint32(out[0:], h[0])
	binary.BigEndian.PutUint32(out[4:], h[1])
	binary.BigEndian.PutUint32(out[8:], h[2])
	binary.BigEndian.PutUint32(out[12:], h[3])
	binary.BigEndian.PutUint32(out[16:], h[4])
	return out
}

// add160 computes (x + y + 1) mod 2^160, matching RFC 4187 Appendix A
// step 3.2.c.
func add160(x, y [20]byte) [20]byte {
	var out [20]byte
	carry := uint32(1)
	for i := 19; i >= 0; i-- {
		sum := uint32(x[i]) + uint32(y[i]) + carry
		out[i] = byte(sum)
		carry = sum >> 8
	}
	return out
}

// deriveMK computes MK = SHA1(Identity | IK | CK) per RFC 4187 section 7.
func deriveMK(identity string, ik, ck []byte) [20]byte {
	h := sha1.New()
	h.Write([]byte(identity))
	h.Write(ik)
	h.Write(ck)
	var mk [20]byte
	copy(mk[:], h.Sum(nil))
	return mk
}
