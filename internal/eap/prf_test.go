package eap

import (
	"encoding/hex"
	"testing"
)

// TestFIPSPRFAgainstStrongSwanVector uses the test vector documented in
// strongSwan's src/libstrongswan/plugins/fips_prf/fips_prf.c, which is the same
// PRF (PRF_FIPS_SHA1_160) that strongSwan's EAP-AKA implementation selects via
// simaka_crypto_create(). Matching it byte for byte demonstrates that the
// ePDG derives identical EAP-AKA keys to the UE.
func TestFIPSPRFAgainstStrongSwanVector(t *testing.T) {
	key := mustHex(t, "bd029bbe7f51960bcf9edb2b61f06f0feb5a38b6")
	const want = "2070b3223dba372fde1c0ffc7b2e3b49" +
		"8b2606143c6c18bacb0f6c55babb1378" +
		"8e20d737a3275116"

	var xkey [20]byte
	copy(xkey[:], key)

	// One iteration yields x_0 = w_0 | w_1, 320 bits as defined in
	// RFC 4187 Appendix A step 3.3.
	got := fips186PRF(xkey, 1)
	if len(got) != 40 {
		t.Fatalf("one PRF iteration produced %d octets, want 40", len(got))
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("PRF output = %s\nwant            %s", hex.EncodeToString(got), want)
	}
}

// TestFIPSPRFStreamIsPrefixStable verifies that requesting more iterations
// extends the stream without disturbing the earlier octets. This is what makes
// it interoperable with strongSwan, which requests three iterations (120
// octets) while an EMSK needs four (160 octets).
func TestFIPSPRFStreamIsPrefixStable(t *testing.T) {
	key := mustHex(t, "bd029bbe7f51960bcf9edb2b61f06f0feb5a38b6")
	var xkey [20]byte
	copy(xkey[:], key)

	three := fips186PRF(xkey, 3)
	four := fips186PRF(xkey, 4)
	if len(three) != 120 || len(four) != 160 {
		t.Fatalf("unexpected PRF lengths: %d and %d", len(three), len(four))
	}
	if hex.EncodeToString(three) != hex.EncodeToString(four[:120]) {
		t.Error("the first 120 octets differ between a 3 and a 4 iteration derivation")
	}
}

// TestAdd160Carries checks the modular addition used by the PRF.
func TestAdd160Carries(t *testing.T) {
	var a, b [20]byte
	for i := range a {
		a[i] = 0xff
	}
	b[19] = 0x01
	// 0xff..ff + 0x00..01 + 1 == 0x00..01 mod 2^160
	got := add160(a, b)
	if got[19] != 0x01 {
		t.Errorf("add160 wrap produced %x, want a value ending in 01", got)
	}
	for i := 0; i < 19; i++ {
		if got[i] != 0 {
			t.Errorf("add160 wrap left octet %d as %#x, want 00", i, got[i])
		}
	}
}
