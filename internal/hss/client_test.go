package hss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, baseURL, resync string) *Client {
	t.Helper()
	return New(baseURL,
		"/auc/aka/vector_count/1/imsi/{imsi}",
		resync,
		"/oam/ping", 2*time.Second)
}

// TestResyncBuildsExpectedPath checks that the SQN resynchronisation request is
// addressed to the PyHSS endpoint
// /auc/aka/resync/imsi/<imsi>/auts/<auts>/rand/<rand> (RFC 4187 section 10.6,
// 3GPP TS 29.272 section 7.2.5).
func TestResyncBuildsExpectedPath(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_, _ = w.Write([]byte(`{"result": "ok"}`))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL, "/auc/aka/resync/imsi/{imsi}/auts/{auts}/rand/{rand}")
	auts := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd}
	rand := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	if err := c.Resync(context.Background(), "001010000000001", auts, rand); err != nil {
		t.Fatalf("Resync: %v", err)
	}
	const want = "/auc/aka/resync/imsi/001010000000001/auts/00112233445566778899aabbccdd/rand/deadbeef000102030405060708090a0b"
	if gotMethod != http.MethodGet || gotPath != want {
		t.Errorf("resync request = %s %s, want GET %s", gotMethod, gotPath, want)
	}
}

func TestResyncRejectsMissingConfiguration(t *testing.T) {
	c := testClient(t, "http://127.0.0.1:1", "")
	if err := c.Resync(context.Background(), "001010000000001", []byte{1}, []byte{2}); err == nil {
		t.Error("Resync accepted an empty resync path template")
	}
	if err := c.Resync(context.Background(), "001010000000001", nil, []byte{2}); err == nil {
		t.Error("Resync accepted an empty AUTS")
	}
}

func TestResyncPropagatesHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "/auc/aka/resync/imsi/{imsi}/auts/{auts}/rand/{rand}")
	err := c.Resync(context.Background(), "001010000000001", []byte{1}, []byte{2})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("Resync error = %v, want an HTTP 500 error", err)
	}
}

// TestVectorParsesAKAArray checks the quintuplet decoding used on the AKA
// endpoint, which returns a JSON array.
func TestVectorParsesAKAArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"rand":"00112233445566778899aabbccddeeff",` +
			`"autn":"ffeeddccbbaa99887766554433221100",` +
			`"xres":"0102030405060708",` +
			`"ck":"11111111111111111111111111111111",` +
			`"ik":"22222222222222222222222222222222"}]`))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL, "")
	v, err := c.Vector(context.Background(), "001010000000001")
	if err != nil {
		t.Fatalf("Vector: %v", err)
	}
	if len(v.RAND) != 16 || len(v.AUTN) != 16 || len(v.XRES) != 8 || len(v.CK) != 16 || len(v.IK) != 16 {
		t.Errorf("decoded vector has wrong field lengths: %+v", v)
	}
}
