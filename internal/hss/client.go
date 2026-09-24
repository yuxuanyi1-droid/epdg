// Package hss retrieves AKA authentication vectors from PyHSS. The ePDG is the
// SWm/EAP-AKA server, so it needs at least one quintuplet (RAND, AUTN, XRES, CK,
// IK) per authentication attempt. PyHSS exposes the full quintuplet through its
// AKA endpoint; the SWm flavoured endpoint omits CK and IK and is therefore not
// sufficient to derive the EAP-AKA MSK.
package hss

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Vector is a full AKA quintuplet as delivered by the HSS.
type Vector struct {
	RAND []byte
	AUTN []byte
	XRES []byte
	CK   []byte
	IK   []byte
}

// Client talks to the PyHSS REST API.
type Client struct {
	baseURL            string
	vectorPathTemplate string
	oamPingPath        string
	http               *http.Client
}

// New builds a client. vectorPathTemplate must contain an {imsi} placeholder
// and may contain a {plmn} placeholder.
func New(baseURL, vectorPathTemplate, oamPingPath string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		baseURL:            strings.TrimRight(baseURL, "/"),
		vectorPathTemplate: vectorPathTemplate,
		oamPingPath:        oamPingPath,
		http:               &http.Client{Timeout: timeout},
	}
}

// oamPing is the shape of the /oam/ping response, which PyHSS renders as a map.
type oamPing map[string]any

// Ping verifies that the HSS API is reachable and answering.
func (c *Client) Ping(ctx context.Context) error {
	body, status, err := c.get(ctx, c.oamPingPath)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("hss: %s returned HTTP %d: %s", c.oamPingPath, status, truncate(body))
	}
	var probe oamPing
	if err := json.Unmarshal(body, &probe); err != nil {
		return fmt.Errorf("hss: %s did not return a JSON object: %w", c.oamPingPath, err)
	}
	return nil
}

// akaVectorJSON mirrors the JSON emitted by PyHSS for an AKA quintuplet.
type akaVectorJSON struct {
	RAND string `json:"rand"`
	AUTN string `json:"autn"`
	XRES string `json:"xres"`
	CK   string `json:"ck"`
	IK   string `json:"ik"`
}

// Vector requests one authentication quintuplet for the given IMSI.
func (c *Client) Vector(ctx context.Context, imsi string) (*Vector, error) {
	if imsi == "" {
		return nil, errors.New("hss: imsi is required")
	}
	path := strings.ReplaceAll(c.vectorPathTemplate, "{imsi}", url.PathEscape(imsi))
	path = strings.ReplaceAll(path, "{plmn}", url.PathEscape(plmnFromIMSI(imsi)))

	body, status, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("hss: %s returned HTTP %d: %s", path, status, truncate(body))
	}

	// PyHSS returns a JSON array for the AKA endpoint and an object carrying a
	// "vectors" member for the SWm flavoured endpoint. Accept both.
	var list []akaVectorJSON
	if err := json.Unmarshal(body, &list); err != nil {
		var single akaVectorJSON
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			var wrapper struct {
				Vectors []akaVectorJSON `json:"vectors"`
			}
			if err3 := json.Unmarshal(body, &wrapper); err3 != nil || len(wrapper.Vectors) == 0 {
				return nil, fmt.Errorf("hss: cannot decode AKA vector from %s: %w", path, err)
			}
			list = wrapper.Vectors
		} else {
			list = []akaVectorJSON{single}
		}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("hss: %s returned an empty vector list", path)
	}
	return decodeVector(list[0])
}

func decodeVector(raw akaVectorJSON) (*Vector, error) {
	v := &Vector{}
	for _, f := range []struct {
		name string
		in   string
		want int
		out  *[]byte
	}{
		{"rand", raw.RAND, 16, &v.RAND},
		{"autn", raw.AUTN, 16, &v.AUTN},
		{"xres", raw.XRES, 8, &v.XRES},
		{"ck", raw.CK, 16, &v.CK},
		{"ik", raw.IK, 16, &v.IK},
	} {
		if f.in == "" {
			return nil, fmt.Errorf("hss: AKA vector is missing the %s field", f.name)
		}
		b, err := hex.DecodeString(f.in)
		if err != nil {
			return nil, fmt.Errorf("hss: AKA vector field %s is not hex: %w", f.name, err)
		}
		if len(b) != f.want {
			return nil, fmt.Errorf("hss: AKA vector field %s is %d octets, want %d", f.name, len(b), f.want)
		}
		*f.out = b
	}
	return v, nil
}

func (c *Client) get(ctx context.Context, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("hss: cannot build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("hss: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("hss: cannot read response from %s: %w", path, err)
	}
	return body, resp.StatusCode, nil
}

// plmnFromIMSI derives the home PLMN from the IMSI prefix. PyHSS ignores the
// value for the AKA endpoint but requires the path segment to exist.
func plmnFromIMSI(imsi string) string {
	if len(imsi) >= 6 {
		return imsi[:6]
	}
	return imsi
}

func truncate(b []byte) string {
	const max = 256
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
