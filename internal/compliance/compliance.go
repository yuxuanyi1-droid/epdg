// Package compliance produces the readiness report exposed by the management
// API. Each item exercises a real dependency rather than a stub.
package compliance

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Item is one readiness check result.
type Item struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// Report is the aggregated readiness report.
type Report struct {
	Profile string `json:"profile"`
	Passed  bool   `json:"passed"`
	NodeID  string `json:"node_id"`
	Items   []Item `json:"items"`
}

// New assembles a report from individual items.
func New(nodeID, profile string, items []Item) *Report {
	passed := true
	for _, item := range items {
		if !item.Passed {
			passed = false
			break
		}
	}
	return &Report{Profile: profile, NodeID: nodeID, Passed: passed, Items: items}
}

// TCPDial checks that a TCP endpoint accepts connections.
func TCPDial(ctx context.Context, address string, timeout time.Duration) Item {
	name := "tcp " + address
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return Item{Name: name, Passed: false, Details: err.Error()}
	}
	conn.Close()
	return Item{Name: name, Passed: true, Details: "reachable"}
}

// Check is a named readiness probe.
type Check struct {
	Name string
	Run  func(ctx context.Context) error
}

// Run executes every check in order.
func Run(ctx context.Context, checks []Check) []Item {
	items := make([]Item, 0, len(checks))
	for _, c := range checks {
		if err := c.Run(ctx); err != nil {
			items = append(items, Item{Name: c.Name, Passed: false, Details: err.Error()})
			continue
		}
		items = append(items, Item{Name: c.Name, Passed: true, Details: "ok"})
	}
	return items
}

// JoinDetails renders a details string from parts, trimming empty entries.
func JoinDetails(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "; ")
}

// Errorf is a small helper keeping error text consistent.
func Errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
