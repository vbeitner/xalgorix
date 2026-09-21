package reporting

import (
	"io"
	"strings"
	"testing"
)

func TestOWASPReportRenders(t *testing.T) {
	scan := &Scan{
		ID:     "test-123",
		Target: "https://example.com",
		Vulns: []Vuln{
			{Title: "SQL Injection in /login", Severity: "Critical", Endpoint: "/login", Description: "desc", Verified: true, VerificationMethod: "PoC", OWASP: "A03:2021"},
			{Title: "XSS in comment field", Severity: "High", Endpoint: "/comments", OWASP: "A03"},
			{Title: "Unrelated finding", Severity: "Medium", OWASP: "NOT-A-CATEGORY"},
			{Title: "No tag at all", Severity: "Low"},
		},
	}
	r, err := DownloadOWASPReport(scan)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	b, _ := io.ReadAll(r)
	s := string(b)
	for _, want := range []string{
		"OWASP Top 10",
		"SQL Injection",          // :2021 suffix normalized into A03 bucket
		"Verified via POC",
		"UNVERIFIED",
		"Other Findings",        // unmatched section rendered
		"Unrelated finding",     // not silently dropped
		"No tag at all",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Count(s, "Verified via POC") != 1 {
		t.Errorf("expected exactly one verified finding, got %d", strings.Count(s, "Verified via POC"))
	}
}
