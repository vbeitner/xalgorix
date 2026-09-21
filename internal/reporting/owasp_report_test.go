package reporting

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testOWASPScan() *Scan {
	return &Scan{
		ID:     "SCAN-TEST-1",
		Target: "https://example.com",
		Vulns: []Vuln{
			{Title: "Reflected XSS in /search", Severity: "High", Description: "User input reflected in <script> tag", Endpoint: "/search", CWE: "CWE-79"},
			{Title: "SQL Injection in login", Severity: "Critical", Description: "Error-based sql injection via username", OWASP: "A03"},
			{Title: "Broken Access Control in admin", Severity: "Medium", Description: "IDOR allows unauthorized access to other users' data", CWE: "CWE-639"},
			{Title: "SSRF via webhook <script>alert(1)</script>", Severity: "High", Description: "server-side request forgery to internal metadata endpoint", CWE: "CWE-918"},
			{Title: "Mystery finding", Severity: "Info", Description: "No recognizable class"},
		},
	}
}

func TestGenerateOWASPReportGroupsAndEscapes(t *testing.T) {
	scan := testOWASPScan()
	dir := t.TempDir()
	out := filepath.Join(dir, "owasp.html")

	path, err := GenerateOWASPReport(scan, out)
	if err != nil {
		t.Fatalf("GenerateOWASPReport: %v", err)
	}
	if path != out {
		t.Fatalf("expected path %q, got %q", out, path)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	body := string(data)

	// Grouping: XSS->A03, SQLi->A03, IDOR->A01, SSRF->A10
	for _, want := range []string{"A01", "A03", "A10", "Broken Access Control", "Injection", "Server-Side Request Forgery"} {
		if !strings.Contains(body, want) {
			t.Errorf("report missing expected content %q", want)
		}
	}
	// Injection count should be 2 (XSS + SQLi)
	if !strings.Contains(body, "2 finding(s)") {
		t.Errorf("expected a category with 2 findings (A03)")
	}
	// Unmatched finding must not leak into any category; total = 5
	if !strings.Contains(body, "5") {
		t.Errorf("expected total findings 5 in summary")
	}
	// HTML escaping: raw script tag from title must not survive
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("raw <script> from title not escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("expected escaped title in report")
	}
}

func TestDownloadOWASPReportStreams(t *testing.T) {
	scan := testOWASPScan()
	reader, err := DownloadOWASPReport(scan)
	if err != nil {
		t.Fatalf("DownloadOWASPReport: %v", err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "OWASP Top 10 Security Report") {
		t.Errorf("streamed report missing header")
	}
}

func TestOWASPReportNilScan(t *testing.T) {
	if _, err := GenerateOWASPReport(nil, t.TempDir()+"/x.html"); err == nil {
		t.Errorf("expected error for nil scan")
	}
	if _, err := DownloadOWASPReport(nil); err == nil {
		t.Errorf("expected error for nil scan")
	}
}
