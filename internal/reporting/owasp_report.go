package reporting

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"
)

// GenerateOWASPReport generates a standalone OWASP Top 10 (2021) focused
// HTML report for a scan and writes it to outputPath. Returns the path to
// the generated file. Classification reuses the canonical InferMappings
// pipeline so the grouping matches the PDF reference index.
func GenerateOWASPReport(scan *Scan, outputPath string) (string, error) {
	if scan == nil {
		return "", fmt.Errorf("scan is nil")
	}

	data, err := buildOWASPReportData(scan)
	if err != nil {
		return "", fmt.Errorf("failed to build OWASP report data: %w", err)
	}

	htmlOut, err := renderOWASPHTMLReport(data)
	if err != nil {
		return "", fmt.Errorf("failed to render OWASP HTML report: %w", err)
	}

	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	if err := os.WriteFile(outputPath, []byte(htmlOut), 0644); err != nil {
		return "", fmt.Errorf("failed to write OWASP report: %w", err)
	}
	return outputPath, nil
}

// DownloadOWASPReport returns the OWASP Top 10 HTML report for a scan as an
// io.Reader suitable for HTTP streaming.
func DownloadOWASPReport(scan *Scan) (io.Reader, error) {
	if scan == nil {
		return nil, fmt.Errorf("scan is nil")
	}
	data, err := buildOWASPReportData(scan)
	if err != nil {
		return nil, fmt.Errorf("failed to build OWASP report data: %w", err)
	}
	htmlOut, err := renderOWASPHTMLReport(data)
	if err != nil {
		return nil, fmt.Errorf("failed to render OWASP HTML report: %w", err)
	}
	return strings.NewReader(htmlOut), nil
}

// owaspVulnView is a template-safe projection of a finding: every string
// is pre-HTML-escaped so the report never injects raw user/agent content.
type owaspVulnView struct {
	Title            string
	Severity         string
	SeverityCSS      string
	Endpoint         string
	Description      string
	Remediation      string
	CVE              string
	CWE              string
	Verified         bool
	VerificationText string
}

// owaspCategoryView is one OWASP Top 10 bucket in canonical order.
type owaspCategoryView struct {
	ID    string
	Name  string
	Vulns []owaspVulnView
}

// owaspReportData is the full template payload.
type owaspReportData struct {
	GeneratedAt   string
	ScanID        string
	Target        string
	TotalFindings int
	VerifiedCount int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	Unmatched      int
	UnmatchedVulns []owaspVulnView
	Categories     []owaspCategoryView
}

// buildOWASPReportData groups scan findings into OWASP Top 10 buckets via
// InferMappings and pre-escapes every rendered string.
func buildOWASPReportData(scan *Scan) (*owaspReportData, error) {
	// Normalize the agent-provided category ID to the canonical "A0x" form
	// (the agent may emit "A03:2021" or similar suffixed variants).
	buckets := make(map[string][]Vuln, len(OWASPCategories))
	var unmatched []Vuln
	for _, v := range scan.Vulns {
		m := InferMappings(v)
		if m.OWASP != "" {
			if canon := normalizeOWASPID(m.OWASP); canon != "" {
				buckets[canon] = append(buckets[canon], v)
				continue
			}
		}
		unmatched = append(unmatched, v)
	}

	data := &owaspReportData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
		ScanID:      html.EscapeString(scan.ID),
		Target:      html.EscapeString(scan.Target),
	}

	// Render findings that did not map to any OWASP Top 10 category so they
	// are never silently dropped from the report.
	for _, v := range unmatched {
		verified, verificationText := owaspVerificationStatus(v)
		data.UnmatchedVulns = append(data.UnmatchedVulns, owaspVulnView{
			Title:            html.EscapeString(v.Title),
			Severity:         html.EscapeString(v.Severity),
			SeverityCSS:      html.EscapeString(strings.ToLower(v.Severity)),
			Endpoint:         html.EscapeString(v.Endpoint),
			Description:      html.EscapeString(v.Description),
			Remediation:      html.EscapeString(v.Remediation),
			CVE:              html.EscapeString(v.CVE),
			CWE:              html.EscapeString(v.CWE),
			Verified:         verified,
			VerificationText: html.EscapeString(verificationText),
		})
	}

	for _, cat := range OWASPCategories {
		view := owaspCategoryView{ID: cat.ID, Name: cat.Name}
		for _, v := range buckets[cat.ID] {
			verified, verificationText := owaspVerificationStatus(v)
			view.Vulns = append(view.Vulns, owaspVulnView{
				Title:            html.EscapeString(v.Title),
				Severity:         html.EscapeString(v.Severity),
				SeverityCSS:      html.EscapeString(strings.ToLower(v.Severity)),
				Endpoint:         html.EscapeString(v.Endpoint),
				Description:      html.EscapeString(v.Description),
				Remediation:      html.EscapeString(v.Remediation),
				CVE:              html.EscapeString(v.CVE),
				CWE:              html.EscapeString(v.CWE),
				Verified:         verified,
				VerificationText: html.EscapeString(verificationText),
			})
		}
		data.Categories = append(data.Categories, view)
	}

	for _, v := range scan.Vulns {
		data.TotalFindings++
		if v.Verified {
			data.VerifiedCount++
		}
		switch v.Severity {
		case "Critical":
			data.CriticalCount++
		case "High":
			data.HighCount++
		case "Medium":
			data.MediumCount++
		case "Low":
			data.LowCount++
		}
	}
	data.Unmatched = len(unmatched)

	return data, nil
}

// owaspVerificationStatus derives the display status for a finding from its
// Phase 20 exploit-verification result. Mirrors the PDF report semantics: a
// finding is "verified" only when it carries a verification method AND was
// confirmed, otherwise it is flagged for manual review.
func owaspVerificationStatus(v Vuln) (bool, string) {
	switch {
	case v.Verified && v.VerificationMethod != "":
		return true, "Verified via " + strings.ToUpper(v.VerificationMethod)
	case v.VerificationMethod != "":
		return false, "UNVERIFIED — manual review required (reported via " + strings.ToUpper(v.VerificationMethod) + ")"
	default:
		return false, "UNVERIFIED — no verification evidence recorded"
	}
}

// normalizeOWASPID canonicalizes an agent-provided OWASP category token to
// the "A01".."A10" form used by OWASPCategory IDs, tolerating suffixed
// variants such as "A03:2021". Returns "" when no valid category is present.
var owaspIDPattern = regexp.MustCompile(`^A(0[1-9]|10)`)

func normalizeOWASPID(s string) string {
	m := owaspIDPattern.FindString(strings.TrimSpace(strings.ToUpper(s)))
	if m == "" {
		return ""
	}
	return m
}

// renderOWASPHTMLReport executes the report template against prepared data.
func renderOWASPHTMLReport(data *owaspReportData) (string, error) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP Top 10 Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0 0 10px 0; font-size: 2.5em; }
        .header p { margin: 0; opacity: 0.9; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-card .number { font-size: 2.5em; font-weight: bold; color: #667eea; }
        .stat-card .label { color: #666; margin-top: 5px; }
        .stat-card.verified .number { color: #059669; }
        .category { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .category-header { background: #f8f9fa; padding: 20px 30px; border-left: 4px solid #667eea; }
        .category-header h2 { margin: 0; color: #333; font-size: 1.5em; }
        .category-header .id { display: inline-block; background: #667eea; color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; margin-left: 10px; }
        .category-header .count { margin-left: 10px; font-size: 0.9em; color: #888; }
        .vuln-list { padding: 20px 30px; }
        .vuln { border-bottom: 1px solid #eee; padding: 20px 0; }
        .vuln:last-child { border-bottom: none; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; gap: 10px; }
        .vuln-title { font-size: 1.2em; font-weight: 600; color: #333; }
        .vuln-badges { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }
        .verified { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; }
        .verified.yes { background: #d1fae5; color: #065f46; }
        .verified.no { background: #fee2e2; color: #991b1b; }
        .severity { padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; text-transform: capitalize; }
        .severity.critical { background: #fee2e2; color: #dc2626; }
        .severity.high { background: #ffedd5; color: #ea580c; }
        .severity.medium { background: #fef3c7; color: #d97706; }
        .severity.low { background: #dbeafe; color: #2563eb; }
        .severity.info { background: #f3f4f6; color: #6b7280; }
        .vuln-body { color: #555; line-height: 1.6; }
        .vuln-meta { margin-top: 10px; font-size: 0.9em; color: #888; }
        .no-findings { color: #666; font-style: italic; padding: 20px; text-align: center; }
        .footer { text-align: center; padding: 30px; color: #888; font-size: 0.9em; }
        @media print { body { background: white; } .header { background: #667eea !important; -webkit-print-color-adjust: exact; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#128274; OWASP Top 10 Security Report</h1>
            <p>Generated on {{.GeneratedAt}} | Scan ID: {{.ScanID}}{{if .Target}} | Target: {{.Target}}{{end}}</p>
        </div>

        <div class="summary">
            <div class="stat-card">
                <div class="number">{{.TotalFindings}}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card verified">
                <div class="number">{{.VerifiedCount}}</div>
                <div class="label">Verified</div>
            </div>
            <div class="stat-card">
                <div class="number">{{.CriticalCount}}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number">{{.HighCount}}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number">{{.MediumCount}}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="number">{{.LowCount}}</div>
                <div class="label">Low</div>
            </div>
        </div>

        {{range .Categories}}
        <div class="category">
            <div class="category-header">
                <h2>{{.Name}} <span class="id">{{.ID}}</span><span class="count">{{len .Vulns}} finding(s)</span></h2>
            </div>
            <div class="vuln-list">
                {{if .Vulns}}
                    {{range .Vulns}}
                    <div class="vuln">
                        <div class="vuln-header">
                            <div class="vuln-title">{{.Title}}</div>
                            <div class="vuln-badges">
                                <span class="verified {{if .Verified}}yes{{else}}no{{end}}">{{if .Verified}}&#10003; {{.VerificationText}}{{else}}&#9888; {{.VerificationText}}{{end}}</span>
                                <span class="severity {{.SeverityCSS}}">{{.Severity}}</span>
                            </div>
                        </div>
                        {{if .Description}}
                        <div class="vuln-body">{{.Description}}</div>
                        {{end}}
                        <div class="vuln-meta">
                            {{if .Endpoint}}Endpoint: {{.Endpoint}} | {{end}}
                            {{if .CVE}}CVE: {{.CVE}} | {{end}}
                            {{if .CWE}}CWE: {{.CWE}}{{end}}
                        </div>
                        {{if .Remediation}}
                        <div class="vuln-meta">Recommendation: {{.Remediation}}</div>
                        {{end}}
                    </div>
                    {{end}}
                {{else}}
                    <div class="no-findings">&#10003; No findings for this category</div>
                {{end}}
            </div>
        </div>
        {{end}}

        {{if .UnmatchedVulns}}
        <div class="category">
            <div class="category-header">
                <h2>Other Findings <span class="id">Uncategorized</span><span class="count">{{len .UnmatchedVulns}} finding(s)</span></h2>
            </div>
            <div class="vuln-list">
                {{range .UnmatchedVulns}}
                <div class="vuln">
                    <div class="vuln-header">
                        <div class="vuln-title">{{.Title}}</div>
                        <div class="vuln-badges">
                            <span class="verified {{if .Verified}}yes{{else}}no{{end}}">{{if .Verified}}&#10003; {{.VerificationText}}{{else}}&#9888; {{.VerificationText}}{{end}}</span>
                            <span class="severity {{.SeverityCSS}}">{{.Severity}}</span>
                        </div>
                    </div>
                    {{if .Description}}
                    <div class="vuln-body">{{.Description}}</div>
                    {{end}}
                    <div class="vuln-meta">
                        {{if .Endpoint}}Endpoint: {{.Endpoint}} | {{end}}
                        {{if .CVE}}CVE: {{.CVE}} | {{end}}
                        {{if .CWE}}CWE: {{.CWE}}{{end}}
                    </div>
                    {{if .Remediation}}
                    <div class="vuln-meta">Recommendation: {{.Remediation}}</div>
                    {{end}}
                </div>
                {{end}}
            </div>
        </div>
        {{end}}

        <div class="footer">
            <p>Report generated by Xalgorix OWASP Scanner | For more information visit owasp.org</p>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("owasp").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	return buf.String(), nil
}
