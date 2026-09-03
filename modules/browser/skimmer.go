package browser

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/aydocs/fang/pkg/models"
	"gopkg.in/yaml.v3"
)

// skimmerPack mirrors data/js-skimmers.yaml (static content patterns only).
type skimmerPack struct {
	C2PanelPaths          []string `yaml:"c2_panel_paths"`
	C2PanelBodyIndicators []string `yaml:"c2_panel_body_indicators"`
	SkimmerMarkers        []string `yaml:"skimmer_markers"`
}

// checkSkimmerPatterns runs the two data-pack content checks: capped C2-panel
// path probing plus skimmer-marker detection on the target page. GET-only.
func (m *BrowserModule) checkSkimmerPatterns(ctx context.Context, target *models.Target) []*models.Finding {
	raw, readErr := os.ReadFile(filepath.Join("data", "js-skimmers.yaml"))
	if readErr != nil {
		return nil
	}
	var pack skimmerPack
	if yaml.Unmarshal(raw, &pack) != nil {
		return nil
	}

	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	for _, p := range pack.C2PanelPaths {
		if ctx.Err() != nil || len(findings) >= 5 { // cap per target
			break
		}
		u := base + p
		matched := m.matchedContent(ctx, u, pack.C2PanelBodyIndicators)
		if len(matched) < 2 {
			continue
		}
		findings = append(findings, &models.Finding{
			CheckID:     "browser.browser-c2-panel-content-detected",
			Title:       "Browser - C2 Panel Content Detected",
			Severity:    models.Medium,
			Confidence:  models.MediumConfidence,
			URL:         u,
			Evidence:    "Indicators matched at " + u + ": " + strings.Join(matched, ", "),
			Description: "A common C2-panel path returned 200 with multiple command-and-control content indicators.",
			Remediation: "Restrict management endpoints to authenticated internal users.",
			CWEID:       "CWE-306",
			ModuleID:    "browser",
		})
	}

	matched := m.matchedContent(ctx, target.URL, pack.SkimmerMarkers)
	if len(matched) > 0 {
		findings = append(findings, &models.Finding{
			CheckID:     "browser.browser-js-skimmer-marker-detected",
			Title:       "Browser - JS Skimmer Marker Detected",
			Severity:    models.High,
			Confidence:  models.MediumConfidence,
			URL:         target.URL,
			Evidence:    "Skimmer markers in page body: " + strings.Join(matched, ", "),
			Description: "Page content matches known payment-skimmer script patterns (Magecart-style form exfiltration).",
			Remediation: "Audit inline and third-party scripts for form-data exfiltration; enforce a strict CSP.",
			CWEID:       "CWE-359",
			ModuleID:    "browser",
		})
	}
	return findings
}

// matchedContent GETs u once and returns which needles appear in the body.
func (m *BrowserModule) matchedContent(ctx context.Context, u string, needles []string) []string {
	resp, err := m.client.GetContext(ctx, u)
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return nil
	}
	body := strings.ToLower(resp.Body)
	var matched []string
	for _, n := range needles {
		if strings.Contains(body, n) {
			matched = append(matched, n)
		}
	}
	return matched
}
