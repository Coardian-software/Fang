// Package exposure performs GET-only content discovery for publicly reachable
// dependency manifests and exotic SDR, RFID, Wi-Fi and mobile-artifact
// services, driven entirely by the committed data/exposure-paths.yaml packs.
package exposure

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

const (
	moduleID    = "exposure"
	maxFindings = 12
	cweInfo     = "CWE-200"
)

// packPath is swapped by tests to point at the repo-root data pack.
var packPath = filepath.Join("data", "exposure-paths.yaml")

type ExposureModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ExposureModule) ID() string   { return moduleID }
func (m *ExposureModule) Name() string { return "Exposure - Content & Service Discovery" }
func (m *ExposureModule) Description() string {
	return "GET-only discovery of exposed dependency manifests plus SDR, RFID, Wi-Fi and mobile-artifact services"
}
func (m *ExposureModule) Severity() models.Severity { return models.Medium }

func (m *ExposureModule) Init(_ context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	if cfg.Client != nil {
		m.client = cfg.Client
	} else if m.client == nil {
		m.client = fanghttp.NewDefaultClient()
	}
	return nil
}

func (m *ExposureModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	pack := loadPack()
	if pack == nil {
		return nil, nil
	}
	s := &scanState{m: m, base: strings.TrimRight(target.URL, "/")}
	s.checkManifests(ctx, pack.DependencyManifests)
	s.checkServices(ctx, pack.serviceGroups())
	s.checkCaptivePortals(ctx, pack.WiFi)
	s.checkMobileArtifacts(ctx, pack.MobileArtifacts)
	return s.findings, nil
}

// scanState funnels every request through one cancellation poll and result-cap
// gate: between requests the scan observes ctx and stops once the cap is hit.
type scanState struct {
	m        *ExposureModule
	base     string
	findings []*models.Finding
}

func (s *scanState) stopped(ctx context.Context) bool {
	if len(s.findings) >= maxFindings {
		return true
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (s *scanState) fetch(ctx context.Context, p string) (*fanghttp.Response, bool) {
	if s.stopped(ctx) {
		return nil, false
	}
	resp, err := s.m.client.GetContext(ctx, s.base+p)
	return resp, err == nil && resp != nil
}

// hitSpec carries the per-finding fields; CWE and module id are constant.
type hitSpec struct {
	title, url, evidence, desc, remediation string
	sev                                     models.Severity
	conf                                    models.Confidence
}

func (s *scanState) add(h hitSpec) {
	if len(s.findings) >= maxFindings {
		return
	}
	s.findings = append(s.findings, &models.Finding{
		Title: h.title, Severity: h.sev, Confidence: h.conf, URL: h.url,
		CheckID:  models.DefaultCheckID(moduleID, h.title),
		Evidence: h.evidence, Description: h.desc, Remediation: h.remediation,
		CWEID: cweInfo, ModuleID: moduleID,
	})
}

func (s *scanState) checkManifests(ctx context.Context, g pathGroup) {
	for _, p := range g.Paths {
		resp, ok := s.fetch(ctx, p)
		if !ok || resp.StatusCode != 200 {
			continue
		}
		hits := matchIndicators(strings.ToLower(resp.Body), g.BodyIndicators)
		if len(hits) == 0 {
			continue
		}
		s.add(hitSpec{
			title: "Dependency/manifest file exposed", sev: models.High, conf: models.HighConfidence,
			url:         s.base + p,
			evidence:    fmt.Sprintf("%s returned 200; matched indicators %v", p, hits),
			desc:        "A dependency manifest or lockfile is reachable over HTTP, disclosing the exact dependency tree and toolchain attackers need to target known-vulnerable versions.",
			remediation: "Block manifests, lockfiles and dotfiles at the web server; keep build artifacts out of the webroot.",
		})
	}
}

func (s *scanState) checkServices(ctx context.Context, groups []pathGroup) {
	for _, g := range groups {
		if s.stopped(ctx) {
			return
		}
		indicators := g.indicators()
		for _, p := range g.Paths {
			resp, ok := s.fetch(ctx, p)
			if !ok || resp.StatusCode != 200 {
				continue
			}
			body := strings.ToLower(resp.Body)
			hits := matchIndicators(body, indicators)
			strong := matchIndicators(body, g.StrongMarkers)
			if len(hits) < 2 && len(strong) == 0 {
				continue
			}
			evidence := fmt.Sprintf("%s returned 200; matched %d indicator(s) %v", p, len(hits), hits)
			if len(strong) > 0 {
				evidence += fmt.Sprintf("; strong marker %q", strong[0])
			}
			s.add(hitSpec{
				title: "Possible " + g.Name + " exposed", sev: models.Medium, conf: models.MediumConfidence,
				url:         s.base + p,
				evidence:    evidence,
				desc:        "A path consistent with a " + g.Name + " answered 200 with several content indicators, suggesting an unauthenticated management or data interface.",
				remediation: "Restrict these interfaces to authenticated internal users and remove them from public routes.",
			})
		}
	}
}

func (s *scanState) checkCaptivePortals(ctx context.Context, w wifiGroup) {
	paths := append(append([]string{}, w.CaptivePortalPaths...), w.CaptiveProbePaths...)
	for _, p := range paths {
		resp, ok := s.fetch(ctx, p)
		if !ok || (resp.StatusCode != 200 && resp.StatusCode != 204) {
			continue
		}
		s.add(hitSpec{
			title: "Captive portal endpoint", sev: models.Medium, conf: models.Tentative,
			url:         s.base + p,
			evidence:    fmt.Sprintf("%s answered with HTTP %d", p, resp.StatusCode),
			desc:        "A captive-portal or connectivity-check endpoint responds without authentication; low-value on its own, it hints at hotspot or guest-network equipment.",
			remediation: "Restrict captive-portal endpoints to the guest network segment.",
		})
		return // informational only: cap at one finding per target
	}
}

func (s *scanState) checkMobileArtifacts(ctx context.Context, mg mobileGroup) {
	groups := []struct {
		label string
		grp   pathGroup
	}{
		{"Android application artifact", mg.Android},
		{"iOS application artifact", mg.IOS},
	}
	for _, art := range groups {
		for _, p := range art.grp.Paths {
			resp, ok := s.fetch(ctx, p)
			if !ok || resp.StatusCode != 200 {
				continue
			}
			hits := matchIndicators(strings.ToLower(resp.Body), art.grp.indicators())
			if len(hits) == 0 {
				continue
			}
			s.add(hitSpec{
				title: "Exposed " + art.label, sev: models.Medium, conf: models.MediumConfidence,
				url:         s.base + p,
				evidence:    fmt.Sprintf("%s returned 200; matched indicators %v", p, hits),
				desc:        "A mobile build artifact or its metadata is downloadable, leaking bundle identifiers, endpoint URLs and debug/staging environment details.",
				remediation: "Serve application artifacts only from authenticated distribution channels.",
			})
		}
	}
}

func init() {
	engine.GetRegistry().Register(&ExposureModule{})
}
