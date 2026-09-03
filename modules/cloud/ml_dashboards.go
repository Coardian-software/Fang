package cloud

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aydocs/fang/pkg/models"
	"gopkg.in/yaml.v3"
)

// mlDashboard is one ML-infrastructure dashboard entry from data/cloud-dashboards.yaml.
type mlDashboard struct {
	Name       string   `yaml:"name"`
	Paths      []string `yaml:"paths"`
	Indicators []string `yaml:"indicators"`
}

func loadMLDashboards() []mlDashboard {
	raw, err := os.ReadFile(filepath.Join("data", "cloud-dashboards.yaml"))
	if err != nil {
		return nil
	}
	return parseMLDashboards(raw)
}

func parseMLDashboards(raw []byte) []mlDashboard {
	var pack struct {
		Dashboards []mlDashboard `yaml:"dashboards"`
	}
	if err := yaml.Unmarshal(raw, &pack); err != nil {
		return nil
	}
	return pack.Dashboards
}

func (m *CloudModule) checkMLDashboards(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	for _, d := range loadMLDashboards() {
		for _, p := range d.Paths {
			if ctx.Err() != nil {
				return findings
			}
			u := strings.TrimRight(target.URL, "/") + p
			resp, err := m.client.GetContext(ctx, u)
			if err != nil || resp == nil || resp.StatusCode != 200 {
				continue
			}
			body := strings.ToLower(resp.Body)
			hit := ""
			for _, ind := range d.Indicators {
				if strings.Contains(body, ind) {
					hit = ind
					break
				}
			}
			if hit == "" {
				continue
			}
			findings = append(findings, m.finding(
				fmt.Sprintf("Exposed %s Dashboard", d.Name),
				models.Medium, models.MediumConfidence,
				u, "", "",
				fmt.Sprintf("%s dashboard at path %s returned 200 with body indicator '%s'", d.Name, p, hit),
				"Restrict ML-infrastructure dashboards to authenticated internal users.",
				"CWE-306",
			))
		}
	}
	return findings
}
