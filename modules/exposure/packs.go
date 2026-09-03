package exposure

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// pathGroup is one path/indicator section of data/exposure-paths.yaml; only
// the keys a group actually ships are populated.
type pathGroup struct {
	Name            string   `yaml:"-"`
	Paths           []string `yaml:"paths"`
	Indicators      []string `yaml:"indicators"`
	StrongMarkers   []string `yaml:"strong_markers"`
	BodyIndicators  []string `yaml:"body_indicators"`
	DebugIndicators []string `yaml:"debug_indicators"`
	CrashIndicators []string `yaml:"crash_indicators"`
}

type wifiGroup struct {
	Paths              []string `yaml:"paths"`
	CaptivePortalPaths []string `yaml:"captive_portal_paths"`
	CaptiveProbePaths  []string `yaml:"captive_probe_paths"`
}

type mobileGroup struct {
	Android pathGroup `yaml:"android"`
	IOS     pathGroup `yaml:"ios"`
}

type exposurePack struct {
	DependencyManifests pathGroup   `yaml:"dependency_manifests"`
	SDRRadio            pathGroup   `yaml:"sdr_radio"`
	SDRGPS              pathGroup   `yaml:"sdr_gps"`
	SDRConfig           pathGroup   `yaml:"sdr_config"`
	RFIDReaders         pathGroup   `yaml:"rfid_readers"`
	WiFi                wifiGroup   `yaml:"wifi_interfaces"`
	MobileArtifacts     mobileGroup `yaml:"mobile_artifacts"`
}

func loadPack() *exposurePack {
	raw, err := os.ReadFile(packPath)
	if err != nil {
		return nil
	}
	return parsePack(raw)
}

func parsePack(raw []byte) *exposurePack {
	var p exposurePack
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil
	}
	p.SDRRadio.Name = "SDR radio"
	p.SDRGPS.Name = "GPS receiver"
	p.SDRConfig.Name = "SDR configuration"
	p.RFIDReaders.Name = "RFID reader"
	return &p
}

// serviceGroups returns the exotic-service groups; Wi-Fi joins via its
// interface paths while its captive lists are probed separately.
func (p *exposurePack) serviceGroups() []pathGroup {
	groups := []pathGroup{p.SDRRadio, p.SDRGPS, p.SDRConfig, p.RFIDReaders}
	return append(groups, pathGroup{Name: "Wi-Fi interface", Paths: p.WiFi.Paths})
}

// indicators resolves the group's match list. Groups shipped without any YAML
// indicator list fall back to minimal token sets; the >=2-match threshold in
// checkServices still suppresses soft-404 false positives for them.
func (g pathGroup) indicators() []string {
	for _, list := range [][]string{g.Indicators, g.BodyIndicators, g.DebugIndicators, g.CrashIndicators} {
		if len(list) > 0 {
			return list
		}
	}
	return fallbackIndicators[g.Name]
}

var fallbackIndicators = map[string][]string{
	"RFID reader":     {"rfid", "nfc"},
	"Wi-Fi interface": {"wifi", "wlan", "wireless"},
}

// matchIndicators reports which lowercase indicators occur in body.
func matchIndicators(body string, indicators []string) []string {
	var hits []string
	for _, ind := range indicators {
		if ind != "" && strings.Contains(body, ind) {
			hits = append(hits, ind)
		}
	}
	return hits
}
