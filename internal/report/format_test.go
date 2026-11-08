package report

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aydocs/fang/pkg/models"
)

func TestParseSeverity(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  models.Severity
	}{
		{" info ", models.Info},
		{"low", models.Low},
		{"MEDIUM", models.Medium},
		{"high", models.High},
		{"critical", models.Critical},
	} {
		got, err := ParseSeverity(tc.input)
		if err != nil || got != tc.want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", tc.input, got, err, tc.want)
		}
	}
	if _, err := ParseSeverity("unknown"); err == nil {
		t.Fatal("ParseSeverity(unknown) error = nil")
	}
}

func TestWriteCSVEscapesFindingFields(t *testing.T) {
	result := &models.ScanResult{Findings: []*models.Finding{{
		Severity: models.High,
		ModuleID: "test",
		Title:    "quoted, title",
		URL:      "https://example.test/?q=\"x\"",
	}}}
	var out bytes.Buffer
	if err := Write(context.Background(), &out, "csv", result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !strings.Contains(out.String(), `"quoted, title"`) {
		t.Fatalf("CSV did not quote comma-containing field: %q", out.String())
	}
}
