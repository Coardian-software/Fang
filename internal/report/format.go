package report

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aydocs/fang/pkg/models"
)

// ValidFormats lists every output format the unified --format flag accepts.
func ValidFormats() []string {
	return []string{"json", "sarif", "markdown", "html", "csv", "jsonl", "pdf"}
}

// IsValidFormat reports whether format is one of ValidFormats.
func IsValidFormat(format string) bool {
	format = normalizeFormat(format)
	for _, v := range ValidFormats() {
		if format == v {
			return true
		}
	}
	return false
}

func normalizeFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

// Write renders result to w in the given unified format.
//
// json/sarif/markdown/html/csv/jsonl stream to w; pdf renders through headless
// Chromium and writes a file instead, printing its path to w.
func Write(ctx context.Context, w io.Writer, format string, result *models.ScanResult) error {
	switch normalizeFormat(format) {
	case "json":
		s, err := generateJSON(result)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, s)
	case "sarif":
		e := New(&Config{})
		s, err := e.GenerateSARIF(ctx, result)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, s)
	case "markdown":
		fmt.Fprintln(w, generateMarkdown(result))
	case "html":
		s := New(&Config{}).HTML(result)
		fmt.Fprintln(w, s)
	case "csv":
		return writeCSV(w, result)
	case "jsonl":
		return writeJSONL(w, result.Findings)
	case "pdf":
		path, err := New(&Config{}).GeneratePDF(ctx, result, nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "report written: %s\n", path)
	default:
		return fmt.Errorf("unknown format %q (valid: %s)", format, strings.Join(ValidFormats(), ", "))
	}
	return nil
}

func writeCSV(w io.Writer, result *models.ScanResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"severity", "module_id", "check_id", "title", "url",
		"parameter", "confidence", "fingerprint",
	}); err != nil {
		return err
	}
	for _, f := range result.Findings {
		row := []string{
			f.Severity.String(),
			f.ModuleID,
			f.CheckID,
			f.Title,
			f.URL,
			f.Parameter,
			f.Confidence.String(),
			f.Fingerprint,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeJSONL(w io.Writer, findings []*models.Finding) error {
	enc := json.NewEncoder(w)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// SeverityAtLeast reports whether s meets or exceeds threshold on the
// Info<Low<Medium<High<Critical scale used by --fail-on.
func SeverityAtLeast(s models.Severity, threshold models.Severity) bool {
	return s >= threshold
}

// ParseSeverity maps a CLI string to models.Severity ("medium" etc).
func ParseSeverity(s string) (models.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return models.Info, nil
	case "low":
		return models.Low, nil
	case "medium":
		return models.Medium, nil
	case "high":
		return models.High, nil
	case "critical":
		return models.Critical, nil
	default:
		return models.Info, fmt.Errorf("unknown severity %q (valid: info, low, medium, high, critical)", s)
	}
}
