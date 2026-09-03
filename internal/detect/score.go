// Package detect scores finding confidence at aggregation time, before any
// persistence. It replaces the deleted verifier amplifier with cheap,
// boring signals: pattern-class tables, unique-marker reflection, baseline
// delta, multi-class corroboration and a single stability re-request.
package detect

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

// STRONG patterns prove active server misbehaviour on their own; WEAK
// patterns are generic noise a healthy app emits too. The tables reclassify
// the substrings modules already match (see inject.SQLIErrorPatterns).
var (
	strongPatterns = []string{
		"error in your sql syntax",
		"ora-",
		"pg_query",
		"cast to objectid failed",
		"unclosed quotation mark",
		"sql syntax",
	}
	weakPatterns = []string{
		"warning:",
		"unexpected",
		"division by zero",
	}
)

// reflectionModules may carry an inject.UniqueMarker echo in their evidence;
// a marker echoed back proves our payload was executed, not merely printed.
var reflectionModules = map[string]bool{
	"xss":    true,
	"cmdi":   true,
	"lfi":    true,
	"inject": true,
}

// UniqueMarker renders as FNG<prefix><16 hex chars>; prefixes are uppercase.
var markerRe = regexp.MustCompile(`FNG[A-Z]{2,8}[0-9a-f]{16}`)

// Options carries the run-scoped dependencies Score may use. A nil Client
// disables the stability re-request entirely.
type Options struct {
	Ctx    context.Context
	Client *fanghttp.Client
}

// Result reports the outcome of scoring a single finding.
type Result struct {
	Key string // dedup key assigned to the finding

	// Signal accounting feeds Calibrate. StrongSignals counts STRONG
	// pattern classes matched by the evidence, Reflected records an echoed
	// unique marker, and Corroborated marks a second independent payload
	// class on the same dedup key (set by the Aggregator). A finding with
	// none of these is an unverified module claim.
	StrongSignals int
	Reflected     bool
	Corroborated  bool
}

// signalCount returns how many independent signals back the finding.
// Critical severity requires at least two of: STRONG pattern hit, marker
// reflection, multi-class corroboration.
func (r Result) signalCount() int {
	n := 0
	if r.StrongSignals > 0 {
		n++
	}
	if r.Reflected {
		n++
	}
	if r.Corroborated {
		n++
	}
	return n
}

// Calibrate enforces the safe-default severity ceiling on a scored finding,
// in place. Two rules, applied to every finding regardless of module:
//
//  1. Findings backed by zero independent signals — substring-only or pure
//     heuristic claims — can never exceed Low until something verifies them.
//  2. Critical requires at least two independent signals; single-signal
//     findings cap at High.
func Calibrate(f *models.Finding, r Result) {
	signals := r.signalCount()
	if signals == 0 && f.Severity > models.Low {
		f.Severity = models.Low
	}
	if signals < 2 && f.Severity == models.Critical {
		f.Severity = models.High
	}
}

// Score adjusts f.Confidence and f.Severity in place from its evidence and
// returns the dedup key. Rules, applied in order:
//
//  1. STRONG pattern hit floors confidence at Medium; WEAK-only evidence
//     drops it to Tentative; no signal leaves the module's claim untouched.
//  2. An echoed unique marker boosts one tier for reflection-class modules.
//  3. Crossing into HighConfidence triggers at most ONE stability
//     re-request; if the signal does not reproduce, one tier is dropped.
//  4. Critical severity requires HighConfidence, else severity caps at High.
func Score(f *models.Finding, opts Options) Result {
	text := strings.ToLower(f.Evidence + "\n" + f.Payload + "\n" + f.Title)
	matchedStrong := matchAll(text, strongPatterns)
	matchedWeak := matchAll(text, weakPatterns)

	prev := f.Confidence
	conf := prev
	switch {
	case len(matchedStrong) > 0:
		if conf < models.MediumConfidence {
			conf = models.MediumConfidence
		}
	case len(matchedWeak) > 0:
		conf = models.Tentative
	}

	marker := findMarker(f.Payload)
	echoed := marker != "" && reflectionModules[f.ModuleID] &&
		strings.Contains(f.Evidence+"\n"+f.Response, marker)
	if echoed {
		conf = shift(conf, 1)
	}

	if opts.Client != nil && conf >= models.HighConfidence && prev < models.HighConfidence {
		if !reproduces(opts, f.URL, matchedStrong, matchedWeak, marker) {
			conf = shift(conf, -1)
		}
	}

	if f.Severity == models.Critical && conf < models.HighConfidence {
		f.Severity = models.High
	}
	f.Confidence = conf

	res := Result{
		Key:           DedupKey(f),
		StrongSignals: len(matchedStrong),
		Reflected:     echoed,
	}
	Calibrate(f, res)
	return res
}

// BaselineDelta reports whether response differs from baseline after
// normalization (lowercase, tags stripped, whitespace collapsed). Callers
// that already hold both bodies use it to separate real reflection from
// static page noise.
func BaselineDelta(baselineBody, responseBody string) bool {
	return normalizeBody(baselineBody) != normalizeBody(responseBody)
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

func normalizeBody(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(tagRe.ReplaceAllString(s, " "))), " ")
}

// DedupKey is sha1(vuln_class|host|param|path). vuln_class prefers CWEID so
// different modules reporting the same bug class collapse onto one key.
func DedupKey(f *models.Finding) string {
	host, path := "", ""
	if u, err := url.Parse(f.URL); err == nil {
		host, path = u.Hostname(), u.EscapedPath()
	}
	class := f.CWEID
	if class == "" {
		class = f.ModuleID
	}
	sum := sha1.Sum([]byte(class + "|" + host + "|" + f.Parameter + "|" + path))
	return hex.EncodeToString(sum[:])
}

// PayloadClass buckets a payload into a coarse class so corroboration can
// count distinct exploitation angles against the same dedup key.
func PayloadClass(payload string) string {
	p := strings.ToLower(payload)
	switch {
	case markerRe.MatchString(payload):
		return "marker"
	case strings.Contains(p, "union select"):
		return "sqli-union"
	case strings.Contains(p, "sleep("), strings.Contains(p, "waitfor"):
		return "sqli-time"
	case strings.Contains(p, "$ne"), strings.Contains(p, "$gt"), strings.Contains(p, "$regex"):
		return "nosql"
	case strings.Contains(p, "' or"), strings.Contains(p, "and '1'="):
		return "sqli-boolean"
	case strings.Contains(p, "<script"), strings.Contains(p, "onerror"),
		strings.Contains(p, "onload"), strings.Contains(p, "javascript:"):
		return "xss-tag"
	case strings.Contains(p, "../"), strings.Contains(p, "%2e%2e"),
		strings.Contains(p, "etc/passwd"), strings.Contains(p, "win.ini"):
		return "traversal"
	case strings.Contains(p, "{{"), strings.Contains(p, "${"), strings.Contains(p, "#set"):
		return "template"
	case strings.Contains(p, "file://"), strings.Contains(p, "php://"):
		return "wrapper"
	default:
		return "generic"
	}
}

func matchAll(text string, patterns []string) []string {
	var matched []string
	for _, p := range patterns {
		if strings.Contains(text, p) {
			matched = append(matched, p)
		}
	}
	return matched
}

func findMarker(payload string) string {
	return markerRe.FindString(payload)
}

// reproduces re-requests the finding URL once and checks the original
// signal survives. Transport errors never demote: only a fetched body that
// lost every signal counts as non-reproducing.
func reproduces(opts Options, rawURL string, strong, weak []string, marker string) bool {
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	resp, err := opts.Client.GetContext(ctx, rawURL)
	if err != nil || resp == nil {
		return true
	}
	body := strings.ToLower(resp.Body)
	for _, p := range strong {
		if strings.Contains(body, p) {
			return true
		}
	}
	for _, p := range weak {
		if strings.Contains(body, p) {
			return true
		}
	}
	return marker != "" && strings.Contains(resp.Body, marker)
}

func shift(c models.Confidence, n int) models.Confidence {
	v := int(c) + n
	if v < int(models.Tentative) {
		v = int(models.Tentative)
	}
	if v > int(models.CriticalConfidence) {
		v = int(models.CriticalConfidence)
	}
	return models.Confidence(v)
}
