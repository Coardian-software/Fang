package models

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Lifecycle status values tracked across scans for every finding.
const (
	StatusOpen     = "open"
	StatusReopened = "reopened"
	StatusFixed    = "fixed"
)

// FingerprintLen is the byte length of the truncated SHA-256 fingerprint:
// 16 bytes render as 32 hex chars, enough to stay collision-free per target
// while keeping rows and diffs compact.
const FingerprintLen = 16

var numericSegment = regexp.MustCompile(`^[0-9]+$`)

// Enrich completes a finding for persistence and dedup: it fills OWASP/CVSS
// defaults, assigns a CheckID slug when the construction site did not,
// stamps lifecycle timestamps and computes the stable fingerprint. It is
// idempotent and must be called exactly once per finding upstream of
// dedup/persistence (the engine owns that single call site).
//
// The fingerprint deliberately EXCLUDES payload and evidence: XSS markers
// are randomized per run, so including them would break cross-scan joins.
func (f *Finding) Enrich() {
	if f.OWASPCategory == "" {
		f.OWASPCategory = CWEToOWASP(f.CWEID)
	}
	if f.CVSS == nil {
		v := CWEToCVSS(f.CWEID)
		f.CVSS = &v
	}
	if f.CheckID == "" {
		f.CheckID = DefaultCheckID(f.ModuleID, f.Title)
	}
	now := time.Now()
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	f.LastSeen = now
	if f.Status == "" {
		f.Status = StatusOpen
	}
	f.Fingerprint = f.Fingerprint16()
}

// Fingerprint16 returns hex(truncate(sha256(...), 16)) over exactly
// ModuleID | CheckID | lowerHost(host) | normalizePath(path) | Parameter.
func (f *Finding) Fingerprint16() string {
	host, path := hostAndPath(f.URL)
	parts := []string{f.ModuleID, f.CheckID, host, NormalizePath(path), f.Parameter}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:FingerprintLen])
}

// hostAndPath splits a raw finding URL into lowercased host (default ports
// :80/:443 stripped) and the escaped path.
func hostAndPath(rawURL string) (host, path string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	host = NormalizeHost(u.Host)
	return host, u.EscapedPath()
}

// NormalizeHost lowercases a host and strips default ports so
// https://API.Example.com:443/a and http://api.example.com/a share identity.
func NormalizeHost(host string) string {
	host = strings.ToLower(host)
	for _, suffix := range []string{":80", ":443"} {
		if strings.HasSuffix(host, suffix) {
			return strings.TrimSuffix(host, suffix)
		}
	}
	return host
}

// NormalizePath strips the query string and trailing slash and collapses
// purely numeric path segments to ":id", so /users/42/ and /users/99?id=1
// normalize to /users/:id.
func NormalizePath(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimRight(path, "/")
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if numericSegment.MatchString(seg) {
			segs[i] = ":id"
		}
	}
	out := strings.Join(segs, "/")
	if out == "" {
		return "/"
	}
	return out
}

// DefaultCheckID derives "<module>.<kebab-title>" — the deterministic
// fallback for findings whose construction site carries no explicit slug.
func DefaultCheckID(moduleID, title string) string {
	slug := SlugifyTitle(title)
	switch {
	case moduleID == "" && slug == "":
		return "unknown.check"
	case moduleID == "":
		return slug
	case slug == "":
		return moduleID + ".check"
	default:
		return moduleID + "." + slug
	}
}

var (
	formatVerb        = regexp.MustCompile(`%[-#0-9.]*[a-zA-Z]`)
	verbParenthetical = regexp.MustCompile(`\([^()]*%[^()]*\)`)
)

// SlugifyTitle kebab-cases the static part of a finding title: format verbs
// and their parenthetical wrappers are dropped, punctuation becomes word
// boundaries. "Missing Security Header: %s" -> "missing-security-header".
func SlugifyTitle(title string) string {
	title = verbParenthetical.ReplaceAllString(title, "")
	title = formatVerb.ReplaceAllString(title, "")
	var b strings.Builder
	prevDash := true // suppress leading dash
	for _, r := range strings.ToLower(title) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
