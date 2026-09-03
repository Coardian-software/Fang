package engine

import (
	"net"
	"net/url"
	"strings"

	"github.com/aydocs/fang/pkg/models"
)

// createTarget normalizes a raw target string into a scan target, defaulting
// the scheme to https and trimming trailing slashes.
func (e *Engine) createTarget(target string) (*models.Target, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	target = strings.TrimRight(target, "/")

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	return &models.Target{
		URL:     target,
		Domain:  u.Hostname(),
		Method:  "GET",
		Headers: e.config.Headers,
		Cookies: e.config.Cookies,
	}, nil
}

// TargetFromURL builds a scan target from a raw URL using this engine's
// header and cookie defaults.
func (e *Engine) TargetFromURL(rawURL string) (*models.Target, error) {
	return e.createTarget(rawURL)
}

// isPrivateTarget reports whether host falls into a range suppressed by
// default: loopback, RFC1918, link-local, or the "localhost" name family.
// Scans opt in with Config.AllowPrivate.
func isPrivateTarget(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
