# OIDC fold — JWT attack notes (salvaged from idpwn checkJWT)

Source: `modules/idpwn` (deleted). Reimplement these five checks inside
`modules/oidc` against `cfg.Client`. All probes are GET-only (`?token=`).

## 1. JWT token discovery
Scan response body for base64url JWT prefixes: `eyJ`, `eyI`, `eyJhbGci`,
`eyJ0eXAi`, `eyJraWQ`. Extract until delimiter `" ' space tab CR LF < > &`.
Split on `.`; exactly 3 parts => report finding (High/CWE-287).

## 2. alg:none acceptance (Critical, CWE-287)
Token = `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.`
GET `<target>?token=<algNoneToken>`; accepted if status NOT in {401,403}.
Forges arbitrary tokens without signing key.

## 3. kid path traversal (Critical, CWE-22)
Header JSON: {"kid":"../../etc/passwd","alg":"HS256"} (base64url, no padding)
Payload:    {"sub":"admin","role":"admin"}
Signature:  literal ".signature"
Accepted if status NOT in {401,403} => KID used for file-path secret resolution.

## 4. JWK injection / self-signed trust (Critical, CWE-287)
Header embeds attacker RSA JWK:
{"alg":"RS256","jwk":{"kty":"RSA","n":"<modulus>","e":"AQAB"}}
Accepted if status NOT in {401,403} => server trusts embedded keys instead of JWKS endpoint.

## 5. HMAC/RSA key confusion (Critical, CWE-287)
Header {"alg":"HS256","typ":"JWT"} + admin payload + signature = base64url(RSA public key).
Also brute loop over common public-key blobs (3 hardcoded samples in original —
replace with configurable key list). Accepted if status NOT in {401,403}.

## Implementation contract (bind to shared client)
- All requests via cfg.Client with ctx propagation.
- One check per token type; dedup handled engine-side by fingerprint.
- Confidence: keep MediumConfidence for acceptance-based findings (status-code
  inference is weak evidence); discovery check stays High only when full
  3-part structure parses.
