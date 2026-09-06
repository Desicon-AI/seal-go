package seal

import (
	"net"
	"net/http"
	"regexp"
	"strings"
)

var (
    sqliRegex = regexp.MustCompile(`(?i)(?:\bUNION\s+(?:ALL\s+)?SELECT\b)|(?:['"]\s*(?:OR|AND)\s+\d+\s*=\s*\d+)`)
	xssRegex  = regexp.MustCompile(`(?i)(?:<|%3C)script[\s\S]*?(?:>|%3E)|(?:<|%3C)[\s\S]*?(?:on[a-z]+\s*=)(?:>|%3E)`)
)

// WAFMiddleware is the zero-latency edge protection for Go net/http apps
func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !initialized {
			next.ServeHTTP(w, r)
			return
		}

        ip, _, err := net.SplitHostPort(r.RemoteAddr)
        if err != nil { ip = r.RemoteAddr }
        cfCountry := ""
        if clientOptions.WAF.TrustProxyHeaders {
            if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" { ip = strings.TrimSpace(strings.Split(forwarded, ",")[0]) }
            cfCountry = r.Header.Get("CF-IPCountry")
        }

		ua := r.UserAgent()
		method := r.Method
		uri := r.URL.Path

		waf := clientOptions.WAF

		// Geo-Blocking
		if cfCountry != "" && len(waf.GeoBlocking.BlockedCountries) > 0 {
			for _, c := range waf.GeoBlocking.BlockedCountries {
				if c == cfCountry {
					reportThreat("GEO_BLOCKED", ip, map[string]interface{}{"action": threatAction(waf.GeoBlocking.Action), "country": cfCountry}, r)
					if waf.GeoBlocking.Action == "drop" {
						http.Error(w, "Access Denied from your Region", http.StatusForbidden)
						return
					}
				}
			}
		}

		// Method Tampering
		allowedMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true, "HEAD": true}
		if !allowedMethods[method] {
			reportThreat("METHOD_TAMPERING", ip, map[string]interface{}{"action": threatAction(waf.MethodTampering.Action), "method": method}, r)
			if waf.MethodTampering.Action == "drop" {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
		}

		// Malicious Scanners
		if regexp.MustCompile(`(?i)(sqlmap|nikto|masscan|zmap|nmap)`).MatchString(ua) {
			reportThreat("MALICIOUS_SCANNER", ip, map[string]interface{}{"action": threatAction(waf.MaliciousScanners.Action), "user_agent": ua}, r)
			if waf.MaliciousScanners.Action == "drop" {
				http.Error(w, "Forbidden Scanner", http.StatusForbidden)
				return
			}
		}

		// Payload Overflow
		if r.ContentLength > waf.PayloadOverflow.MaxPayloadSize {
			reportThreat("PAYLOAD_OVERFLOW", ip, map[string]interface{}{"action": threatAction(waf.PayloadOverflow.Action), "content_length": r.ContentLength}, r)
			if waf.PayloadOverflow.Action == "drop" {
				http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
				return
			}
		}

		// Path Traversal
		if strings.Contains(uri, "../") || strings.Contains(strings.ToLower(uri), "%2e%2e%2f") {
			reportThreat("PATH_TRAVERSAL", ip, map[string]interface{}{"action": threatAction(waf.PathTraversal.Action)}, r)
			if waf.PathTraversal.Action == "drop" {
				http.Error(w, "Forbidden Path", http.StatusForbidden)
				return
			}
		}

		// Honeypot
		honeypots := map[string]bool{"/wp-admin": true, "/wp-login.php": true, "/.env": true, "/config.php": true, "/.git/config": true}
		if honeypots[uri] {
			reportThreat("HONEYPOT_ACCESS", ip, nil, r)
		}

		// SQLi & XSS URL Inspection
		if sqliRegex.MatchString(r.URL.RawQuery) || sqliRegex.MatchString(uri) {
			reportThreat("SQL_INJECTION", ip, nil, r)
		} else if xssRegex.MatchString(r.URL.RawQuery) || xssRegex.MatchString(uri) {
			reportThreat("XSS_ATTACK", ip, nil, r)
		}

        // Do not consume the application request body during heuristic inspection.

		next.ServeHTTP(w, r)
	})
}

func threatAction(action string) string {
    if action == "drop" { return "blocked" }
    return "observed"
}
