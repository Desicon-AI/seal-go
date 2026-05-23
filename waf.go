package seal

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

var (
	sqliRegex = regexp.MustCompile(`(?i)(?:\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE)?|INSERT( +INTO)?|MERGE|SELECT|UPDATE|UNION( +ALL)?)\b)|(?:'|%27).*?(?:OR|AND).*?(?:'|%27)|(?:--)`)
	xssRegex  = regexp.MustCompile(`(?i)(?:<|%3C)script[\s\S]*?(?:>|%3E)|(?:<|%3C)[\s\S]*?(?:on[a-z]+\s*=)(?:>|%3E)`)
)

// WAFMiddleware is the zero-latency edge protection for Go net/http apps
func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !initialized {
			next.ServeHTTP(w, r)
			return
		}

		ip := r.Header.Get("CF-Connecting-IP")
		if ip == "" {
			ip = r.Header.Get("X-Forwarded-For")
		}
		if ip == "" {
			ip = r.RemoteAddr
		}

		cfCountry := r.Header.Get("CF-IPCountry")
		ua := r.UserAgent()
		method := r.Method
		uri := r.URL.Path

		waf := clientOptions.WAF

		// Geo-Blocking
		if cfCountry != "" && len(waf.GeoBlocking.BlockedCountries) > 0 {
			for _, c := range waf.GeoBlocking.BlockedCountries {
				if c == cfCountry {
					reportThreat("GEO_BLOCKED", ip, map[string]interface{}{"country": cfCountry}, r)
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
			reportThreat("METHOD_TAMPERING", ip, map[string]interface{}{"method": method}, r)
			if waf.MethodTampering.Action == "drop" {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
		}

		// Malicious Scanners
		if regexp.MustCompile(`(?i)(sqlmap|nikto|masscan|zmap|nmap|python-requests|curl|wget)`).MatchString(ua) {
			reportThreat("MALICIOUS_SCANNER", ip, map[string]interface{}{"user_agent": ua}, r)
			if waf.MaliciousScanners.Action == "drop" {
				http.Error(w, "Forbidden Scanner", http.StatusForbidden)
				return
			}
		}

		// Payload Overflow
		if r.ContentLength > waf.PayloadOverflow.MaxPayloadSize {
			reportThreat("PAYLOAD_OVERFLOW", ip, map[string]interface{}{"content_length": r.ContentLength}, r)
			if waf.PayloadOverflow.Action == "drop" {
				http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
				return
			}
		}

		// Path Traversal
		if strings.Contains(uri, "../") || strings.Contains(strings.ToLower(uri), "%2e%2e%2f") {
			reportThreat("PATH_TRAVERSAL", ip, nil, r)
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

		// Fast payload check (POST body) - only if reasonable size to avoid parsing huge files
		if r.ContentLength > 0 && r.ContentLength < 100000 {
			bodyBytes, err := ioutil.ReadAll(r.Body)
			if err == nil {
				// Restore the io.ReadCloser to its original state
				r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
				bodyStr := string(bodyBytes)
				if sqliRegex.MatchString(bodyStr) {
					reportThreat("SQL_INJECTION", ip, nil, r)
				} else if xssRegex.MatchString(bodyStr) {
					reportThreat("XSS_ATTACK", ip, nil, r)
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}
