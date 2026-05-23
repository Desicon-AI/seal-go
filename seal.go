package seal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

type WafConfig struct {
	GeoBlocking       struct { BlockedCountries []string; Action string }
	MaliciousScanners struct { Action string }
	MethodTampering   struct { Action string }
	PayloadOverflow   struct { MaxPayloadSize int64; Action string }
	PathTraversal     struct { Action string }
}

type Options struct {
	APIKey      string
	AppName     string
	Environment string
	Endpoint    string
	Sandbox     bool
	WAF         WafConfig
}

var (
	clientOptions Options
	initialized   bool
	startTime     int64
)

// Init initializes the Seal engine
func Init(opts Options) {
	if initialized {
		return
	}

	if opts.AppName == "" {
		opts.AppName = "go-app"
	}
	if opts.Environment == "" {
		opts.Environment = "production"
	}
	
	if opts.Sandbox {
		opts.Endpoint = "https://sealengine.desicon.ai/api/v1/sandbox/ingest"
	} else if opts.Endpoint == "" {
		opts.Endpoint = "https://sealengine.desicon.ai/api/v1/ingest"
	}
	
	// Set default WAF actions to report if not specified
	if opts.WAF.PayloadOverflow.MaxPayloadSize == 0 {
		opts.WAF.PayloadOverflow.MaxPayloadSize = 5242880 // 5MB
	}

	clientOptions = opts
	startTime = time.Now().UnixMilli()
	initialized = true

	if opts.APIKey == "" {
		fmt.Println("[Seal] Warning: Missing API Key. Crashes will not be reported.")
	}

	// Ping to resolve old errors
	go func() {
		req, _ := http.NewRequest("POST", opts.Endpoint+"/ping", nil)
		req.Header.Set("X-API-Key", opts.APIKey)
		client := &http.Client{Timeout: 3 * time.Second}
		client.Do(req)
	}()

	// Start Heartbeat Goroutine
	go heartbeatLoop()

	fmt.Printf("[Seal.ai] Initialized for %s (%s). We are watching you.\n", opts.AppName, opts.Environment)
}

func heartbeatLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Initial ping
	sendHeartbeat()

	for range ticker.C {
		sendHeartbeat()
	}
}

func sendHeartbeat() {
	if clientOptions.APIKey == "" {
		return
	}
	payload := map[string]interface{}{
		"app_name":    clientOptions.AppName,
		"environment": clientOptions.Environment,
		"started_at":  startTime,
		"source":      "server_goroutine",
	}
	sendAsyncPayload(clientOptions.Endpoint+"/heartbeat", payload)
}

// Recover is a middleware/defer wrapper to catch panics
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				handlePanic(err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func handlePanic(err interface{}) {
	if clientOptions.APIKey == "" {
		return
	}

	stack := string(debug.Stack())
	errorMsg := fmt.Sprintf("%v", err)

	payload := map[string]interface{}{
		"app_name":      clientOptions.AppName,
		"environment":   clientOptions.Environment,
		"error_type":    "GoPanic",
		"error_message": errorMsg,
		"stack_trace":   stack,
		"code_context":  "Context extraction pending implementation in Go.",
	}

	sendAsyncPayload(clientOptions.Endpoint, payload)
}

func reportThreat(threatType, ip string, details map[string]interface{}, r *http.Request) {
	if clientOptions.APIKey == "" {
		return
	}

	if details == nil {
		details = make(map[string]interface{})
	}
	details["method"] = r.Method
	details["url"] = r.URL.String()

	payload := map[string]interface{}{
		"app_name":    clientOptions.AppName,
		"environment": clientOptions.Environment,
		"ip_address":  ip,
		"threat_type": threatType,
		"context":     details,
	}

	endpoint := strings.Replace(clientOptions.Endpoint, "/ingest", "/ingest/threat", 1)
	go sendAsyncPayload(endpoint, payload)
}

func RegisterDeployment(version string) {
	if clientOptions.APIKey == "" {
		return
	}
	if version == "" {
		version = "unknown"
	}
	
	payload := map[string]interface{}{
		"version":     version,
		"environment": clientOptions.Environment,
	}

	endpoint := strings.Replace(clientOptions.Endpoint, "/ingest", "/deployment", 1)
	endpoint = strings.Replace(endpoint, "/api/v1/sandbox/deployment", "/api/v1/deployment", 1)
	go sendAsyncPayload(endpoint, payload)
}

func sendAsyncPayload(url string, payload map[string]interface{}) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", clientOptions.APIKey)

	client := &http.Client{Timeout: 5 * time.Second}
	client.Do(req)
}
