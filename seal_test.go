package seal

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestSignedTransportAndAcknowledgement(t *testing.T) {
    clientOptions = Options{APIKey:"synthetic", SigningSecret:"synthetic-secret"}
    calls := 0
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        calls++
        body, _ := io.ReadAll(r.Body)
        signature := hmac.New(sha256.New, []byte(clientOptions.SigningSecret))
        signature.Write(append([]byte(r.Header.Get("X-Seal-Timestamp")+"."),body...))
        if r.Header.Get("X-Seal-Signature") != hex.EncodeToString(signature.Sum(nil)) { t.Error("signature does not match actual body") }
        if r.Header.Get("X-API-Key") != "synthetic" { t.Error("missing project key") }
        if calls == 1 { w.Write([]byte(`{"status":"ok"}`)) } else { w.WriteHeader(503) }
    }))
    defer server.Close()
    payload := map[string]interface{}{"app_name":"test","environment":"staging"}
    if err := sendAsyncPayload(server.URL+"/heartbeat",payload); err != nil { t.Fatal(err) }
    if err := sendAsyncPayload(server.URL+"/heartbeat",payload); err == nil { t.Fatal("HTTP 503 must not be acknowledged") }
}

func TestAuxiliaryRoutes(t *testing.T) {
    clientOptions.Endpoint = "https://example.test/custom/sandbox/ingest/"
    if got := auxiliaryEndpoint("/deployment"); got != "https://example.test/custom/ingest/deployment" { t.Fatal(got) }
    if err := sendAsyncPayload(":bad-url",nil); err == nil { t.Fatal("invalid URL must return an error") }
}

func TestNormalClientsAndRequestBodyArePreserved(t *testing.T) {
    initialized = true
    clientOptions = Options{}
    clientOptions.WAF.MaliciousScanners.Action = "drop"
    clientOptions.WAF.PathTraversal.Action = "drop"
    clientOptions.WAF.PayloadOverflow.MaxPayloadSize = 5242880
    next := http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
        body,_ := io.ReadAll(r.Body)
        if string(body) != "legitimate body" { t.Error("request body changed") }
        w.WriteHeader(200)
    })
    for _, ua := range []string{"curl/8","python-requests/2","wget/1"} {
        request := httptest.NewRequest("POST","http://example.test/api/select/update",strings.NewReader("legitimate body"))
        request.Header.Set("User-Agent",ua)
        response := httptest.NewRecorder()
        WAFMiddleware(next).ServeHTTP(response,request)
        if response.Code != 200 { t.Fatalf("%s blocked: %d",ua,response.Code) }
    }
    response := httptest.NewRecorder()
    WAFMiddleware(next).ServeHTTP(response,httptest.NewRequest("GET","http://example.test/../secret",nil))
    if response.Code != 403 { t.Fatal("explicit traversal rule no longer enforces") }
}
