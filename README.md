# Seal Go SDK alignment candidate

`Options` supports `APIKey`, `SigningSecret`, `AppName`, `Environment`, `Endpoint`, `Sandbox`, and `WAF`. SigningSecret enables HMAC over the exact transmitted body, including startup and every heartbeat. Auxiliary routes are `/ingest/ping`, `/ingest/heartbeat`, `/ingest/deployment` and `/ingest/threat`; sandbox error ingestion remains `/sandbox/ingest`.

Heartbeat checks run every 60 seconds. `HeartbeatDeliveryOK()` reports the latest acknowledgement; HTTP errors and negative heartbeat responses are failures. Response bodies are closed. This monitors a logical application/environment, not each replica.

WAF actions remain explicitly configured. curl, wget and Python requests are normal clients; forwarded identity/country headers require `WAF.TrustProxyHeaders` behind a trusted proxy. Threat telemetry uses a path hash, not a raw URL. Middleware preserves application request bodies. This SDK does not execute rescue patches.

Run `go test -v ./...`. GitHub Actions runs the same suite. Package publication/tagging remains separate from this review branch.
