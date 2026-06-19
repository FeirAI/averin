// Command feir-proxy is the OpenAI-compatible reverse proxy. Point your agent's base_url at it; it
// forwards to the upstream LLM and records tamper-evident llm_call evidence to a feir server.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/feir-dev/feir/server/internal/proxy"
)

func main() {
	upstream := envOr("FEIR_UPSTREAM", "https://api.openai.com")
	feirURL := envOr("FEIR_SERVER_URL", "http://localhost:8080")
	projectID := envOr("FEIR_PROJECT_ID", "default")
	addr := envOr("FEIR_PROXY_ADDR", ":8081")

	rec := &proxy.HTTPRecorder{URL: feirURL, Token: os.Getenv("FEIR_PROXY_FEIR_TOKEN")}
	p := proxy.New(upstream, projectID, rec)
	if inbound := os.Getenv("FEIR_PROXY_INBOUND_TOKEN"); inbound != "" {
		p.WithInboundAuth(inbound)
		log.Printf("feir-proxy: inbound auth REQUIRED (X-Feir-Proxy-Token / Authorization: Bearer)")
	} else {
		log.Printf("feir-proxy: WARNING — no FEIR_PROXY_INBOUND_TOKEN set: this is an OPEN RELAY + evidence-injection surface; bind to loopback or place behind your own auth")
	}
	log.Printf("feir-proxy on %s -> upstream %s, recording to %s", addr, upstream, feirURL)
	log.Fatal(http.ListenAndServe(addr, p.Handler()))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
