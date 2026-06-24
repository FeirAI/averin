// Command feir-proxy is the OpenAI-compatible reverse proxy. Point your agent's base_url at it; it
// forwards to the upstream LLM and records tamper-evident llm_call evidence to a feir server.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	// Timeouts on the INBOUND server (http.ListenAndServe leaves them unbounded → Slowloris). No WriteTimeout:
	// the proxy STREAMS long upstream completions back to the client, which must not be cut off.
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// Graceful shutdown: the proxy STREAMS long upstream completions, so an instant kill cuts an
	// agent's in-flight response. On SIGINT/SIGTERM, Shutdown lets active streams finish, bounded by
	// FEIR_SHUTDOWN_TIMEOUT (default 60s — longer than feir-server since completions stream). Keep it
	// under the orchestrator's stop grace (k8s terminationGracePeriod / compose stop_grace_period).
	drainTimeout := 60 * time.Second
	if v := os.Getenv("FEIR_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			drainTimeout = d
		} else {
			log.Printf("feir-proxy: ignoring invalid FEIR_SHUTDOWN_TIMEOUT %q (using %s)", v, drainTimeout)
		}
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.ListenAndServe() }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	case sig := <-stop:
		log.Printf("feir-proxy: received %s — draining in-flight streams (timeout %s)", sig, drainTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("feir-proxy: graceful shutdown timed out (a stream was cut): %v", err)
		}
		log.Print("feir-proxy: shutdown complete")
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
