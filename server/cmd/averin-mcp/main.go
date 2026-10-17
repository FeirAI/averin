// Command averin-mcp is an experimental MCP (Model Context Protocol) server over stdio, exposing averin
// to agents as tools. Point it at a running averin server with AVERIN_SERVER_URL.
// A server outside AVERIN_DEV_MODE refuses requests without a token: set AVERIN_API_TOKEN (sent as a Bearer token).
package main

import (
	"log"
	"os"

	"github.com/feirai/averin/server/internal/mcp"
)

func main() {
	averinURL := os.Getenv("AVERIN_SERVER_URL")
	if averinURL == "" {
		averinURL = "http://localhost:8080"
	}
	if err := mcp.New(averinURL).WithToken(os.Getenv("AVERIN_API_TOKEN")).Serve(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
