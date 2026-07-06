// Command averin-mcp is an experimental MCP (Model Context Protocol) server over stdio, exposing averin
// to agents as tools. Point it at a running averin server with AVERIN_SERVER_URL.
package main

import (
	"log"
	"os"

	"github.com/averin-dev/averin/server/internal/mcp"
)

func main() {
	averinURL := os.Getenv("AVERIN_SERVER_URL")
	if averinURL == "" {
		averinURL = "http://localhost:8080"
	}
	if err := mcp.New(averinURL).Serve(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
