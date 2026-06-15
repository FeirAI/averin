// Command feir-mcp is an experimental MCP (Model Context Protocol) server over stdio, exposing feir
// to agents as tools. Point it at a running feir server with FEIR_SERVER_URL.
package main

import (
	"log"
	"os"

	"github.com/feir-dev/feir/server/internal/mcp"
)

func main() {
	feirURL := os.Getenv("FEIR_SERVER_URL")
	if feirURL == "" {
		feirURL = "http://localhost:8080"
	}
	if err := mcp.New(feirURL).Serve(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
