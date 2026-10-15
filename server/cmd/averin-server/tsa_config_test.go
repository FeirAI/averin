package main

import "testing"

func TestResolveTSAConfig(t *testing.T) {
	// default: off
	if u, pin, err := resolveTSAConfig("", ""); err != nil || u != "" || pin != "" {
		t.Fatalf("default must be off: %q %q %v", u, pin, err)
	}
	// preset: one setting
	u, pin, err := resolveTSAConfig("freetsa", "")
	if err != nil || u != "https://freetsa.org/tsr" || pin == "" {
		t.Fatalf("freetsa preset: %q %q %v", u, pin, err)
	}
	// any other authority by URL, no pin implied
	if u, pin, err := resolveTSAConfig("", "https://tsa.example.com/ts"); err != nil || u != "https://tsa.example.com/ts" || pin != "" {
		t.Fatalf("url: %q %q %v", u, pin, err)
	}
	// fail closed on ambiguity and on typos
	if _, _, err := resolveTSAConfig("freetsa", "https://tsa.example.com"); err == nil {
		t.Fatal("preset plus URL must be refused")
	}
	if _, _, err := resolveTSAConfig("freetsaa", ""); err == nil {
		t.Fatal("unknown preset must be refused")
	}
}

func TestTSAAuthHeaderRequiresHTTPS(t *testing.T) {
	if err := checkTSAAuthTransport("http://timestamp.digicert.com", "Bearer x"); err == nil {
		t.Fatal("a credential header with an http TSA URL must refuse start-up")
	}
	if err := checkTSAAuthTransport("ftp://tsa.example.com", "Bearer x"); err == nil {
		t.Fatal("a credential header with a non-https scheme must refuse start-up")
	}
	if err := checkTSAAuthTransport("tsa.example.com/ts", "Bearer x"); err == nil {
		t.Fatal("a credential header with a scheme-less URL must refuse start-up")
	}
	if err := checkTSAAuthTransport("https://tsa.example.com/ts", "Bearer x"); err != nil {
		t.Fatalf("https with a header is the supported shape: %v", err)
	}
	if err := checkTSAAuthTransport("http://timestamp.digicert.com", ""); err != nil {
		t.Fatalf("no credential, nothing to protect: %v", err)
	}
	if err := checkTSAAuthTransport("", "Bearer x"); err != nil {
		t.Fatalf("anchoring off: %v", err)
	}
}
