package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestContentDirRefusal(t *testing.T) {
	const dsn = "postgres://u:p@h/db"
	cases := []struct {
		name       string
		dev        bool
		dsn, dir   string
		wantRefuse bool
	}{
		{"durable records, no content dir, production", false, dsn, "", true},
		{"durable records, content dir set", false, dsn, "/var/lib/averin/content", false},
		{"durable records, no content dir, dev mode", true, dsn, "", false},
		{"volatile everything, production gate handles it elsewhere", false, "", "", false},
		{"whitespace-only DSN is not a database", false, "  ", "", false},
	}
	for _, c := range cases {
		err := contentDirRefusal(c.dev, c.dsn, c.dir)
		if (err != nil) != c.wantRefuse {
			t.Errorf("%s: err=%v want refuse=%v", c.name, err, c.wantRefuse)
		}
		if err != nil && (!strings.Contains(err.Error(), "AVERIN_CONTENT_DIR") || !strings.Contains(err.Error(), "restart")) {
			t.Errorf("%s: the message must name AVERIN_CONTENT_DIR and why: %v", c.name, err)
		}
	}
}

func TestContentMemMaxBytesFromEnv(t *testing.T) {
	if n, err := contentMemMaxBytesFromEnv(""); n != 0 || err != nil {
		t.Fatalf("empty means the default: %d %v", n, err)
	}
	if n, err := contentMemMaxBytesFromEnv(" 1048576 "); n != 1048576 || err != nil {
		t.Fatalf("%d %v", n, err)
	}
	for _, bad := range []string{"0", "-5", "64MiB", "1.5"} {
		if _, err := contentMemMaxBytesFromEnv(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// TestDefaults_RefuseDurableRecordsWithVolatileContent: with a database but no AVERIN_CONTENT_DIR the real
// binary exits at startup, before it touches the database, naming AVERIN_CONTENT_DIR.
func TestDefaults_RefuseDurableRecordsWithVolatileContent(t *testing.T) {
	bin, _ := buildForDefaults(t)
	out, err := runToExit(t, bin, "AVERIN_SIGNING_SEED="+strings.Repeat("a1", 32), "AVERIN_API_KEYS=proj:tok",
		"AVERIN_DATABASE_URL=postgres://u:p@127.0.0.1:1/none")
	if ee, ok := err.(*exec.ExitError); !ok || ee.Success() || !strings.Contains(out, "AVERIN_CONTENT_DIR") {
		t.Fatalf("a database without a content dir must be refused at startup: %v\n%s", err, out)
	}
}
