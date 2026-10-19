package api

import (
	"net/http"

	"github.com/feirai/averin/server/internal/auth"
)

// writeRoutes are the POST routes that add evidence. A token with the write role may call them.
var writeRoutes = map[string]bool{
	"/v2/records":         true,
	"/v2/grants":          true,
	"/v2/grants/prepare":  true,
	"/v2/grants/finalize": true,
	"/v2/introspection":   true,
	"/v2/refusals":        true,
	"/v2/use":             true,
	"/v2/use-intent":      true,
	"/v2/use-outcome":     true,
	"/v2/otel/traces":     true,
}

// requiredRole is the role a request needs under scoped tokens (AVE-05). GET and HEAD need read. The
// evidence-adding POST routes need write. Everything else is admin, including revoke, checkpoints, any
// other method and any path not listed, so a route added later is admin-only until it is classified.
func requiredRole(r *http.Request) auth.Role {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return auth.RoleRead
	case http.MethodPost:
		if writeRoutes[r.URL.Path] {
			return auth.RoleWrite
		}
	}
	return auth.RoleAdmin
}
