// Package ui serves the local dashboard. This file holds only the embedded
// static assets and a content-type helper; the server, guard and API handlers
// live in their own files. Keep this file init-free: internal/ui is linked
// into the hook binary and the fast path must not pay for it.
package ui

import (
	"embed"
	"strings"
)

// StaticFS holds internal/ui/static: index.html, app.css, app.js, pages.js,
// map.js and map.css. Embedding is static data with no init cost.
//
//go:embed static
var StaticFS embed.FS

// ContentType returns the explicit Content-Type for a static path. It does
// not use package mime (its init registers types and reads system tables);
// the guard sets X-Content-Type-Options: nosniff, so every type is spelled
// out here. Unknown extensions fall back to application/octet-stream.
func ContentType(path string) string {
	ext := path
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		ext = path[i:]
	} else {
		ext = ""
	}
	switch strings.ToLower(ext) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".json":
		return "application/json"
	case ".txt", ".md":
		return "text/plain; charset=utf-8"
	}
	return "application/octet-stream"
}
