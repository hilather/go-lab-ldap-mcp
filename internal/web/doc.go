// Package web embeds static UI assets and hashed-asset helpers.
//
// It must not import internal/app. Session exchange and SPA-fallback
// routing live in cmd/labldap and internal/api. This package only
// exposes embed.FS, cache-policy helpers, and file serving.
package web
