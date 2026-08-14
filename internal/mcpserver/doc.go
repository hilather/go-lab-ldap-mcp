// Package mcpserver is the MCP transport (official Go SDK).
//
// It registers tools and resources and maps inputs to application
// commands. It must not import internal/api or talk to LDAP directly.
// Both REST and MCP call internal/app (KD-R8). Authorization is
// re-checked inside application services (T-057).
package mcpserver
