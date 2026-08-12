// Package app holds transport-neutral use cases: users, groups, search,
// bind-test, reset, export, capabilities, and baseline.
//
// Handlers in internal/api and tools in internal/mcpserver call these
// interfaces. This package must not import either transport.
package app
