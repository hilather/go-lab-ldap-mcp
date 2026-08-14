// Package auth implements the token registry, scopes, sessions, and
// authorization checks shared by REST, MCP, and browser sessions.
//
// Application mutations re-check authorization here even when transport
// middleware already ran. Token IDs never appear in missing-scope errors.
package auth
