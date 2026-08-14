// Package audit records structured security and mutation events.
//
// Event payloads must never include tokens, passwords, session cookie
// values, authorization headers, or secret-file contents. Actor is a
// non-secret token ID or session ID (for example "token:admin").
//
// The production sink is a bounded in-memory ring plus a structured log.
// Default capacity is 4096 events. Events older than DefaultTTL (24h) are
// omitted from queries. There is no persistent audit database in v1;
// process restart drops the ring. AuditSink / Hook is the extension point.
package audit
