// Package parity implements the T-147 dual-engine parity harness described
// in docs/design/native-engine-parity-contract.md.
//
// One scenario fixture is compiled once and applied to a fresh native
// engine (internal/ldapserver, in-process, no Docker) and — under the
// integration build tag — to a fresh pinned 389 Directory Server container
// (the oracle). Every Contract-tier case executes the SAME LDAP operation
// sequence against both engines and compares canonicalized outcomes
// (result codes, normalized DNs, attribute sets with secrets stripped).
// Control-plane cases (controlplane.go) additionally drive internal/app
// + ds389.Runtime against each engine (contract section 5 rule 2).
//
// Contract mismatches fail the build. Known differences are adjudicated
// through the CAND-* probe set: each probe runs against both engines and
// records the oracle and native outcomes into the machine-readable delta
// ledger (delta-ledger.json). The committed ledger is a golden file: a
// drift in either engine's observed behavior fails the integration run
// until the ledger is deliberately regenerated (PARITY_UPDATE_LEDGER=1).
//
// The suite runs hermetically (native only) under `go test ./test/parity/`
// and dual-engine under `go test -tags integration ./test/parity/`.
package parity
