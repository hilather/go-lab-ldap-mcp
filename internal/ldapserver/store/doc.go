// Package store provides the bbolt-backed implementation of the ldapserver
// Store interface: a single-file MVCC entry store under the engine data
// directory (compose: /data/labldapd.bolt, mode 0600) with the dn2id /
// id2entry layout and the Contract-tier equality indices internal to it
// (ADR-0009 decisions 5-8).
//
// The implementation lands in T-129 (the bbolt module version is pinned at
// first import). Until then this package carries only the boundary
// documentation, and the in-memory FakeStore in internal/ldapserver remains
// the store for protocol unit tests.
package store
