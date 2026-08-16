// Package store provides the bbolt-backed implementation of the ldapserver
// Store interface: a single-file MVCC entry store under the engine data
// directory (compose: /data/labldapd.bolt, mode 0600) with the dn2id /
// id2entry layout (ADR-0009 decisions 5-8).
//
// The dn2id bucket maps canonical case-folded DN keys
// (config.DN.FoldedKey) to 8-byte entry ids; id2entry maps ids to
// serialized entries (codec.go); a children bucket holds one nested bucket
// per parent folded DN containing child ids, which backs Children, the
// recursive Subtree walk, and the Delete leaf guard. One Store.Update is
// one bbolt transaction, so writes are crash-safe and concurrent readers
// see pre- or post-commit snapshots (MVCC, ADR-0009 decision 7).
//
// The Contract-tier equality indices (uid, cn, member, uniqueMember,
// objectClass) land with T-130 and are likewise internal to this package.
// The in-memory FakeStore in internal/ldapserver remains the store for
// protocol unit tests that do not need persistence.
package store
