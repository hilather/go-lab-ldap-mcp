package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// StoreFileName is the bbolt database file inside a native data directory.
const StoreFileName = "labldapd.bolt"

// boltMagic is go.etcd.io/bbolt's on-disk marker (internal/common.Magic).
const boltMagic uint32 = 0xED0CDAED

// ErrEngineDataMismatch reports a data directory that is not a native
// labldapd store. Callers test with errors.Is. The message never includes
// file contents.
var ErrEngineDataMismatch = errors.New("store: data directory is not a native labldapd store")

// AssertNativeDataDir refuses to proceed when dir looks like a 389
// Directory Server nsslapd tree or contains a labldapd.bolt that is not a
// bbolt database. A missing directory is acceptable (the daemon creates
// it). The check must run before Open so a 389 volume does not get a new
// bolt file created beside it.
func AssertNativeDataDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("store: empty data directory")
	}
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store: stat data directory: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("%w: data path is not a directory", ErrEngineDataMismatch)
	}
	if looksLike389Tree(dir) {
		return fmt.Errorf("%w: looks like a 389 Directory Server tree; run compose-reset or set engine: 389ds", ErrEngineDataMismatch)
	}
	boltPath := filepath.Join(dir, StoreFileName)
	bst, err := os.Stat(boltPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store: stat database: %w", err)
	}
	if bst.IsDir() {
		return fmt.Errorf("%w: labldapd.bolt is a directory", ErrEngineDataMismatch)
	}
	if !isBoltDB(boltPath) {
		return fmt.Errorf("%w: labldapd.bolt is not a bbolt database; run compose-reset or set engine: 389ds", ErrEngineDataMismatch)
	}
	return nil
}

func looksLike389Tree(dir string) bool {
	markers := []string{
		"container.inf",
		filepath.Join("config", "container.inf"),
		filepath.Join("config", "dse.ldif"),
		"dse.ldif",
	}
	for _, rel := range markers {
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			return true
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, "slapd-") {
			return true
		}
	}
	return false
}

func isBoltDB(path string) bool {
	if hasBoltMagic(path) {
		return true
	}
	// Authoritative check: a readable bbolt file opens read-only.
	db, err := bolt.Open(path, fileMode, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return false
	}
	_ = db.Close()
	return true
}

func hasBoltMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	// Meta.magic sits after the 16-byte page header; also accept offset 0
	// in case a future layout writes the marker first.
	buf := make([]byte, 32)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false
	}
	if n < 4 {
		return false
	}
	if binary.LittleEndian.Uint32(buf[:4]) == boltMagic {
		return true
	}
	if n >= 20 && binary.LittleEndian.Uint32(buf[16:20]) == boltMagic {
		return true
	}
	return false
}
