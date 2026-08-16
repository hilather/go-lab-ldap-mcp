package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// StoreFileName is the bbolt database file inside a native data directory
// (ADR-0009; deploy/docker/labldapd-image-contract.md).
const StoreFileName = "labldapd.bolt"

// bboltMagic is the on-disk meta-page magic (go.etcd.io/bbolt). It sits
// immediately after the 16-byte page header. Used only to refuse a
// non-bbolt labldapd.bolt — we never log or return file contents.
const (
	bboltPageHeaderSize = 16
	bboltMagic          = 0xED0CDAED
)

// ErrEngineDataMismatch reports that the data directory belongs to another
// engine (typically a 389 nsslapd tree) or that labldapd.bolt exists but
// is not a bbolt file. Callers map this to apperr CodeConfiguration /
// engine_data_mismatch. The error text is secret-free.
var ErrEngineDataMismatch = errors.New("store: data directory is not a native engine store")

// CheckDataDir fails closed when dir looks like a 389 nsslapd tree or
// when labldapd.bolt exists and is not a bbolt database. An absent
// directory or an empty native dir is allowed (Open will create the file).
// Errors never include file contents.
func CheckDataDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("%w: empty data directory", ErrEngineDataMismatch)
	}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store: stat data directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: data path is not a directory", ErrEngineDataMismatch)
	}
	if looksLike389Tree(dir) {
		return fmt.Errorf("%w: 389 nsslapd markers present", ErrEngineDataMismatch)
	}
	boltPath := filepath.Join(dir, StoreFileName)
	st, err := os.Stat(boltPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store: stat database: %w", err)
	}
	if st.IsDir() {
		return fmt.Errorf("%w: %s is a directory", ErrEngineDataMismatch, StoreFileName)
	}
	return inspectBoltFile(boltPath)
}

func looksLike389Tree(dir string) bool {
	for _, rel := range []string{"container.inf", filepath.Join("config", "container.inf")} {
		if fileExists(filepath.Join(dir, rel)) {
			return true
		}
	}
	for _, parent := range []string{dir, filepath.Join(dir, "config")} {
		if hasSlapdDir(parent) {
			return true
		}
	}
	return false
}

func hasSlapdDir(parent string) bool {
	ents, err := os.ReadDir(parent)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "slapd-") {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// inspectBoltFile reports ErrEngineDataMismatch when path exists and is
// not a bbolt database. Open/read failures (permission, I/O) are returned
// as-is so callers do not tell operators to compose-reset.
func inspectBoltFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: open database: %w", err)
	}
	defer func() { _ = f.Close() }()
	var hdr [bboltPageHeaderSize + 4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: %s is not a bbolt database", ErrEngineDataMismatch, StoreFileName)
		}
		return fmt.Errorf("store: read database: %w", err)
	}
	if binary.LittleEndian.Uint32(hdr[bboltPageHeaderSize:]) != bboltMagic {
		return fmt.Errorf("%w: %s is not a bbolt database", ErrEngineDataMismatch, StoreFileName)
	}
	return nil
}
