// Package baseline stores and loads signed baseline files.
//
// On-disk format (JSON):
//
//	{
//	  "algorithm": "sha256",
//	  "created_at": "...",
//	  "root": "/var/log",
//	  "entries": [...],
//	  "hmac": "hex(HMAC-SHA256(key, canonical-payload))"
//	}
//
// The HMAC covers algorithm, created_at, root and every entry (path,
// hash, size, mode, uid, gid, mtime, algorithm) encoded via
// encoding/json with sorted struct fields, so any byte-level tamper
// with the document invalidates the signature. Files are written
// atomically (temp file + rename) with 0600 permissions.
package baseline

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// Store is a signed baseline bound to an HMAC key.
type Store struct {
	key []byte
}

// New creates a store with the given HMAC key (never empty).
func New(key []byte) (*Store, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("baseline: empty HMAC key")
	}
	return &Store{key: key}, nil
}

// signedDoc is the internal HMAC-computed shape (no hmac field).
type signedDoc struct {
	Version   int             `json:"version"`
	Algorithm model.Algorithm `json:"algorithm"`
	CreatedAt string          `json:"created_at"`
	Root      string          `json:"root"`
	Entries   []model.Entry   `json:"entries"`
}

// doc is the full on-disk document including the HMAC tag.
type doc struct {
	signedDoc
	HMAC string `json:"hmac"`
}

// computeMAC serializes the signed part deterministically and HMACs it,
// returning an error instead of a silent empty tag on failure.
func (s *Store) computeMAC(d signedDoc) (string, error) {
	b, err := json.Marshal(d) // struct field order is fixed => deterministic
	if err != nil {
		return "", fmt.Errorf("baseline: serialize for MAC: %w", err)
	}
	m := hmac.New(sha256.New, s.key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// Save writes b to path atomically with 0600 permissions and an HMAC tag.
func (s *Store) Save(path string, b model.Baseline) error {
	sd := signedDoc{
		Version:   b.Version,
		Algorithm: b.Algorithm,
		CreatedAt: b.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Root:      b.Root,
		Entries:   b.Entries,
	}
	d := doc{signedDoc: sd}
	mac, err := s.computeMAC(sd)
	if err != nil {
		return err
	}
	d.HMAC = mac
	payload, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(path)
	// The requested baseline location may live in a directory that does
	// not exist yet (e.g. --baseline state/baseline.json on first run).
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("baseline: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".baseline-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// Best-effort directory fsync so the rename survives power loss.
	if dfd, err := os.Open(dir); err == nil {
		_ = dfd.Sync()
		_ = dfd.Close()
	}
	return nil
}

// ErrTampered is returned when the baseline HMAC does not verify.
var ErrTampered = errors.New("baseline: HMAC verification failed (baseline may be tampered)")

// Load reads path, verifies the HMAC, and returns the baseline.
func (s *Store) Load(path string) (model.Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.Baseline{}, err
	}
	var d doc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return model.Baseline{}, fmt.Errorf("baseline: parse %s: %w", path, err)
	}
	// A valid HMAC must cover the entire file: reject any non-whitespace
	// trailing content after the JSON document (attacker appending bytes
	// that the decoder would otherwise ignore).
	if dec.More() {
		return model.Baseline{}, fmt.Errorf("baseline: parse %s: trailing data after JSON document", path)
	}
	want, err := s.computeMAC(d.signedDoc)
	if err != nil {
		return model.Baseline{}, err
	}
	if !hmac.Equal([]byte(want), []byte(d.HMAC)) {
		return model.Baseline{}, ErrTampered
	}
	created, err := parseTime(d.CreatedAt)
	if err != nil {
		return model.Baseline{}, fmt.Errorf("baseline: bad created_at: %w", err)
	}
	b := model.Baseline{
		Version:   d.Version,
		Algorithm: d.Algorithm,
		CreatedAt: created,
		Root:      d.Root,
		Entries:   d.Entries,
	}
	if b.Version != model.BaselineVersion {
		return b, fmt.Errorf("baseline: unsupported version %d (want %d)", b.Version, model.BaselineVersion)
	}
	if _, err := model.ParseAlgorithm(string(b.Algorithm)); err != nil {
		return b, fmt.Errorf("baseline: %w", err)
	}
	return b, nil
}
