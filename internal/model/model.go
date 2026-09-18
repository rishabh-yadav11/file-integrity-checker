// Package model defines the shared data types used across integrity-check:
// file entries recorded in a baseline, change kinds detected by `check`,
// and the algorithm identifiers supported by the hashing layer.
package model

import (
	"fmt"
	"time"
)

// Algorithm identifies a hash algorithm supported by integrity-check.
type Algorithm string

// Supported algorithms. SHA-256 is the default.
const (
	AlgoSHA256  Algorithm = "sha256"
	AlgoSHA512  Algorithm = "sha512"
	AlgoBLAKE2b Algorithm = "blake2b"
)

// ParseAlgorithm validates a user-supplied algorithm name.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch Algorithm(s) {
	case AlgoSHA256, AlgoSHA512, AlgoBLAKE2b:
		return Algorithm(s), nil
	case "":
		return AlgoSHA256, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %q (want sha256, sha512 or blake2b)", s)
	}
}

// ChangeKind describes how a file differs from the baseline.
type ChangeKind string

// Change kinds reported by check and update.
const (
	KindUnmodified ChangeKind = "unmodified"
	KindModified   ChangeKind = "modified"
	KindNew        ChangeKind = "new"
	KindMissing    ChangeKind = "missing"
)

// Entry is the recorded state of one regular file in a baseline.
// Path is slash-separated and relative to the scan root.
type Entry struct {
	Path      string    `json:"path"`
	Hash      string    `json:"hash"`
	Size      int64     `json:"size"`
	Mode      uint32    `json:"mode"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Mtime     time.Time `json:"mtime"`
	Algorithm Algorithm `json:"algorithm"`
}

// Result is the outcome of comparing one file against the baseline.
type Result struct {
	Path    string     `json:"path"`
	Kind    ChangeKind `json:"kind"`
	Reasons []string   `json:"reasons,omitempty"`
}

// Baseline is the signed on-disk document produced by init/update.
type Baseline struct {
	Version   int          `json:"version"`
	Algorithm Algorithm    `json:"algorithm"`
	CreatedAt time.Time    `json:"created_at"`
	Root      string       `json:"root"`
	Entries   []Entry      `json:"entries"`
}

// BaselineVersion is the current baseline format version.
const BaselineVersion = 1
