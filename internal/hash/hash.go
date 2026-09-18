// Package hash computes file digests with configurable algorithms,
// using chunked reads for large files and a bounded worker pool.
package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"sync"

	"golang.org/x/crypto/blake2b"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// chunkSize bounds memory use per read (1 MiB).
const chunkSize = 1 << 20

// newHasher returns a hash.Hash for the given algorithm.
func newHasher(algo model.Algorithm) (hash.Hash, error) {
	switch algo {
	case model.AlgoSHA256:
		return sha256.New(), nil
	case model.AlgoSHA512:
		return sha512.New(), nil
	case model.AlgoBLAKE2b:
		// 32-byte output, no key: standard digest form of BLAKE2b.
		return blake2b.New256(nil)
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algo)
	}
}

// File hashes the contents of path using algo, reading in fixed-size
// chunks so arbitrarily large files hash in bounded memory. Directories
// are rejected up front: reading a directory as an io.Reader blocks.
func File(path string, algo model.Algorithm) (string, error) {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return "", fmt.Errorf("cannot hash directory %s", path)
	}
	h, err := newHasher(algo)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := io.CopyBuffer(h, io.LimitReader(f, 1<<62), make([]byte, chunkSize)); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// Job is one unit of hashing work produced by a walker.
type Job struct {
	Path  string // absolute or root-relative path to hash
	Entry *model.Entry
}

// Pool runs hashing jobs across a bounded worker pool.
// Results are delivered on the returned channel; errCh carries per-file
// read errors so callers can fail without losing successful siblings.
type Pool struct {
	workers int
	jobs    chan Job
	results chan *model.Entry
	errCh   chan error
	wg      sync.WaitGroup
}

// NewPool starts workers goroutines ready to accept jobs.
func NewPool(workers int) *Pool {
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers < 1 {
			workers = 1
		}
	}
	p := &Pool{
		workers: workers,
		jobs:    make(chan Job, workers*4),
		results: make(chan *model.Entry, workers*4),
		errCh:   make(chan error, workers*4),
	}
	return p
}

// Start launches the worker goroutines.
func (p *Pool) Start(algo model.Algorithm) {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for job := range p.jobs {
				sum, err := File(job.Path, algo)
				if err != nil {
					p.errCh <- err
					continue
				}
				job.Entry.Hash = sum
				p.results <- job.Entry
			}
		}()
	}
}

// Submit enqueues one file for hashing. Call Close when all jobs are
// submitted; workers exit once the queue drains.
func (p *Pool) Submit(j Job) { p.jobs <- j }

// Close signals that no more jobs will be submitted. After all queued
// jobs are processed, Wait unblocks and result/error channels close.
// Close must be called exactly once, before Wait.
func (p *Pool) Close() { close(p.jobs) }

// Results is the channel of completed entries.
func (p *Pool) Results() <-chan *model.Entry { return p.results }

// Errors is the channel of per-file errors.
func (p *Pool) Errors() <-chan error { return p.errCh }

// Wait blocks until all workers finish and closes result/error channels.
func (p *Pool) Wait() {
	p.wg.Wait()
	close(p.results)
	close(p.errCh)
}
