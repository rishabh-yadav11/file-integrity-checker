package hash

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

// BenchmarkFile50MB measures raw hashing throughput of one large file
// (chunked reads, sha256).
func BenchmarkFile50MB(b *testing.B) {
	dir := b.TempDir()
	p := dir + "/f50mb"
	if err := os.WriteFile(p, make([]byte, 50<<20), 0o644); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(50 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := File(p, model.AlgoSHA256); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPool500x300KB hashes 500 x 300KB files with N workers to
// expose wall time and allocation churn (the per-file 1MiB chunk
// buffer). Drains results concurrently like walk.Scan does.
func BenchmarkPool500x300KB(b *testing.B) {
	dir := b.TempDir()
	sub := dir + "/d"
	if err := os.Mkdir(sub, 0o755); err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 300*1024)
	for i := 0; i < 500; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s/f%03d.dat", sub, i), buf, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	for _, workers := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("workers%d", workers), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pool := NewPool(workers)
				pool.Start(model.AlgoSHA256)
				n := 0
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range pool.Results() {
						n++
					}
				}()
				for j := 0; j < 500; j++ {
					p := fmt.Sprintf("%s/f%03d.dat", sub, j)
					pool.Submit(Job{Path: p, Entry: &model.Entry{Path: p}})
				}
				pool.Close()
				pool.Wait()
				wg.Wait()
				for range pool.Errors() {
				}
				if n != 500 {
					b.Fatalf("got %d results", n)
				}
			}
		})
	}
}
