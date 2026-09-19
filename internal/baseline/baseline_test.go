package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

func testKey() []byte { return []byte("test-key-do-not-use-in-prod") }

func sampleBaseline(t time.Time) model.Baseline {
	return model.Baseline{
		Version:   model.BaselineVersion,
		Algorithm: model.AlgoSHA256,
		CreatedAt: t,
		Root:      "/var/log",
		Entries: []model.Entry{
			{Path: "a.log", Hash: "aaaa", Size: 10, Mode: 0o644, UID: 0, GID: 0,
				Mtime: t, Algorithm: model.AlgoSHA256},
			{Path: "sub/b.log", Hash: "bbbb", Size: 20, Mode: 0o600, UID: 1000, GID: 1000,
				Mtime: t.Add(time.Second), Algorithm: model.AlgoSHA256},
		},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()
	key := testKey()
	st, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	b := sampleBaseline(now)
	path := filepath.Join(t.TempDir(), "baseline.json")

	if err := st.Save(path, b); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := st.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Algorithm != b.Algorithm || got.Root != b.Root || got.Version != b.Version {
		t.Fatalf("metadata mismatch: %+v", got)
	}
	if len(got.Entries) != len(b.Entries) {
		t.Fatalf("entries: got %d want %d", len(got.Entries), len(b.Entries))
	}
	for i, e := range got.Entries {
		if e != b.Entries[i] {
			t.Errorf("entry[%d] = %+v, want %+v", i, e, b.Entries[i])
		}
	}
}

func TestSavePerms0600(t *testing.T) {
	t.Parallel()
	st, _ := New(testKey())
	path := filepath.Join(t.TempDir(), "b.json")
	if err := st.Save(path, sampleBaseline(time.Now())); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("baseline perms = %v, want -rw-------", info.Mode().Perm())
	}
}

func TestSaveAtomicNoTempLeftovers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	st, _ := New(testKey())
	path := filepath.Join(dir, "b.json")
	for i := 0; i < 3; i++ {
		if err := st.Save(path, sampleBaseline(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	fis, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, fi := range fis {
		if strings.HasPrefix(fi.Name(), ".baseline-") && strings.HasSuffix(fi.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", fi.Name())
		}
	}
}

func TestTamperDetection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(raw []byte) []byte
	}{
		{"flip hash", func(r []byte) []byte { return []byte(strings.Replace(string(r), "aaaa", "aaab", 1)) }},
		{"flip size", func(r []byte) []byte { return []byte(strings.Replace(string(r), `"size": 10`, `"size": 11`, 1)) }},
		{"flip mode", func(r []byte) []byte { return []byte(strings.Replace(string(r), "420", "438", 1)) }},
		{"add entry", func(r []byte) []byte {
			var d map[string]any
			_ = json.Unmarshal(r, &d)
			entries := d["entries"].([]any)
			entries = append(entries, map[string]any{
				"path": "evil.log", "hash": "cccc", "size": 1, "mode": 420,
				"uid": 0, "gid": 0, "mtime": "2020-01-01T00:00:00Z", "algorithm": "sha256",
			})
			d["entries"] = entries
			out, _ := json.Marshal(d)
			return out
		}},
		{"drop entry", func(r []byte) []byte {
			var d map[string]any
			_ = json.Unmarshal(r, &d)
			entries := d["entries"].([]any)
			d["entries"] = entries[:1]
			out, _ := json.Marshal(d)
			return out
		}},
		{"bad hmac", func(r []byte) []byte {
			return []byte(strings.Replace(string(r), `"hmac": "`, `"hmac": "0`, 1))
		}},
		{"missing hmac", func(r []byte) []byte {
			var d map[string]any
			_ = json.Unmarshal(r, &d)
			delete(d, "hmac")
			out, _ := json.Marshal(d)
			return out
		}},
		{"flip root", func(r []byte) []byte { return []byte(strings.Replace(string(r), "/var/log", "/var/lg", 1)) }},
		{"flip created_at", func(r []byte) []byte {
			var d map[string]any
			_ = json.Unmarshal(r, &d)
			d["created_at"] = "1999-01-01T00:00:00Z"
			out, _ := json.Marshal(d)
			return out
		}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st, _ := New(testKey())
			path := filepath.Join(t.TempDir(), "b.json")
			if err := st.Save(path, sampleBaseline(time.Now())); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutPath := filepath.Join(t.TempDir(), "b-mut.json")
			if err := os.WriteFile(mutPath, tt.mutate(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Load(mutPath); !errors.Is(err, ErrTampered) {
				t.Fatalf("expected ErrTampered, got %v", err)
			}
		})
	}
}

func TestWrongKeyRejected(t *testing.T) {
	t.Parallel()
	st1, _ := New([]byte("key-one"))
	st2, _ := New([]byte("key-two"))
	path := filepath.Join(t.TempDir(), "b.json")
	if err := st1.Save(path, sampleBaseline(time.Now())); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Load(path); !errors.Is(err, ErrTampered) {
		t.Fatalf("expected ErrTampered with wrong key, got %v", err)
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	t.Parallel()
	if _, err := New(nil); err == nil {
		t.Fatal("expected error for nil key")
	}
	if _, err := New([]byte{}); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestSaveAllowsEmpty(t *testing.T) {
	t.Parallel()
	st, _ := New(testKey())
	b := sampleBaseline(time.Now())
	b.Entries = nil
	// An empty baseline is valid (e.g. initializing an empty directory).
	if err := st.Save(filepath.Join(t.TempDir(), "b.json"), b); err != nil {
		t.Fatalf("saving empty baseline: %v", err)
	}
}

func TestGarbageInput(t *testing.T) {
	t.Parallel()
	st, _ := New(testKey())
	path := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(path, []byte("not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(path); err == nil {
		t.Fatal("expected parse error for garbage")
	}
	if _, err := st.Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestUnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	st, _ := New(testKey())
	path := filepath.Join(t.TempDir(), "b.json")
	if err := st.Save(path, sampleBaseline(time.Now())); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var d map[string]any
	_ = json.Unmarshal(raw, &d)
	d["sneaky"] = "field"
	out, _ := json.Marshal(d)
	mutPath := filepath.Join(t.TempDir(), "b2.json")
	_ = os.WriteFile(mutPath, out, 0o600)
	if _, err := st.Load(mutPath); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

// FuzzLoad verifies the parser never panics and never accepts a
// document whose HMAC does not verify, regardless of input bytes.
func FuzzLoad(f *testing.F) {
	st, _ := New(testKey())
	base, _ := json.Marshal(doc{signedDoc: signedDoc{
		Version: 1, Algorithm: "sha256", CreatedAt: "2026-01-01T00:00:00Z",
		Root: "/v", Entries: []model.Entry{{Path: "a", Hash: "h", Size: 1, Mode: 420,
			Mtime: time.Unix(0, 0), Algorithm: "sha256"}},
	}, HMAC: "deadbeef"})
	f.Add(base)
	f.Add([]byte(`{"hmac":"x"}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"version":1,"algorithm":"sha256","created_at":"nope","root":"","entries":[],"hmac":""}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		path := filepath.Join(t.TempDir(), "fuzz.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Skip()
		}
		b, err := st.Load(path)
		if err == nil {
			// Only a genuinely well-signed document may load.
			if b.Version != model.BaselineVersion {
				t.Fatalf("fuzz: loaded baseline with bad version %d", b.Version)
			}
			rePath := filepath.Join(t.TempDir(), "re.json")
			if err := st.Save(rePath, b); err != nil {
				t.Fatalf("fuzz: roundtrip save failed: %v", err)
			}
			if _, err := st.Load(rePath); err != nil {
				t.Fatalf("fuzz: roundtrip load failed: %v", err)
			}
		} else if !errors.Is(err, ErrTampered) &&
			!strings.Contains(err.Error(), "parse") &&
			!strings.Contains(err.Error(), "created_at") &&
			!strings.Contains(err.Error(), "version") &&
			!strings.Contains(err.Error(), "algorithm") {
			// Anything else would be an unclassified failure mode.
			t.Fatalf("fuzz: unexpected error class: %v", err)
		}
	})
}

// TestSaveCreatesMissingParentDir verifies Save creates the baseline's
// parent directory (0700) instead of failing when it does not exist.
func TestSaveCreatesMissingParentDir(t *testing.T) {
	t.Parallel()
	st, err := New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "nested", "baseline.json")
	if err := st.Save(path, sampleBaseline(time.Now().UTC())); err != nil {
		t.Fatalf("Save into missing dir: %v", err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("parent dir mode = %v (%v), want 0700", fi.Mode().Perm(), err)
	}
	if _, err := st.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
