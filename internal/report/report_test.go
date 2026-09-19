package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rishabh-yadav11/file-integrity-checker/internal/model"
)

func sampleResults() []model.Result {
	return []model.Result{
		{Path: "b.log", Kind: model.KindModified, Reasons: []string{"hash", "size"}},
		{Path: "a.log", Kind: model.KindUnmodified},
		{Path: "c.log", Kind: model.KindNew},
		{Path: "gone.log", Kind: model.KindMissing},
	}
}

// TestRenderDoesNotMutateInput verifies Render sorts a copy and leaves the
// caller's slice order untouched.
func TestRenderDoesNotMutateInput(t *testing.T) {
	t.Parallel()
	in := []model.Result{{Path: "z.log", Kind: model.KindUnmodified}, {Path: "a.log", Kind: model.KindUnmodified}, {Path: "m.log", Kind: model.KindUnmodified}}
	before := append([]model.Result{}, in...)
	if err := Render(discardWriter{}, in, Options{}); err != nil {
		t.Fatal(err)
	}
	for i := range in {
		if in[i].Path != before[i].Path {
			t.Fatalf("Render mutated the caller slice: got %q at %d, want %q", in[i].Path, i, before[i].Path)
		}
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestCount(t *testing.T) {
	t.Parallel()
	s := Count(sampleResults())
	if s.Unmodified != 1 || s.Modified != 1 || s.New != 1 || s.Missing != 1 {
		t.Fatalf("summary = %+v", s)
	}
	if !s.Changed() {
		t.Error("Changed() = false, want true")
	}
	if s.Total() != 4 {
		t.Fatalf("Total = %d, want 4", s.Total())
	}
	clean := Count([]model.Result{{Path: "x", Kind: model.KindUnmodified}})
	if clean.Changed() {
		t.Error("clean Changed() = true, want false")
	}
}

func TestRenderTextSorted(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	if err := Render(&sb, sampleResults(), Options{}); err != nil {
		t.Fatal(err)
	}
	got := sb.String()
	want := "UNMODIFIED a.log\nMODIFIED b.log (hash, size)\nNEW c.log\nMISSING gone.log\n"
	if got != want {
		t.Fatalf("text output =\n%q\nwant\n%q", got, want)
	}
}

func TestRenderTextQuiet(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	if err := Render(&sb, sampleResults(), Options{Quiet: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sb.String(), "UNMODIFIED") {
		t.Fatalf("quiet mode still shows unmodified:\n%s", sb.String())
	}
}

func TestRenderTextColor(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	if err := Render(&sb, sampleResults(), Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	got := sb.String()
	for _, want := range []string{"\033[32mUNMODIFIED\033[0m", "\033[31mMODIFIED\033[0m", "\033[33mNEW\033[0m", "\033[31mMISSING\033[0m"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing colored %q in output:\n%q", want, got)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	if err := Render(&sb, sampleResults(), Options{Format: "json"}); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Results []model.Result `json:"results"`
	}
	if err := json.Unmarshal([]byte(sb.String()), &parsed); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, sb.String())
	}
	if len(parsed.Results) != 4 {
		t.Fatalf("json results = %d, want 4", len(parsed.Results))
	}
	// Sorted by path.
	if parsed.Results[0].Path != "a.log" || parsed.Results[3].Path != "gone.log" {
		t.Fatalf("json not sorted: %+v", parsed.Results)
	}
	if parsed.Results[1].Kind != model.KindModified || len(parsed.Results[1].Reasons) != 2 {
		t.Fatalf("modified entry wrong: %+v", parsed.Results[1])
	}
}

func TestRenderUnknownKind(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	err := Render(&sb, []model.Result{{Path: "x", Kind: "weird"}}, Options{})
	if err == nil || !strings.Contains(err.Error(), "unknown change kind") {
		t.Fatalf("expected unknown-kind error, got %v", err)
	}
}

func TestSummaryText(t *testing.T) {
	t.Parallel()
	s := Count(sampleResults())
	want := "summary: 1 unmodified, 1 modified, 1 new, 1 missing (4 files)"
	if s.Text() != want {
		t.Fatalf("Text() = %q, want %q", s.Text(), want)
	}
}
