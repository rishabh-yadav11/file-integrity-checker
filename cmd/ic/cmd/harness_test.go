package cmd

import (
	"os"
	"strings"
	"testing"
)

// runCLIIn executes the CLI with cwd set and returns exit code + output.
func runCLIIn(t *testing.T, cwd, dir string, env map[string]string, args ...string) (int, string) {
	t.Helper()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}

	oldStdout, oldStderr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	os.Stderr = w
	for k, v := range env {
		t.Setenv(k, v)
	}
	code := ExecuteMain(args)
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	w.Close()
	buf := make([]byte, 1<<16)
	var out strings.Builder
	for {
		n, err := r.Read(buf)
		out.Write(buf[:n])
		if err != nil || n == 0 {
			break
		}
	}
	return code, out.String()
}
