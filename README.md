# integrity-check

A production-grade CLI that detects tampering in log files and other
sensitive files. Think of it as a small AIDE/Tripwire: it records an
HMAC-signed baseline of your files (content hash plus size, mode, and
mtime), then detects any drift from that baseline.

## Features

- **Commands**: `init`, `check`, `update`, `watch`, `verify-baseline`
- **Algorithms**: SHA-256 (default), SHA-512, BLAKE2b via `--algo`
- **Metadata tracking**: size, mode, owner (uid/gid on Unix), mtime compared alongside the digest
- **Recursive scan** with `--include` / `--exclude` globs; symlinks are recorded as entries with their target string but never followed/hashed by default (`--follow-symlinks` opts in), so link swaps and retargets are detected; FIFOs, sockets and devices are skipped with a warning and never opened
- **File or directory paths**: `init`, `check`, and `update` all accept a single file as well as a directory
- **Bounded worker pool** and chunked reads: large files hash in constant memory
- **Signed baseline**: JSON, written atomically (temp file + rename), perms 0600, HMAC-SHA256 signed; one algorithm per baseline (update refuses to mix)
- **`verify-baseline`** confirms the baseline file itself was not tampered with
- **Real-time watch mode** (fsnotify) with debouncing and optional webhook alerts
- **Output**: colored text or `--format json`; exit code 0 clean, 1 changes, 2 error
- **YAML config file** with per-flag overrides
- **Structured logging** (`slog`), configurable worker pool, chunked 1 MiB reads

## Install

From source (Go 1.27+):

```sh
make build            # produces bin/integrity-check
```

Or with Docker (mount the directory and pass the subcommand; the
baseline must be reachable inside the container, e.g. another mount or
a config file):

```sh
docker build -t integrity-check .
docker run --rm --user "$(id -u):$(id -g)" -e IC_KEY=secret \
  -v "$PWD/logs:/data" -v "$PWD/b.json:/b.json:ro" \
  integrity-check check /data --baseline /b.json -q
```

Releases for Linux/macOS/Windows (amd64/arm64) are built by GoReleaser on
`v*` tags; see the [release workflow](.github/workflows/release.yml).

## Quick start

```sh
export IC_KEY='a-long-random-secret'      # HMAC key (or use --keyfile)
BL=/var/lib/integrity-check/baseline.json

integrity-check init /var/log/myapp --baseline "$BL"
integrity-check check /var/log/myapp --baseline "$BL" -q
# tamper a file, then:
integrity-check check /var/log/myapp --baseline "$BL"    # exit 1
integrity-check verify-baseline --baseline "$BL"
integrity-check update /var/log/myapp --baseline "$BL"   # accept changes
integrity-check watch /var/log/myapp --baseline "$BL" --webhook https://hooks.example/x
```

One baseline path (`$BL`) is used by every command. Keep the baseline (and
the HMAC key) on a different host or offline media from the files it
describes, and never store it inside the tree it monitors — `init` warns
if you do and auto-excludes the in-tree baseline from its own scans.

### Example session

Output is from a real run against `logs/` containing `app.log` and
`other.log`, with the baseline stored as `baseline.json`:

```console
$ integrity-check init logs/ --baseline baseline.json
baseline written: baseline.json (2 files, sha256)

$ integrity-check check logs/ --baseline baseline.json
UNMODIFIED app.log
UNMODIFIED other.log
summary: 2 unmodified, 0 modified, 0 new, 0 missing (2 files)

$ echo hacked >> logs/app.log
$ integrity-check check logs/ --baseline baseline.json
MODIFIED app.log (hash, size 3 -> 9, mtime)
UNMODIFIED other.log
summary: 1 unmodified, 1 modified, 0 new, 0 missing (2 files)
# exit code 1

$ integrity-check check logs/ --baseline baseline.json --format json
{
  "results": [
    {
      "path": "app.log",
      "kind": "modified",
      "reasons": ["hash", "size 3 -> 9", "mtime"]
    },
    {
      "path": "other.log",
      "kind": "unmodified"
    }
  ]
}
```

Baseline fields: `version`, `algorithm`, `created_at`, `sequence`
(monotonic, HMAC-covered), `root` (absolute scan root), `entries[]` (each
with `path`, `hash`, `size`, `mode`, `uid`, `gid`, `mtime`, optional
`algorithm`, and `link_target` for symlinks), and an `hmac` covering the
whole document.

### Options

| Flag | Meaning |
| --- | --- |
| `--baseline <path>` | baseline file (required unless set in config) |
| `--algo <name>` | `sha256` (default), `sha512`, `blake2b`; `check` defaults to the baseline's stored algorithm when omitted, an explicit different value fails the run |
| `--format text|json` | output format |
| `-q` / `--quiet` | hide unmodified lines; on a clean tree print nothing at all (CI/cron friendly, exit code still 0/1/2) |
| `--include` / `--exclude` | glob filters, repeatable (validated at load) |
| `--workers N` | hashing workers (0 = NumCPU) |
| `--keyfile <path>` | HMAC key file (else `IC_KEY` env) |
| `--allow-loose-keyfile` | permit a group/world-readable keyfile (default: refuse) |
| `--webhook <url>` | POST tamper alerts as JSON (watch) |
| `--debounce 500ms` | watch-mode event coalescing window |
| `--follow-symlinks` | follow symlinks and hash their targets (default: record the link target, never follow) |
| `--ignore-mtime` | compare content (hash) only, ignoring size/mode/owner/mtime |

Exit codes: `0` = clean, `1` = changes found, `2` = error.

### Configuration file

`~/.config/integrity-check/config.yaml` (override with `--config`):

```yaml
baseline: /var/lib/integrity-check/baseline.json
algorithm: sha256
workers: 8
format: text
exclude: ["*.tmp", "cache/"]
webhook_url: https://alerts.example.internal/hook
key_file: /etc/integrity-check/hmac.key
```

Command-line flags override the config file; the HMAC key comes from
`IC_KEY` or `--keyfile` (config `key_file:` works too) and is never
stored in the baseline.

## Threat model

`integrity-check` defends against **offline tampering of log files**: an
attacker (or insider) who edits, truncates, replaces, or deletes log
files after the fact and hopes nobody notices. It provides strong
evidence of modification, provided the baseline and key were created
before the attacker had access.

### What it detects

- Modified file contents (SHA-256/512/BLAKE2b digest mismatch)
- Size, permission, or mtime changes, even if content matches a stale hash
- New files appearing inside watched trees, and baseline files that vanish

### What it does NOT defend against

- **Key or baseline compromise.** The HMAC key and the baseline file must
  be stored out of band (different host, offline media). An attacker who
  can rewrite the baseline *and* holds the key can re-sign their edits.
  `verify-baseline` only proves the file matches its own HMAC.
- **Replay of an old signed baseline.** Each baseline carries a monotonic
  `sequence` number covered by the HMAC. Because the tool is stateless,
  the HMAC check alone cannot detect that a *whole older* baseline has
  been restored. To close this, store the current sequence number out of
  band (e.g. append it to your cron/audit log) and alert when a loaded
  baseline's sequence is not greater than the last one you saw.
- **Live attackers racing the watcher.** Watch mode is best-effort;
  `fsnotify` events are debounced, not a security boundary. Always run
  `check` from a trusted context for audit conclusions. Watch compares
  against the baseline snapshot loaded at startup: run `update` before
  starting `watch`, or restart `watch` after updating the baseline.
- **Attacker with root on the scanning host.** A root attacker can
  subvert the binary, its config, or the kernel. Run integrity-check
  from read-only media against a read-only mount for high-assurance use.
- **Symlink games.** Symlinks are never followed or hashed: the scanner
  records the link (its target string) and never descends a directory
  symlink (`WalkDir` does not follow them), and a symlink where a regular
  file was recorded shows as `modified`. The final component of a hashed
  path is opened with `O_NOFOLLOW`, which closes the stat-then-open race
  on that component. A symlink raced into an *intermediate* path
  component mid-hash is not separately guarded (guarding every component
  would require `openat`-style per-component walks), so treat the scanner
  as a strong defense against link swaps, not as a mount-point boundary.

### Operational guidance

1. Generate the key once (`IC_KEY` env or `--keyfile`, file perms 0600).
2. `init` the baseline immediately after a known-good state, then move
   the baseline file (and key) somewhere the monitored host cannot write.
   Do not store the baseline inside the tree it describes; init warns if
   you do (every save changes the baseline, so every check would flag it).
3. Schedule `check` (cron/systemd timer) and alert on exit code 1 or 2.
4. Treat `verify-baseline` failures as incidents: the baseline was
   altered or you are using the wrong key.
5. Rotate baselines deliberately with `update` after *reviewed* log
   rotation, not automatically.

## Development

```sh
make test     # go test ./...
make race     # race detector
make cover    # coverage gate (85%+ enforced in CI)
make fuzz     # fuzz the baseline parser (60s)
make docker   # container image
```

## License

MIT. See [LICENSE](LICENSE).
