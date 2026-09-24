# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **High**
  - `update` now rejects a target outside the baseline root instead of
    writing `../` prefixed entries (H1).
  - One unreadable file no longer aborts a scan: readable siblings are
    still reported, the unreadable files are named, and the run exits 2
    (H2).
  - `update` of a deleted path prunes that entry from the baseline rather
    than failing on Lstat (H3).
  - Watch webhooks use a bounded queue, a posting timeout, and drain on
    shutdown instead of one goroutine per event (H4).
  - POSIX permission checks are skipped on platforms without meaningful
    perm bits so keyfiles are not spuriously refused on Windows (H6).
- **Medium**
  - Baselines carry a monotonic, HMAC-covered `sequence` number to detect
    replayed (rolled-back) baselines; the README documents the required
    external anchor (M1).
  - `watch` of a subdir of the baseline root now offsets keys so
    pre-existing files are not misreported as new (M2).
  - Checking a deleted root reports every entry MISSING (exit 1) instead
    of a raw stat error (M3).
  - `init` of a single FIFO/device refuses with exit 2 instead of writing
    an empty baseline (M4).
  - `update` and `verify-baseline` honor `--format json` (M5).
  - JSON output no longer HTML-escapes `->` in reasons (M6).
  - Orphaned `.baseline-*.tmp` files are swept on save and auto-excluded
    from scans (M8).
  - Setting both `IC_KEY` and `--keyfile` now warns that `IC_KEY` wins
    (M9).
  - `owner_unix.go` uses the `unix` build tag so it builds on plan9 (M10).
  - Unix-perm baseline tests are gated behind the `unix` tag (M11).
  - `verify-baseline` no longer prints the loose-perms warning twice
    (M12).
  - Nonexistent paths report an actionable `cannot scan <path>` error
    (M13).
  - fsnotify event overflow is logged at Error level with a count and a
    full-rescan hint (M14).
  - The test trap sink is mutex-guarded against data races (M15).
  - The in-tree baseline warning now fires for single-file baselines
    (M16).
  - `init`/`update`/`check` canonicalize roots and targets through
    symlinks, so a tree reached via two spellings of the same directory
    (e.g. macOS /var -> /private/var) no longer fails with a false
    "outside baseline root" and no longer leaks a copy of the baseline
    path (M17).
- **Low**
  - Wrong-key HMAC failures say so instead of only "tampered" (L3).
  - Watch debounce uses a one-shot timer instead of a perpetual ticker
    (L4).
  - The walk error path drains its collectors (L5).
  - `-q` is honored in JSON output (L7).
  - Color precedence fixed: `--color=false` forces off and `NO_COLOR`
    wins (L8).
  - JSON output carries a consistent envelope with summary counts (L9).
  - Baseline write errors name the temp file and hint at disk-full (L10).
  - Following a symlink whose target lies outside the root warns (L12).
  - The package-level `walk.Diff` was renamed `DiffEntries` (L14).
- **Quality**
  - Removed a redundant webhook flag re-read (Q1), consolidated color
    resolution into one helper (Q2), reused the shared single-file hash
    helper (Q3), removed dead test lines and weak assertions (Q4), and
    made `main` testable (Q5).
- **Docs**
  - Added this changelog (D1), corrected the README options table (D2),
    added baseline/key ignores (D3, D4), fixed the version ldflags
    comment (D5), added `shell: bash` to the gofmt CI step (D6), pinned
    golangci-lint (D7) and the release Go version (D8).
  - Pinned CI to golangci-lint-action v8 with golangci-lint v2.13.2 and
    added a `.gitattributes` enforcing LF line endings so gofmt stays
    clean on Windows checkouts (D9).

### Security

- Added a monotonic HMAC-covered sequence number to baselines (M1); full
  replay protection still requires storing the current sequence out of
  band (see README).

### Added

- Tests for every fixed issue, including FIFO (M4), symlink swap, and a
  large-file suite (final verification).
