# file-integrity-monitor

A Python tool that detects modified, new and deleted files by comparing SHA-256 hashes against a saved baseline. Built as a defensive-security learning project.

> **Ethical use only.** Monitor only systems you own or are authorized to manage.

## Features
- SHA-256 baseline of every file in a directory
- Reports **MODIFIED**, **NEW** and **DELETED** files
- Glob ignore patterns (`-i "*.log"`), including whole folders
- `--update` to accept expected changes as the new baseline
- Exit code `0` = clean, `1` = changes found, so it works in scripts and cron jobs
- Reads files in 1 MB chunks, so large files are fine
- Standard library only, no installs

## Usage
```bash
python3 fim.py [-b BASELINE] baseline <directory> [-i PATTERN ...]
python3 fim.py [-b BASELINE] check [directory] [-i PATTERN ...] [--update]
```

| Command / option | Description |
|---|---|
| `baseline <dir>` | Hash every file in `<dir>` and save the baseline |
| `check [dir]` | Compare the current state with the baseline |
| `-b`, `--baseline` | Baseline file (default `baseline.json`) |
| `-i`, `--ignore` | Glob pattern to skip, repeatable |
| `-u`, `--update` | Accept the current state as the new baseline |

### Example
```bash
python3 fim.py baseline /etc/ssh -i "*.bak"
python3 fim.py check
```

### Example output
```
Checked 3 file(s) against baseline from 2026-10-17T00:53:21+00:00

MODIFIED  a.txt
MODIFIED  sub/d.txt
NEW       c.txt
DELETED   b.txt
```

## How it works
A SHA-256 hash is a fingerprint of a file's contents; changing one character produces a completely different hash. `baseline` stores each file's hash in a JSON file. `check` re-hashes the directory and compares: same name with a different hash is *modified*, a name only in the new scan is *new*, and a name only in the baseline is *deleted*.

## Limitations
- Detects content changes only, not permission or ownership changes
- A baseline file is not itself protected: store it somewhere an attacker cannot edit
- Symbolic links are skipped

## Roadmap
- [ ] Track file permissions and ownership
- [ ] Hash-algorithm option (SHA-512, BLAKE2)
- [ ] JSON report output
- [ ] Scheduled checks with email or webhook alerts

## License
MIT. See [LICENSE](LICENSE).
