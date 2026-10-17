#!/usr/bin/env python3
"""File integrity monitor (v0.2): detect modified, new and deleted files via SHA-256.
For educational use only: monitor only systems you own or are authorized to manage."""
import argparse
import fnmatch
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

CHUNK = 1024 * 1024  # read files 1 MB at a time so big files don't fill memory


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def is_ignored(rel, patterns):
    """True if a relative path (or just its name) matches any ignore pattern."""
    name = os.path.basename(rel)
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in patterns)


def scan(root, skip, ignore):
    """Return {relative_path: sha256} for every readable file under root."""
    hashes = {}
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs
                   if not is_ignored(os.path.relpath(os.path.join(folder, d), root), ignore)]
        for name in files:
            full = os.path.join(folder, name)
            rel = os.path.relpath(full, root)
            if os.path.abspath(full) == skip or os.path.islink(full) or is_ignored(rel, ignore):
                continue
            try:
                hashes[rel] = sha256(full)
            except OSError as e:
                print(f"skipped {rel}: {e}", file=sys.stderr)
    return hashes


def save_baseline(path, root, hashes, ignore):
    data = {
        "root": root,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ignore": sorted(ignore),
        "files": hashes,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def cmd_baseline(args):
    root = os.path.abspath(args.directory)
    if not os.path.isdir(root):
        raise SystemExit(f"Not a directory: {args.directory}")
    ignore = sorted(set(args.ignore or []))
    hashes = scan(root, os.path.abspath(args.baseline), ignore)
    save_baseline(args.baseline, root, hashes, ignore)
    print(f"Baseline saved: {len(hashes)} file(s) -> {args.baseline}")


def cmd_check(args):
    try:
        with open(args.baseline) as f:
            data = json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"No baseline at {args.baseline}. Run 'baseline' first.")
    old = data["files"]
    root = os.path.abspath(args.directory) if args.directory else data["root"]
    ignore = sorted(set(data.get("ignore", [])) | set(args.ignore or []))
    new = scan(root, os.path.abspath(args.baseline), ignore)

    modified = sorted(p for p in old.keys() & new.keys() if old[p] != new[p])
    added = sorted(new.keys() - old.keys())
    deleted = sorted(old.keys() - new.keys())
    changed = bool(modified or added or deleted)

    print(f"Checked {len(new)} file(s) against baseline from {data['created']}\n")
    for p in modified:
        print(f"MODIFIED  {p}")
    for p in added:
        print(f"NEW       {p}")
    for p in deleted:
        print(f"DELETED   {p}")
    if not changed:
        print("OK: no changes detected.")

    if args.update:
        save_baseline(args.baseline, root, new, ignore)
        print("\nBaseline updated: current state accepted.")
    sys.exit(1 if changed and not args.update else 0)


def main():
    ap = argparse.ArgumentParser(description="Simple file integrity monitor")
    ap.add_argument("-b", "--baseline", default="baseline.json",
                    help="baseline file (default baseline.json)")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("baseline", help="record hashes of all files in a directory")
    p.add_argument("directory")
    p.add_argument("-i", "--ignore", action="append", metavar="PATTERN",
                   help="glob pattern to skip, e.g. '*.log' (repeatable)")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("check", help="compare a directory against the saved baseline")
    p.add_argument("directory", nargs="?", help="defaults to the baselined directory")
    p.add_argument("-i", "--ignore", action="append", metavar="PATTERN",
                   help="extra glob pattern to skip (repeatable)")
    p.add_argument("-u", "--update", action="store_true",
                   help="accept the current state as the new baseline")
    p.set_defaults(func=cmd_check)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
