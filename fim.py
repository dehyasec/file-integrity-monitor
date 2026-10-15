#!/usr/bin/env python3
"""File integrity monitor (v0.1): detect modified, new and deleted files via SHA-256.
For educational use only: monitor only systems you own or are authorized to manage."""
import argparse
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


def scan(root, exclude=()):
    """Return {relative_path: sha256} for every readable file under root."""
    hashes = {}
    for folder, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(folder, name)
            if os.path.abspath(full) in exclude or os.path.islink(full):
                continue
            rel = os.path.relpath(full, root)
            try:
                hashes[rel] = sha256(full)
            except OSError as e:
                print(f"skipped {rel}: {e}", file=sys.stderr)
    return hashes


def cmd_baseline(args):
    root = os.path.abspath(args.directory)
    hashes = scan(root, exclude={os.path.abspath(args.baseline)})
    data = {
        "root": root,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": hashes,
    }
    with open(args.baseline, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    print(f"Baseline saved: {len(hashes)} file(s) -> {args.baseline}")


def cmd_check(args):
    try:
        with open(args.baseline) as f:
            data = json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"No baseline at {args.baseline}. Run 'baseline' first.")
    old = data["files"]
    root = os.path.abspath(args.directory) if args.directory else data["root"]
    new = scan(root, exclude={os.path.abspath(args.baseline)})

    modified = sorted(p for p in old.keys() & new.keys() if old[p] != new[p])
    added = sorted(new.keys() - old.keys())
    deleted = sorted(old.keys() - new.keys())

    print(f"Checked {len(new)} file(s) against baseline from {data['created']}\n")
    for p in modified:
        print(f"MODIFIED  {p}")
    for p in added:
        print(f"NEW       {p}")
    for p in deleted:
        print(f"DELETED   {p}")
    if not (modified or added or deleted):
        print("OK: no changes detected.")
    sys.exit(1 if (modified or added or deleted) else 0)


def main():
    ap = argparse.ArgumentParser(description="Simple file integrity monitor")
    ap.add_argument("-b", "--baseline", default="baseline.json",
                    help="baseline file (default baseline.json)")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("baseline", help="record hashes of all files in a directory")
    p.add_argument("directory")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("check", help="compare a directory against the saved baseline")
    p.add_argument("directory", nargs="?", help="defaults to the baselined directory")
    p.set_defaults(func=cmd_check)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
