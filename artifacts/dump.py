#!/usr/bin/env python3
"""Export initial snapshots for a dataset program or a binary."""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "artifacts/build/dataset"
OUTPUT = ROOT / ".tmp"


def main():
    target, engine, image = sys.argv[1:]
    program = DATASET / target
    path = Path(target).expanduser()
    if program.is_dir() and program.parent == DATASET:
        binaries = sorted(program.glob("*.elf"))
    elif path.is_file():
        binaries = [path.resolve()]
    else:
        binaries = sorted(DATASET.glob(f"*/{target}")) if "/" not in target else []
        if len(binaries) > 1:
            sys.exit(f"Ambiguous binary name: {target}; pass its path")
    if not binaries:
        sys.exit(f"No binaries found for {target!r} in {DATASET}")

    for binary in binaries:
        destination = OUTPUT / binary.parent.name / binary.name
        if destination.exists():
            sys.exit(f"Output already exists: {destination}")
        state = Path(tempfile.mkdtemp(prefix="esperware-dump-"))
        try:
            print(f"Dumping {binary} -> {destination}", flush=True)
            subprocess.run([engine, "run", "--rm", "-v", f"{binary}:/input/binary:ro",
                            "-v", f"{state}:/data", image, "--work-dir", "/data/run",
                            "--binary", "/input/binary", "--no-cache", "--dump"], check=True)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(state / "run/code/v0"), str(destination))
        finally:
            subprocess.run(["/usr/bin/trash-put", "--", str(state)], check=True)


if __name__ == "__main__":
    main()
