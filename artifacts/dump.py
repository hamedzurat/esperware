#!/usr/bin/env python3
"""Export initial snapshots for a dataset program or a binary."""

import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "artifacts/build/dataset"
OUTPUT = ROOT / ".tmp"
WORKERS = 16


def identify(binary):
    name = binary.name
    for suffix in (".unstripped.elf", ".stripped.elf"):
        if name.endswith(suffix):
            return name[:-len(suffix)], suffix.removeprefix(".").removesuffix(".elf")
    return binary.stem, "unstripped"


def dump(binary, engine, image, destination):
    log = destination.with_suffix(".txt")
    destination.parent.mkdir(parents=True, exist_ok=True)
    state = Path(tempfile.mkdtemp(prefix="esperware-dump-"))
    try:
        command = [
            engine, "run", "--rm", "-v", f"{binary}:/input/binary:ro",
            "-v", f"{state}:/data", image, "--work-dir", "/data/run",
            "--binary", "/input/binary", "--no-cache", "--dump",
        ]
        with log.open("w") as output:
            output.write(f"$ {' '.join(command)}\n\n")
            output.flush()
            subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=True)
        shutil.move(str(state / "run/code/v0"), str(destination))
        return log
    finally:
        subprocess.run(["/usr/bin/trash-put", "--", str(state)], check=True)


def main():
    if len(sys.argv) != 4:
        sys.exit(f"Usage: {Path(sys.argv[0]).name} <program|binary> <engine> <image>")
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

    jobs = []
    for binary in binaries:
        profile, variant = identify(binary)
        destination = OUTPUT / binary.parent.name / profile / variant
        log = destination.with_suffix(".txt")
        if destination.exists():
            sys.exit(f"Output already exists: {destination}")
        if log.exists():
            sys.exit(f"Log already exists: {log}")
        jobs.append((binary, destination))

    failures = []
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(jobs))) as pool:
        futures = {pool.submit(dump, binary, engine, image, destination): (binary, destination)
                   for binary, destination in jobs}
        total = len(futures)
        for done, future in enumerate(as_completed(futures), 1):
            binary, destination = futures[future]
            try:
                log = future.result()
                print(f"[{done}/{total}] done     {binary.name} ({log})", flush=True)
            except Exception as error:
                failures.append((binary, error))
                print(f"[{done}/{total}] FAILED   {binary.name}: {error}", file=sys.stderr, flush=True)
    if failures:
        sys.exit(f"{len(failures)} of {len(jobs)} dump(s) failed")


if __name__ == "__main__":
    main()
