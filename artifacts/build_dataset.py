#!/usr/bin/env python3
"""Build dataset binaries from codes/<name>/ with the profiles in profiles.toml.

Which profiles each program gets is set in dataset.toml (first matching rule wins).

Each codes/<name>/ directory is one program: all its .c/.cpp files are compiled
and linked into one binary per profile.

Output: build/dataset/<name>/<profile>.{unstripped,stripped}.elf + manifest.jsonl.
A build whose stripped bytes match another profile of the same program is dropped.
"""

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODES = HERE / "codes"
CPP_EXT = {".cpp", ".cc", ".cxx"}
PROFILES = tomllib.loads((HERE / "profiles.toml").read_text())
COMMON = PROFILES.get("common", [])  # flags before every profile's own; the profile's win


def build(program, profile, out):
    sources = sorted(p for p in program.iterdir() if p.suffix in {".c"} | CPP_EXT)
    out_dir = out / program.name
    out_dir.mkdir(parents=True, exist_ok=True)
    unstripped = out_dir / f"{profile['name']}.unstripped.elf"
    stripped = out_dir / f"{profile['name']}.stripped.elf"
    libs = ["-lm"]
    if any(s.suffix in CPP_EXT for s in sources):
        # gcc/clang pick the language per file, but not the C++ runtime
        libs.insert(0, "-lc++" if "-stdlib=libc++" in profile["flags"] else "-lstdc++")
    # Same output on any machine with the same toolchain: no checkout path, clock or random names.
    repro = [f"-ffile-prefix-map={program}=/src/{program.name}", f"-frandom-seed={program.name}"]
    cmd = [profile["cc"], *COMMON, *profile["flags"], *repro, "-g",
           *map(str, sources), "-o", str(unstripped), *libs]
    env = {**os.environ, "SOURCE_DATE_EPOCH": "0", "LC_ALL": "C"}
    # cwd is recorded in the debug info, so it must be the directory the prefix map covers.
    t0 = time.monotonic()
    res = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=program)
    seconds = time.monotonic() - t0
    if res.returncode != 0:
        return {"program": program.name, "profile": profile["name"], "seconds": seconds,
                "error": res.stderr.strip()}
    subprocess.run(["strip", "--strip-all", "-o", str(stripped), str(unstripped)], check=True)
    return {
        "program": program.name,
        "profile": profile["name"],
        "sources": [s.name for s in sources],
        "cc": profile["cc"],
        "flags": [*COMMON, *profile["flags"]],
        "unstripped": str(unstripped.relative_to(HERE)),
        "stripped": str(stripped.relative_to(HERE)),
        "sha256": hashlib.sha256(stripped.read_bytes()).hexdigest(),
        "size": stripped.stat().st_size,
        "seconds": seconds,
    }


def is_cpp(program):
    return any(f.suffix in CPP_EXT for f in program.iterdir())


def planned(program, rules, profiles):
    """Profiles dataset.toml assigns to a program; all of them if no rule matches."""
    for rule in rules:
        if not fnmatch.fnmatch(program.name, rule["match"]):
            continue
        names = rule["profiles"]
        if unknown := [n for n in names if n not in profiles]:
            sys.exit(f"dataset.toml rule {rule['match']!r}: unknown profile {unknown}")
        n = rule.get("per_program", len(names))
        # Fixed slice of the list, chosen by program name: same result every run,
        # and adding programs does not change what earlier ones got.
        start = int(hashlib.sha256(program.name.encode()).hexdigest(), 16) % len(names)
        return [profiles[names[(start + i) % len(names)]] for i in range(min(n, len(names)))]
    return list(profiles.values())


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("profiles", nargs="*", help="build these profiles instead of the dataset.toml plan")
    ap.add_argument("--all", action="store_true", help="build every profile instead of the dataset.toml plan")
    ap.add_argument("--out", type=Path, default=Path("build/dataset"), help="output directory")
    ap.add_argument("-p", "--program", default="*", help="only programs whose name matches this glob")
    args = ap.parse_args()
    OUT = (HERE / args.out).resolve()
    MANIFEST = OUT / "manifest.jsonl"

    profiles = {p["name"]: p for p in PROFILES["profile"]}
    if args.all and args.profiles:
        ap.error("give --all or profile names, not both")
    if unknown := [n for n in args.profiles if n not in profiles]:
        ap.error(f"unknown profile {unknown}; known: " + ", ".join(profiles))
    programs = sorted(
        d for d in CODES.iterdir()
        if d.is_dir() and fnmatch.fnmatch(d.name, args.program)
        and any(f.suffix in {".c"} | CPP_EXT for f in d.iterdir())
    ) if CODES.is_dir() else []
    if not programs:
        sys.exit(f"no programs match {args.program!r}: put .c/.cpp files in {CODES}/<name>/")

    cfg = HERE / "dataset.toml"
    rules = tomllib.loads(cfg.read_text()).get("rule", []) if cfg.exists() else []
    if args.all:
        jobs = [(prog, p) for prog in programs for p in profiles.values()]
    elif args.profiles:
        jobs = [(prog, profiles[n]) for prog in programs for n in args.profiles]
    else:
        jobs = [(prog, p) for prog in programs for p in planned(prog, rules, profiles)]

    # A profile with only = "c" / "cpp" is skipped for programs of the other language.
    jobs = [(prog, p) for prog, p in jobs if p.get("only") in (None, "cpp" if is_cpp(prog) else "c")]

    versions = {}
    for cc in sorted({p["cc"] for _, p in jobs}):
        if not shutil.which(cc):
            sys.exit(f"{cc} not found")
        versions[cc] = subprocess.run([cc, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    print(f"{len(programs)} programs, {len(jobs)} builds, compilers:")
    for cc, version in versions.items():
        print(f"  {cc}: {version}")
    started = time.monotonic()
    with ThreadPoolExecutor() as pool:
        futures = [pool.submit(build, prog, p, OUT) for prog, p in jobs]
        width = len(str(len(jobs)))
        for done, f in enumerate(as_completed(futures), 1):
            r = f.result()
            status = "FAILED" if "error" in r else f"{r['size'] / 1024:7.0f} KB"
            print(f"[{done:{width}}/{len(jobs)}] {r['program']:<24} {r['profile']:<24} "
                  f"{status}  {r['seconds']:5.1f}s", flush=True)
    results = [f.result() for f in futures]  # job order, so the duplicate choice is stable
    print(f"finished in {time.monotonic() - started:.1f}s")

    # Merge with earlier runs so building one profile keeps the others in the manifest.
    rebuilt = {(r["program"], r["profile"]) for r in results}
    kept = []
    if MANIFEST.exists():
        for line in MANIFEST.read_text().splitlines():
            r = json.loads(line)
            if (r["program"], r["profile"]) not in rebuilt and (HERE / r["stripped"]).exists():
                kept.append(r)
    seen = {(r["program"], r["sha256"]): r["profile"] for r in kept}

    new = failed = dupes = 0
    for r in results:
        if "error" in r:
            failed += 1
            print(f"FAILED {r['program']} [{r['profile']}]\n{r['error']}", file=sys.stderr)
            continue
        key = (r["program"], r["sha256"])
        if key in seen:
            dupes += 1
            print(f"duplicate {r['program']}: {r['profile']} == {seen[key]}, dropped")
            (HERE / r["unstripped"]).unlink()
            (HERE / r["stripped"]).unlink()
            continue
        seen[key] = r["profile"]
        r["cc_version"] = versions[r["cc"]]
        del r["seconds"]  # timing is for the log only; the manifest stays the same across runs
        kept.append(r)
        new += 1

    kept.sort(key=lambda r: (r["program"], r["profile"]))
    MANIFEST.write_text("".join(json.dumps(r) + "\n" for r in kept))
    print(f"{new} built, {dupes} duplicates dropped, {failed} failed; manifest has {len(kept)} -> {OUT}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
