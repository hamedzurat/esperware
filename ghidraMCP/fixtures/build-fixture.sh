#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
output_dir="$repo_dir/build/fixtures"
mkdir -p "$output_dir"
gcc -O0 -fno-inline -fno-stack-protector -no-pie -g0 \
  "$repo_dir/fixtures/readability-fixture.c" -o "$output_dir/readability-fixture.elf"
strip --strip-all "$output_dir/readability-fixture.elf"
file "$output_dir/readability-fixture.elf"
