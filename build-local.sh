#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build-local.sh — build petool against LOCAL Zydis / Intel XED sources
#                  (e.g. extracted from zydis.7z / xed.7z). No network needed.
#
# Usage:
#   ./build-local.sh --zydis /path/to/zydis \
#                    [--xed /path/to/xed --mbuild /path/to/mbuild]
#
# Notes:
#   * Zydis must include its Zycore submodule (extract the full clone).
#   * XED needs its sibling 'mbuild' checkout and Python 3 on PATH.
#   * The committed CMake still fetches from GitHub by default; these flags
#     only set CMake's FETCHCONTENT_SOURCE_DIR_* overrides for a local build.
# ---------------------------------------------------------------------------
set -euo pipefail

ZYDIS_DIR=""; XED_DIR=""; MBUILD_DIR=""; BUILD_DIR="build-local"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --zydis)  ZYDIS_DIR="$2"; shift 2;;
    --xed)    XED_DIR="$2";   shift 2;;
    --mbuild) MBUILD_DIR="$2"; shift 2;;
    --build-dir) BUILD_DIR="$2"; shift 2;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

FLAGS=()
[[ -n "$ZYDIS_DIR" ]] && FLAGS+=( -DWITH_ZYDIS=ON -DZYDIS_LOCAL_DIR="$(realpath "$ZYDIS_DIR")" )
[[ -n "$XED_DIR"   ]] && FLAGS+=( -DWITH_XED=ON   -DXED_LOCAL_DIR="$(realpath "$XED_DIR")" )
[[ -n "$MBUILD_DIR" ]] && FLAGS+=( -DMBUILD_LOCAL_DIR="$(realpath "$MBUILD_DIR")" )

if [[ ${#FLAGS[@]} -eq 0 ]]; then
  echo "Nothing to do: pass --zydis and/or --xed (see --help)." >&2; exit 2
fi

echo ">> cmake -S . -B $BUILD_DIR ${FLAGS[*]}"
cmake -S . -B "$BUILD_DIR" "${FLAGS[@]}" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --config Release --parallel
echo ">> Built: $BUILD_DIR/petool"
"$BUILD_DIR/petool" --help || true
