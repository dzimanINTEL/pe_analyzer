#!/usr/bin/env python3
# ============================================================================
#  verify.py — cross-check the Zydis and XED decoder backends of `petool`.
#
#  Runs the analyzer on one or more PE files with BOTH exact decoders
#  (--decoder=zydis and --decoder=xed), compares their APX / AVX10.2 verdicts,
#  and reports any disagreements. Optionally also runs the heuristic for context.
#
#  This is meant to be run on a machine where `petool` was built with BOTH
#  backends enabled (CMake -DWITH_ZYDIS=ON -DWITH_XED=ON). It requires only the
#  Python 3 standard library.
#
#  Usage
#  -----
#    python verify.py --bin ./build/petool PATH [PATH ...]
#    python verify.py --bin ./build/petool ./dlls --recursive
#    python verify.py --bin ./build/petool ./dlls --json report.json
#    python verify.py --bin ./build/petool a.dll --include-heuristic
#
#  Exit codes
#  ----------
#    0  all comparable files agree (and no execution errors)
#    1  at least one MISMATCH between Zydis and XED
#    2  usage error / no PE files found
#    3  a backend was unavailable or petool failed on a file
# ============================================================================

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

# ISA fields we compare across decoders.
COMPARE_KEYS = ("apx", "avx10_2")
PE_EXTS = (".exe", ".dll", ".sys", ".ocx", ".efi", ".mui", ".cpl", ".scr")


@dataclass
class DecoderRun:
    decoder: str                 # requested decoder name
    ok: bool = False             # petool exited 0 and JSON parsed
    used_decoder: Optional[str] = None   # decoder petool actually used
    definitive: Optional[bool] = None
    applicable: Optional[bool] = None
    apx: Optional[bool] = None
    avx10_2: Optional[bool] = None
    rex2: Optional[int] = None
    evex: Optional[int] = None
    sections: Optional[int] = None
    returncode: Optional[int] = None
    parse_failed: bool = False   # petool couldn't parse the file as a PE
    error: Optional[str] = None


@dataclass
class FileResult:
    path: str
    runs: dict = field(default_factory=dict)   # decoder -> DecoderRun
    status: str = "unknown"     # agree | mismatch | skipped | error
    detail: str = ""


def run_petool(binary: str, path: str, decoder: str) -> DecoderRun:
    """Invoke petool on one file with a given decoder; parse the JSON output."""
    r = DecoderRun(decoder=decoder)
    cmd = [binary, path, "--json", "--scan-all-sections", f"--decoder={decoder}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        r.error = f"petool binary not found: {binary}"
        return r
    except subprocess.TimeoutExpired:
        r.error = "petool timed out"
        return r

    # petool returns 1 for non-PE inputs but still emits valid JSON; try to parse
    # regardless, and only treat a parse failure as an error.
    try:
        j = json.loads(proc.stdout)
    except json.JSONDecodeError:
        r.error = (proc.stderr.strip() or proc.stdout.strip()
                   or f"exit {proc.returncode}, no JSON")[:300]
        return r

    isa = j.get("isa", {}) or {}
    notes = j.get("notes", []) or []
    r.ok = True
    r.returncode = proc.returncode
    r.used_decoder = isa.get("decoder")
    r.definitive = isa.get("definitive")
    r.applicable = isa.get("applicable")
    r.apx = isa.get("apx")
    r.avx10_2 = isa.get("avx10_2")
    r.rex2 = isa.get("rex2Candidates")
    r.evex = isa.get("evexCount")
    r.sections = isa.get("sectionsScanned")

    # Did petool fail to parse the input as a PE at all?
    fail_markers = ("Not an MZ/PE", "Missing PE signature", "Cannot read file")
    if proc.returncode != 0 and any(
            any(m in n for m in fail_markers) for n in notes):
        r.parse_failed = True
        return r

    # Genuine backend-missing fallback: we asked for zydis/xed, there WAS code
    # to scan (sectionsScanned > 0), yet petool used the heuristic. A file with
    # no code section (sections == 0) is not a backend problem — it is skipped.
    if (decoder in ("zydis", "xed")
            and r.used_decoder != decoder
            and (r.sections or 0) > 0):
        r.error = (f"requested '{decoder}' but petool used "
                   f"'{r.used_decoder}' (backend not compiled in?)")
    return r


def compare(path: str, binary: str, include_heuristic: bool) -> FileResult:
    fr = FileResult(path=path)
    decoders = ["zydis", "xed"] + (["heuristic"] if include_heuristic else [])
    for d in decoders:
        fr.runs[d] = run_petool(binary, path, d)

    z, x = fr.runs["zydis"], fr.runs["xed"]

    # File wasn't a valid PE at all → skip (not a decoder problem).
    if z.parse_failed or x.parse_failed:
        fr.status = "skipped"
        fr.detail = "not a valid PE file"
        return fr

    # Backend availability / execution problems take precedence.
    if z.error or x.error:
        fr.status = "error"
        fr.detail = "; ".join(e for e in (z.error, x.error) if e)
        return fr

    # Non-x86 target, or no executable code to scan → nothing to compare.
    if not z.applicable or not x.applicable:
        fr.status = "skipped"
        fr.detail = "ISA not applicable (non-x86 target)"
        return fr
    if (z.sections or 0) == 0 and (x.sections or 0) == 0:
        fr.status = "skipped"
        fr.detail = "no executable code section scanned"
        return fr

    diffs = []
    for k in COMPARE_KEYS:
        zv, xv = getattr(z, k), getattr(x, k)
        if zv != xv:
            diffs.append(f"{k}: zydis={zv} xed={xv}")
    if diffs:
        fr.status = "mismatch"
        fr.detail = "; ".join(diffs)
    else:
        fr.status = "agree"
        fr.detail = f"apx={z.apx} avx10_2={z.avx10_2}"
    return fr


def gather_pe_files(paths, recursive: bool):
    out = []
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, _dirs, files in os.walk(p):
                    for f in files:
                        if f.lower().endswith(PE_EXTS):
                            out.append(os.path.join(root, f))
            else:
                for f in sorted(os.listdir(p)):
                    fp = os.path.join(p, f)
                    if os.path.isfile(fp) and f.lower().endswith(PE_EXTS):
                        out.append(fp)
        elif os.path.isfile(p):
            out.append(p)          # explicit file: analyze regardless of ext
        else:
            print(f"warning: path not found: {p}", file=sys.stderr)
    # De-dup while preserving order.
    seen, uniq = set(), []
    for f in out:
        if f not in seen:
            seen.add(f); uniq.append(f)
    return uniq


# --- pretty console output --------------------------------------------------
class C:
    G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; DIM = "\033[2m"; X = "\033[0m"


def _b(v):
    return {True: "Yes", False: "No", None: "n/a"}.get(v, str(v))


def print_report(results, use_color: bool):
    def col(s, c): return f"{c}{s}{C.X}" if use_color else s
    badge = {
        "agree":    col("AGREE   ", C.G),
        "mismatch": col("MISMATCH", C.R),
        "skipped":  col("SKIPPED ", C.Y),
        "error":    col("ERROR   ", C.Y),
    }
    print("=" * 78)
    print(" verify.py — Zydis vs XED decoder cross-check")
    print("=" * 78)
    for fr in results:
        name = os.path.basename(fr.path)
        print(f"[{badge.get(fr.status, fr.status)}] {name}")
        z, x = fr.runs.get("zydis"), fr.runs.get("xed")
        if fr.status in ("agree", "mismatch") and z and x:
            print(f"    {'':10}{'APX':>8}{'AVX10.2':>10}{'REX2':>8}{'EVEX':>8}")
            for d in ("zydis", "xed", "heuristic"):
                r = fr.runs.get(d)
                if not r:
                    continue
                print(f"    {d:<10}{_b(r.apx):>8}{_b(r.avx10_2):>10}"
                      f"{str(r.rex2):>8}{str(r.evex):>8}")
        if fr.detail:
            print(f"    {C.DIM if use_color else ''}{fr.detail}{C.X if use_color else ''}")
    # Summary.
    counts = {}
    for fr in results:
        counts[fr.status] = counts.get(fr.status, 0) + 1
    print("-" * 78)
    print(" summary: " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Cross-check petool's Zydis and XED decoders on PE files.")
    ap.add_argument("paths", nargs="+", help="PE file(s) or folder(s)")
    ap.add_argument("--bin", default="petool",
                    help="path to the petool executable (default: petool on PATH)")
    ap.add_argument("--recursive", action="store_true",
                    help="recurse into folders")
    ap.add_argument("--include-heuristic", action="store_true",
                    help="also run the byte heuristic (for context; not compared)")
    ap.add_argument("--json", metavar="FILE",
                    help="write a machine-readable JSON report to FILE")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = ap.parse_args(argv)

    files = gather_pe_files(args.paths, args.recursive)
    if not files:
        print("No PE files found.", file=sys.stderr)
        return 2

    results = [compare(f, args.bin, args.include_heuristic) for f in files]

    use_color = (not args.no_color) and sys.stdout.isatty()
    print_report(results, use_color)

    if args.json:
        payload = {
            "binary": args.bin,
            "files": [
                {
                    "path": fr.path,
                    "status": fr.status,
                    "detail": fr.detail,
                    "runs": {d: asdict(r) for d, r in fr.runs.items()},
                }
                for fr in results
            ],
        }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"Wrote JSON report: {args.json}")

    # Exit-code precedence: mismatch(1) > error/unavailable(3) > ok(0).
    statuses = {fr.status for fr in results}
    if "mismatch" in statuses:
        return 1
    if "error" in statuses:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
