# PE Toolchain Analyzer

Determines whether a Windows PE (`.exe` / `.dll`) was produced by **Intel ICX
(oneAPI DPC++/C++)**, **MSVC**, or **Clang/LLVM**, and reports compiler & linker
versions, command‑line hints, PGO/HWPGO usage, and whether the code contains
**Intel APX** and/or **AVX10.2** instructions.

The tool parses the PE format by hand (no `<Windows.h>`), so it builds with
MSVC, clang‑cl, g++, or clang on any host OS and can analyze either 32‑ or
64‑bit images.

## Build

```bash
# g++ / clang (heuristic ISA detection)
g++ -std=c++17 -O2 pe_toolchain_analyzer.cpp -o petool

# MSVC
cl /EHsc /std:c++17 pe_toolchain_analyzer.cpp

# --- CMake, heuristic only (default) ---
cmake -S . -B build
cmake --build build

# --- CMake, with EXACT decoding via Zydis and/or Intel XED (auto-fetched) ---
cmake -S . -B build -DWITH_ZYDIS=ON                # Zydis backend
cmake -S . -B build -DWITH_XED=ON                  # Intel XED backend
cmake -S . -B build -DWITH_ZYDIS=ON -DWITH_XED=ON  # BOTH; pick at runtime
cmake --build build
```

### Decoder backend options (CMake)

Both backends are optional and are **fetched from source via FetchContent** using
the upstream repositories. You may enable either or **both** — with both compiled
in, the decoder is chosen at **runtime** via `--decoder=zydis|xed`.

| Option | Default | Meaning |
|---|---|---|
| `-DWITH_ZYDIS=ON` | `OFF` | Enable the **Zydis** backend (`github.com/zyantific/zydis`). |
| `-DWITH_XED=ON` | `OFF` | Enable the **Intel XED** backend (`github.com/intelxed/xed`). |
| `-DZYDIS_USE_SYSTEM=ON` | `OFF` | Use an installed Zydis (`find_package`) instead of fetching. |
| `-DZYDIS_TAG=<ref>` | `master` | Git ref of Zydis to fetch. |
| `-DXED_TAG=<ref>` | `main` | Git ref of Intel XED to fetch. |

* **Zydis** is CMake‑native, so FetchContent builds it (and its Zycore
  dependency) directly.
* **Intel XED** uses its own Python builder (`mfile.py` + `mbuild`), so the CMake
  target fetches XED **and** its sibling `mbuild`, drives `mfile.py --static`,
  and imports the resulting `libxed`. **Python 3 must be on `PATH`.**

### Building from LOCAL sources (offline / behind a firewall)

If you already have the sources on disk (e.g. extracted from `zydis.7z` /
`xed.7z`), point the build at them — **no network is used**, and the committed
GitHub URLs stay the default for everyone else (CI, clean checkouts):

```bash
# Linux/macOS helper (wraps the CMake flags below)
./build-local.sh --zydis /path/to/zydis --xed /path/to/xed --mbuild /path/to/mbuild

# Windows helper (from a VS "x64 Native Tools" prompt)
./build-local.ps1 -Zydis C:\src\zydis -Xed C:\src\xed -Mbuild C:\src\mbuild

# …or the raw CMake, using the built-in FetchContent overrides:
cmake -S . -B build -DWITH_ZYDIS=ON -DZYDIS_LOCAL_DIR=/path/to/zydis \
                    -DWITH_XED=ON   -DXED_LOCAL_DIR=/path/to/xed \
                    -DMBUILD_LOCAL_DIR=/path/to/mbuild
cmake --build build
```

`ZYDIS_LOCAL_DIR` / `XED_LOCAL_DIR` / `MBUILD_LOCAL_DIR` set CMake's built‑in
`FETCHCONTENT_SOURCE_DIR_<name>` overrides, so FetchContent uses your tree
instead of cloning. **Extract the full clones** — Zydis needs its **Zycore**
submodule, and XED needs its sibling **mbuild** checkout.

### Fetching from GitHub behind the Intel proxy

If you'd rather let CMake clone from GitHub on the Intel network, configure git's
proxy first, then use the normal `-DWITH_*` flags:

```bash
git config --global http.proxy  http://proxy-dmz.intel.com:912
git config --global https.proxy http://proxy-dmz.intel.com:912
cmake -S . -B build -DWITH_ZYDIS=ON -DWITH_XED=ON
cmake --build build
```

## Run

```bash
petool <file.exe|file.dll> [options]
```

| Option | Effect |
|---|---|
| `--json` | Emit a machine‑readable JSON report instead of text. |
| `--verbose` | Include Rich header, evidence, and ISA scan detail (text mode). |
| `--decoder=<name>` | Choose the ISA decoder backend: `heuristic` \| `zydis` \| `xed`. |
| `--scan-all-sections` | Scan **every** executable section and aggregate (default: only the first/primary code section). |
| `--zydis` / `--no-zydis` | Aliases for `--decoder=zydis` / `--decoder=heuristic`. |
| `--xed` | Alias for `--decoder=xed`. |
| `-h`, `--help` | Show help. Footer lists the backends compiled into this build. |

`--decoder` selects the ISA‑detection engine **at run time**. If you request a
backend that was not compiled in, the tool prints a note and falls back to the
heuristic (exit still succeeds). The default decoder is the first compiled‑in
exact backend (Zydis, then XED), otherwise the heuristic. Exit codes: `0`
success, `1` analysis failure (e.g. not a PE), `2` bad usage/invalid option.

### JSON schema (top level)

```jsonc
{
  "file": "...",
  "image":  { "kind": "exe|dll", "bits": 32|64, "machine": "...", "machineCode": 0 },
  "toolchain": { "detected": "...", "scores": {icx,icc,clang,msvc},
                 "compilerVersion": "..."|null, "linkerVersion": "..." },
  "commandLineOptions": { "authoritativeSource": "PDB ...", "hintsFromImage": [ ... ] },
  "pgo": { "msvcPogo": bool, "llvmInstrumentationPgo": bool,
           "hwpgo": bool|null, "hwpgoConfidence": "heuristic", "detail": "..."|null },
  "isa": { "applicable": bool, "decoder": "heuristic|zydis|xed|n/a",
           "sectionsScanned": 0, "definitive": bool, "avx10Resolvable": bool,
           "apx": bool|null, "avx10_2": bool|null,
           "rex2Candidates": 0, "evexCount": 0, "apxCount": 0,
           "avx10SetCount": 0, "detail": "..."|null },
  "richHeader": [ ... ],
  "notes": [ ... ]
}
```

`apx` / `avx10_2` are `null` when the answer is unknown (heuristic with nonzero
candidates, or non‑x86 target) and `true`/`false` only when it can be asserted
(`definitive` decoding, or heuristic proving *absence* with zero candidates).
`avx10Resolvable` is `false` when the selected decoder has no AVX10.2 tables at
all (currently any Zydis build), in which case `avx10_2` is always `null`.

## How each fact is derived

| Reported item | Source of truth | Method |
|---|---|---|
| **Toolchain** | Embedded strings + Rich header | ICX ⇒ `Intel(R) oneAPI` / `__INTEL_LLVM_COMPILER`; Clang ⇒ `clang version`; MSVC ⇒ Rich header + `Microsoft (R) ... Compiler`. ICX embeds a Clang fingerprint too, so ICX evidence outranks bare Clang. |
| **Compiler version** | Version strings / Rich header | Regex on `clang version X.Y.Z`, `Intel oneAPI ... N`, and Rich‑header build numbers. |
| **Linker version** | Optional Header + Rich header + LLD string | `Major/MinorLinkerVersion`; `LLD X.Y.Z` for lld‑link. |
| **Command‑line options** | **PDB (authoritative)** | The linked image rarely stores the compiler command line. The tool surfaces any option‑like strings it finds and points you to the PDB (`S_COMPILE3` / `S_ENVBLOCK` via the DIA SDK or `llvm-pdbutil`) and to `dumpbin /DIRECTIVES` on the `.obj`. The PDB path is extracted from the CodeView (`RSDS`) debug record. |
| **MSVC PGO** | Debug directory | `IMAGE_DEBUG_TYPE_POGO` (13) record ⇒ MSVC PGO/BBT layout data. |
| **LLVM instrumentation PGO** | Sections/symbols | Presence of `__llvm_prf_cnts/_data/_names` (`.lprfc/.lprfn`). |
| **HWPGO / sample PGO** | *Heuristic* | Sample/hardware PGO (AutoFDO/CSSPGO, `-fprofile-sample-use`) leaves **no** dedicated section, so this is best‑effort: option strings in debug info / `SampleProfile` markers. Reported as `Yes / No / Undetermined`. |
| **APX** | Executable sections | Intel APX uses the 2‑byte **REX2** prefix `0xD5` (long mode only). Heuristic counts validated `0xD5` candidates. The **XED build** calls `xed_classify_apx()`, which covers all four flavors: the `REX2` prefix, EGPR register *or* memory operands, set-but-ignored APX EVEX bits, and the APX foundation ISA‑sets. The **Zydis build** uses `ZYDIS_ATTRIB_HAS_REX2` plus the `APX*` ISA‑set/extension names, which misses the EGPR‑only case and so reads slightly low. |
| **AVX10.2** | Executable sections | AVX10.2 uses **extended EVEX** (`0x62`). EVEX alone cannot be distinguished from AVX‑512 by raw bytes, so the heuristic reports EVEX presence only. The **XED build** walks each ISA‑set's CPUID groups and counts an instruction only when *every* group requires AVX10 version ≥ 2 (leaf `0x24`, including the `AVX10_V2_AUX` bit); ISA‑sets such as `AVX512F_512` that also carry a legacy AVX‑512 group run on pre‑AVX10 hardware and are not counted. **Zydis cannot answer this at all** — through v5 it ships no AVX10.2 mnemonics or ISA‑sets — so it reports `Undetermined` / `null` rather than a false `No`. |

## Cross-checking the two decoders (`verify.py`)

`verify.py` runs `petool` on your PE files with **both** exact decoders
(`--decoder=zydis` and `--decoder=xed`), compares their APX / AVX10.2 verdicts,
and reports any disagreement. Run it against a `petool` built with **both**
backends (`-DWITH_ZYDIS=ON -DWITH_XED=ON`). Standard library only.

```bash
python verify.py --bin ./build/petool ./some_dlls --recursive
python verify.py --bin ./build/petool a.dll b.dll --json report.json
python verify.py --bin ./build/petool a.dll --include-heuristic   # extra context
```

Per file it prints one of **AGREE / MISMATCH / SKIPPED / ERROR** plus a small
APX/AVX10.2/REX2/EVEX table. A feature that one backend cannot resolve (`null`,
such as AVX10.2 under Zydis) is reported as *not comparable* rather than scored
as a disagreement. **Exit codes** make it CI-friendly:
`0` = all comparable files agree, `1` = at least one **mismatch**, `2` = usage /
no PE files, `3` = a backend was unavailable or `petool` failed. Non-PE inputs
and non-x86 targets are **skipped** (not errors); a `zydis`/`xed` request that
silently falls back to the heuristic (backend not compiled in) is reported as an
**error** so you notice the missing backend.

## Continuous integration

`.github/workflows/ci.yml` builds a matrix of **{ Ubuntu, Windows } × { heuristic,
zydis, xed }** (6 configurations). Each job configures with the matching
`-DWITH_*` flags, builds, checks the backend banner, then runs the analyzer on a
real PE (`kernel32.dll` on Windows; a MinGW‑cross‑built stub on Linux) in text,
`--json`, and `--scan-all-sections` modes, validating the JSON with Python. Built
binaries are uploaded as artifacts. XED jobs set up Python 3 (its build driver);
Windows jobs load the MSVC dev environment so both CMake and XED's `mfile.py` find
`cl.exe`.

## Accuracy notes (read me)

* **APX / AVX10.2 without a decoder are heuristic.** A raw byte scan cannot track
  instruction boundaries, so `0xD5`/`0x62` bytes inside displacements or
  immediates produce false positives. The heuristic output therefore says
  *“None found / Undetermined (heuristic)”* and never a hard *Yes*. Build with
  `-DWITH_ZYDIS=ON` and/or `-DWITH_XED=ON` and run `--decoder=zydis|xed` for a
  definitive result. Only **XED** can resolve AVX10.2; Zydis provides APX
  metadata but has no AVX10.2 tables.
* **A single stray decode can flip the APX verdict.** The scan is a linear sweep
  with `+1` resync, so data, jump tables and padding occasionally decode as
  REX2-prefixed instructions. Because the verdict is "any APX instruction
  found", a known non-APX image such as `mshtml.dll` still reports `APX: Yes`
  off 8 spurious hits in 17.8 MB. Treat low counts as noise and compare against
  the counts, not just the boolean.
* **Non‑x86 targets** (e.g. ARM64) report APX/AVX10.2 as **N/A** — the x86 ISA
  scan is skipped entirely.
* **Command‑line options** are only fully recoverable from the **PDB**; the tool
  is explicit about this rather than guessing.
* **ICX vs Clang:** because ICX is LLVM‑based and emits a Clang version string,
  the tool weights Intel‑specific markers higher so ICX is not misreported as
  plain Clang.
