// ============================================================================
//  pe_toolchain_analyzer.cpp
//
//  Determines whether a Windows PE (.exe / .dll) was produced by the
//  Intel ICX (oneAPI DPC++/C++), MSVC, or Clang/LLVM toolchain and reports:
//     * compiler + linker versions
//     * command-line options (best-effort, authoritative source = PDB)
//     * whether PGO / HWPGO was used
//     * whether the code contains Intel APX (REX2) instructions
//     * whether the code contains AVX10.2 (extended-EVEX) instructions
//
//  Design goals
//  ------------
//  * Self-contained: parses the PE format by hand (no <Windows.h>), so it
//    compiles with MSVC, clang-cl, g++ and clang on any host OS.
//  * Honest about confidence: heuristic results are clearly labelled.
//  * Optional exact ISA decoding via Zydis (build with -DUSE_ZYDIS). When
//    built with Zydis, the decoder can still be toggled at RUNTIME with
//    --zydis / --no-zydis.
//
//  Build
//  -----
//    MSVC   : cl /EHsc /std:c++17 pe_toolchain_analyzer.cpp
//    clang  : clang++ -std=c++17 -O2 pe_toolchain_analyzer.cpp -o petool
//    g++    : g++     -std=c++17 -O2 pe_toolchain_analyzer.cpp -o petool
//    +Zydis : add  -DUSE_ZYDIS  and link against Zydis (>=4.1, APX/AVX10 aware)
//             (the provided CMakeLists.txt fetches Zydis automatically)
//
//  Usage
//  -----
//    petool <file.exe|file.dll> [--verbose] [--json]
//                               [--zydis | --no-zydis]
//      --json       Emit a machine-readable JSON report instead of text.
//      --verbose    Include Rich header, evidence, and ISA scan detail.
//      --zydis      Force exact decoding (only if built with Zydis; default
//                   when Zydis support is compiled in).
//      --no-zydis   Force the byte-level heuristic even if Zydis is available.
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>
#include <optional>

#ifdef USE_ZYDIS
#include <Zydis/Zydis.h>
#endif
#ifdef USE_XED
extern "C" {
#include <xed/xed-interface.h>
}
#endif

// ---------------------------------------------------------------------------
//  Minimal PE structure definitions (subset, packed) — avoids <Windows.h>.
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;      // 'MZ'
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;     // file offset of the PE header
};

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

// PE32 and PE32+ share the leading fields; we read the pieces we need
// with explicit offsets to stay agnostic to magic.
struct OptionalHeaderCommon {
    uint16_t Magic;                 // 0x10b = PE32, 0x20b = PE32+
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
};

struct SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct DebugDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
};
#pragma pack(pop)

static const uint32_t IMAGE_SCN_MEM_EXECUTE  = 0x20000000;
static const uint32_t IMAGE_SCN_CNT_CODE     = 0x00000020;
static const uint16_t IMAGE_FILE_DLL         = 0x2000;
static const uint32_t IMAGE_DEBUG_TYPE_CODEVIEW = 2;
static const uint32_t IMAGE_DEBUG_TYPE_POGO     = 13; // MS PGO reorder data
static const uint32_t IMAGE_DEBUG_TYPE_VC_FEATURE = 12;
static const uint32_t IMAGE_DEBUG_TYPE_ILTCG     = 14; // incremental LTCG
static const uint16_t MACHINE_AMD64 = 0x8664;
static const uint16_t MACHINE_I386  = 0x14c;
static const uint16_t MACHINE_ARM64 = 0xAA64;

// ---------------------------------------------------------------------------
//  Result model
// ---------------------------------------------------------------------------
enum class Toolchain { Unknown, MSVC, ClangLLVM, IntelICX, IntelClassic };

static const char* toolName(Toolchain t) {
    switch (t) {
        case Toolchain::MSVC:         return "Microsoft Visual C++ (MSVC)";
        case Toolchain::ClangLLVM:    return "Clang / LLVM";
        case Toolchain::IntelICX:     return "Intel oneAPI DPC++/C++ (ICX/ICPX)";
        case Toolchain::IntelClassic: return "Intel C++ Classic (ICC/ICL)";
        default:                      return "Unknown";
    }
}

struct Evidence {
    std::string what;
    std::string detail;
    int         weight;   // contribution to confidence
};

struct AnalysisResult {
    std::string file;
    bool        is64 = false;
    bool        isDll = false;
    uint16_t    machine = 0;

    Toolchain   toolchain = Toolchain::Unknown;
    int         msvcScore = 0, clangScore = 0, icxScore = 0, iccScore = 0;

    std::string linkerVersion;       // from optional header + Rich header
    std::string compilerVersion;     // from embedded strings / Rich header
    std::vector<std::string> commandLineHints;

    // PGO
    bool msvcPogo = false;           // IMAGE_DEBUG_TYPE_POGO present
    bool llvmInstrPgo = false;       // __llvm_prf_* present (instrumentation)
    std::optional<bool> hwpgo;       // Intel HW / sample PGO (best-effort)
    std::string pgoDetail;

    // ISA
    bool isaApplicable = true;       // false for non-x86 targets (ARM64, etc.)
    bool apx = false;                // REX2 (0xD5) usage in 64-bit code
    bool avx10_2 = false;            // extended-EVEX AVX10.2 usage
    bool definitive = false;         // true => decoder-backed (Zydis/XED) answer
    std::string decoderName = "heuristic"; // heuristic | zydis | xed | n/a
    int  sectionsScanned = 0;        // number of executable sections analyzed
    uint64_t rex2Count = 0;          // REX2 prefix instruction (or candidate) count
    uint64_t evexCount = 0;          // EVEX-encoded instruction (or candidate) count
    uint64_t apxCount = 0;           // APX-requiring instruction count (decoder only)
    uint64_t avx10Count = 0;         // AVX10.2-requiring instruction count (decoder only)
    std::string isaDetail;

    std::vector<Evidence> evidence;
    std::vector<std::string> richHeader; // decoded Rich header lines
    std::vector<std::string> notes;
};

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------
static bool readFile(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize sz = f.tellg();
    if (sz <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(sz));
    return static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), sz));
}

template <typename T>
static bool readAt(const std::vector<uint8_t>& b, size_t off, T& dst) {
    if (off + sizeof(T) > b.size()) return false;
    std::memcpy(&dst, b.data() + off, sizeof(T));
    return true;
}

static bool contains(const std::vector<uint8_t>& hay, const char* needle) {
    size_t n = std::strlen(needle);
    if (n == 0 || hay.size() < n) return false;
    auto it = std::search(hay.begin(), hay.end(),
                          needle, needle + n);
    return it != hay.end();
}

// Collect printable ASCII strings of length >= minLen from the buffer.
static void extractStrings(const std::vector<uint8_t>& b, size_t minLen,
                           std::vector<std::string>& out) {
    std::string cur;
    for (uint8_t c : b) {
        if (c >= 0x20 && c < 0x7f) {
            cur.push_back(static_cast<char>(c));
        } else {
            if (cur.size() >= minLen) out.push_back(cur);
            cur.clear();
        }
    }
    if (cur.size() >= minLen) out.push_back(cur);
}

// ---------------------------------------------------------------------------
//  Rich header decoding (MSVC / clang-cl / ICX all emit this via the MS linker)
//
//  Layout: after the DOS stub, before the PE header, there is an XOR-masked
//  block ending with "Rich" + key. The block starts with "DanS" XOR key.
//  Between them are (compid, count) 32-bit pairs, also XORed with the key.
//  compid = (productId << 16) | buildNumber  (buildNumber == compiler build).
// ---------------------------------------------------------------------------
struct RichEntry { uint16_t prodId; uint16_t build; uint32_t count; };

static const char* richProductName(uint16_t prodId) {
    // Coarse mapping of the most relevant product-id families.
    if (prodId == 0x00) return "Unmarked/Import";
    if (prodId >= 0x006d && prodId <= 0x0071) return "VS2003 (VC7.1)";
    if (prodId >= 0x005a && prodId <= 0x0060) return "VS2005 (VC8)";
    if (prodId >= 0x0083 && prodId <= 0x0094) return "VS2008 (VC9)";
    if (prodId >= 0x0095 && prodId <= 0x00a6) return "VS2010 (VC10)";
    if (prodId >= 0x00c7 && prodId <= 0x00d9) return "VS2012 (VC11)";
    if (prodId >= 0x00e0 && prodId <= 0x00ec) return "VS2013 (VC12)";
    if (prodId >= 0x00ff && prodId <= 0x0106) return "VS2015 (VC14)";
    if (prodId >= 0x0100 && prodId <= 0x0103) return "VS2017 (VC14.1)";
    if (prodId >= 0x0104 && prodId <= 0x0107) return "VS2019 (VC14.2)";
    if (prodId >= 0x0108 && prodId <= 0x010f) return "VS2022 (VC14.3)";
    return "MSVC toolset";
}

// Map a linker build number back to a human MSVC toolset version (approx).
static std::string msvcBuildToVersion(uint16_t build) {
    // The build number in the Rich header is the exact compiler/linker build.
    // We surface it verbatim and add a coarse family label.
    std::ostringstream os;
    os << "build " << build;
    if (build >= 30000 && build < 40000) os << " (VS2017/2019/2022-era toolset)";
    else if (build >= 20000)             os << " (VS2013/2015-era toolset)";
    return os.str();
}

static void decodeRichHeader(const std::vector<uint8_t>& b, size_t peOff,
                             AnalysisResult& r) {
    // Search the region [0x40, peOff) for the "Rich" tag.
    if (peOff < 0x80 || peOff > b.size()) return;
    size_t richPos = std::string::npos;
    for (size_t i = 0x40; i + 4 <= peOff; ++i) {
        if (b[i]=='R'&&b[i+1]=='i'&&b[i+2]=='c'&&b[i+3]=='h') { richPos = i; break; }
    }
    if (richPos == std::string::npos) return;
    uint32_t key = 0;
    if (!readAt(b, richPos + 4, key)) return;

    // Walk backwards in 4-byte steps looking for "DanS" ^ key.
    const uint32_t DANS = 0x536E6144; // 'D','a','n','S'
    size_t start = std::string::npos;
    for (size_t i = richPos; i >= 0x40 + 4; i -= 4) {
        uint32_t v = 0;
        if (!readAt(b, i - 4, v)) break;
        if ((v ^ key) == DANS) { start = i - 4; break; }
        if (i < 0x44) break;
    }
    if (start == std::string::npos) return;

    // Entries live between start+16 (after DanS + 3 padding dwords) and richPos.
    std::map<uint32_t, uint32_t> tally; // compid -> count
    for (size_t i = start + 16; i + 8 <= richPos; i += 8) {
        uint32_t comp = 0, cnt = 0;
        readAt(b, i, comp); readAt(b, i + 4, cnt);
        comp ^= key; cnt ^= key;
        tally[comp] = cnt;
    }
    for (auto& kv : tally) {
        uint16_t prod  = static_cast<uint16_t>(kv.first >> 16);
        uint16_t build = static_cast<uint16_t>(kv.first & 0xffff);
        std::ostringstream os;
        os << "prodId=0x" << std::hex << prod << std::dec
           << " build=" << build << " count=" << kv.second
           << "  [" << richProductName(prod) << "]";
        r.richHeader.push_back(os.str());
        if (r.compilerVersion.empty() && prod != 0)
            r.compilerVersion = std::string(richProductName(prod)) + ", "
                              + msvcBuildToVersion(build);
    }
}

// ---------------------------------------------------------------------------
//  Toolchain fingerprinting from embedded strings.
// ---------------------------------------------------------------------------
static void fingerprintFromStrings(const std::vector<std::string>& strs,
                                   AnalysisResult& r) {
    std::regex reClang(R"(clang version\s+([0-9]+\.[0-9]+\.[0-9]+))",
                       std::regex::icase);
    std::regex reIcx(R"(Intel\(R\)\s+(oneAPI\s+DPC\+\+/C\+\+|LLVM)\s+Compiler[^0-9]*([0-9]{4}\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+\.[0-9]+))",
                     std::regex::icase);
    std::regex reIcc(R"(Intel\(R\)\s+C\+\+\s+(Intel\(R\)\s+64\s+)?Compiler[^0-9]*([0-9]+\.[0-9]+))",
                     std::regex::icase);
    std::regex reMsvcC(R"(Microsoft \(R\).*Compiler Version\s+([0-9.]+))",
                       std::regex::icase);
    std::regex reLld(R"(LLD\s+([0-9]+\.[0-9]+\.[0-9]+))", std::regex::icase);

    for (const auto& s : strs) {
        std::smatch m;

        // ---- Intel ICX (LLVM-based) -------------------------------------
        if (std::regex_search(s, m, reIcx)) {
            r.icxScore += 100;
            r.compilerVersion = "Intel oneAPI DPC++/C++ Compiler " + m[2].str();
            r.evidence.push_back({"string", s, 100});
        }
        if (s.find("__INTEL_LLVM_COMPILER") != std::string::npos ||
            s.find("Intel(R) oneAPI") != std::string::npos ||
            s.find("oneAPI/compiler") != std::string::npos ||
            s.find("intel/oneapi") != std::string::npos) {
            r.icxScore += 40;
            r.evidence.push_back({"string", s, 40});
        }

        // ---- Intel classic (ICC/ICL) ------------------------------------
        if (std::regex_search(s, m, reIcc) ||
            s.find("__INTEL_COMPILER") != std::string::npos) {
            r.iccScore += 60;
            if (r.compilerVersion.empty())
                r.compilerVersion = "Intel C++ Classic " +
                                    (m.size() > 2 ? m[2].str() : std::string());
            r.evidence.push_back({"string", s, 60});
        }

        // ---- Clang / LLVM -----------------------------------------------
        if (std::regex_search(s, m, reClang)) {
            r.clangScore += 70;
            if (r.compilerVersion.empty())
                r.compilerVersion = "clang version " + m[1].str();
            r.evidence.push_back({"string", s, 70});
        }
        if (std::regex_search(s, m, reLld)) {
            r.clangScore += 20;
            if (r.linkerVersion.empty())
                r.linkerVersion = "LLD " + m[1].str();
            r.evidence.push_back({"string", s, 20});
        }

        // ---- MSVC --------------------------------------------------------
        if (std::regex_search(s, m, reMsvcC)) {
            r.msvcScore += 50;
            if (r.compilerVersion.empty())
                r.compilerVersion = "MSVC compiler " + m[1].str();
            r.evidence.push_back({"string", s, 50});
        }

        // ---- Command-line option hints (best effort) --------------------
        // The authoritative source is the PDB (S_COMPILE3 / S_ENVBLOCK).
        // Some options leak into .debug$S / directive strings in the image.
        if (s.rfind("/GL", 0) == 0 || s.find(" /GL") != std::string::npos ||
            s.find("/O2") != std::string::npos || s.find("/Ox") != std::string::npos ||
            s.find("/guard:cf") != std::string::npos ||
            s.find("/DEBUG") != std::string::npos ||
            s.find("-flto") != std::string::npos ||
            s.find("-O2") != std::string::npos || s.find("-O3") != std::string::npos ||
            s.find("-march=") != std::string::npos ||
            s.find("-fprofile") != std::string::npos ||
            s.find("/Qax") != std::string::npos || s.find("-x") == 0) {
            if (s.size() < 400) r.commandLineHints.push_back(s);
        }
    }
}

// ---------------------------------------------------------------------------
//  PGO / HWPGO detection.
// ---------------------------------------------------------------------------
static void detectPgo(const std::vector<uint8_t>& buf,
                      const std::vector<SectionHeader>& secs,
                      const std::vector<std::string>& strs,
                      AnalysisResult& r) {
    // MSVC classic PGO -> IMAGE_DEBUG_TYPE_POGO handled during debug-dir scan.

    // LLVM instrumentation PGO (-fprofile-instr-generate / -fprofile-generate)
    // leaves __llvm_prf_* symbols/sections; instrumented builds keep counters.
    static const char* llvmPrf[] = {
        "__llvm_prf_cnts", "__llvm_prf_data", "__llvm_prf_names",
        "__llvm_prf_vnds", ".lprfc", ".lprfn", ".lprfd"
    };
    for (const char* s : llvmPrf)
        if (contains(buf, s)) { r.llvmInstrPgo = true; break; }
    for (auto& sec : secs) {
        std::string n(sec.Name, strnlen(sec.Name, 8));
        if (n == ".lprfc" || n == ".lprfn" || n == ".lprfd") r.llvmInstrPgo = true;
    }

    // HWPGO / sample-based PGO detection (best-effort).
    //  * Intel ICX & LLVM support sample/HW PGO via -fprofile-sample-use
    //    (AutoFDO/CSSPGO). Unlike instrumentation PGO, it leaves NO dedicated
    //    counter section, so detection is inherently heuristic.
    //  * Signals we look for: option strings embedded in debug info, and the
    //    LLVM sample-profile discriminator metadata marker.
    bool sampleOpt = false;
    for (const auto& s : strs) {
        if (s.find("-fprofile-sample-use") != std::string::npos ||
            s.find("-fprofile-use") != std::string::npos ||
            s.find("hwpgo") != std::string::npos ||
            s.find("-fauto-profile") != std::string::npos ||
            s.find("SampleProfile") != std::string::npos ||
            s.find("csspgo") != std::string::npos) {
            sampleOpt = true;
            r.pgoDetail += (r.pgoDetail.empty() ? "" : "; ");
            r.pgoDetail += "sample/HW-PGO option string: \"" + s + "\"";
        }
    }
    if (sampleOpt) r.hwpgo = true;
    else if (r.llvmInstrPgo || r.msvcPogo) r.hwpgo = false; // some PGO, but not HW/sample
    // else leave nullopt = undetermined
}

// ---------------------------------------------------------------------------
//  APX (REX2 / 0xD5) and AVX10.2 (extended EVEX / 0x62) detection.
//
//  Without a full decoder we can only give a heuristic scan of the executable
//  sections. With Zydis (compiled in + enabled at runtime) we decode every
//  instruction and consult the ISA-set / attribute metadata for an
//  authoritative answer.
// ---------------------------------------------------------------------------
// Accumulator so multiple sections (--scan-all-sections) can be aggregated.
struct IsaCounts {
    uint64_t rex2 = 0;   // instructions carrying a REX2 prefix, or candidates (heuristic)
    uint64_t evex = 0;   // EVEX-encoded instructions or candidates
    uint64_t apx  = 0;   // instructions requiring APX hardware (decoder only)
    uint64_t avx10 = 0;  // instructions requiring AVX10.2 hardware (decoder only)
};

// Runtime decoder backend selection.
enum class Decoder { Heuristic, Zydis, Xed };

static const char* decoderName(Decoder d) {
    switch (d) {
        case Decoder::Zydis: return "zydis";
        case Decoder::Xed:   return "xed";
        default:             return "heuristic";
    }
}

static void scanIsaHeuristic(const uint8_t* code, size_t len, bool is64,
                             IsaCounts& acc) {
    // NOTE: This is a byte-level heuristic. In 64-bit mode 0xD5 is *only* the
    // REX2 prefix (its legacy AAD meaning is invalid in long mode), so a 0xD5
    // followed by a plausible opcode strongly implies APX. 0x62 (EVEX) is used
    // by both AVX-512 and AVX10.2; we cannot distinguish the sub-version from
    // raw bytes, so EVEX presence is reported separately and AVX10.2 is only
    // asserted via a real decoder. False positives are possible because we are
    // not tracking instruction boundaries.

    // Bytes that may NOT legally follow a REX2 prefix (it is a *terminal*
    // prefix in long mode): further prefixes, escapes, and the inc/dec row.
    auto illegalAfterRex2 = [](uint8_t op) {
        if (op == 0x0F) return true;                 // 2-byte escape (map via M0)
        if (op >= 0x40 && op <= 0x4F) return true;   // REX / inc,dec (NoRex2)
        if (op == 0x62 || op == 0xC4 || op == 0xC5)  // EVEX / VEX
            return true;
        if (op == 0xD5) return true;                 // another REX2
        if (op == 0x66 || op == 0x67 || op == 0xF0 ||
            op == 0xF2 || op == 0xF3) return true;    // legacy prefixes
        if (op == 0x26 || op == 0x2E || op == 0x36 ||
            op == 0x3E || op == 0x64 || op == 0x65) return true; // seg prefixes
        return false;
    };
    for (size_t i = 0; i + 2 < len; ++i) {
        uint8_t c = code[i];
        if (is64 && c == 0xD5) {
            // 0xD5 is REX2-only in long mode. Require a plausible opcode after
            // the payload byte to reject stray 0xD5 data bytes.
            uint8_t op = code[i + 2];
            if (!illegalAfterRex2(op)) { acc.rex2++; i += 2; }
        } else if (c == 0x62) {
            // EVEX must be 4 bytes; byte-1 (P0) has bit2 (0x04) always set and
            // bits[3:2] map field constrained -> a light sanity filter.
            uint8_t p0 = code[i + 1];
            if ((p0 & 0x04) && (i + 3 < len)) { acc.evex++; i += 3; }
        }
    }
}

#ifdef USE_ZYDIS
static void scanIsaZydis(const uint8_t* code, size_t len, bool is64,
                         IsaCounts& acc) {
    ZydisDecoder dec;
    ZydisDecoderInit(&dec,
        is64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
        is64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    size_t off = 0;
    while (off < len) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, len - off,
                                                &insn, ops))) {
            if (insn.attributes & ZYDIS_ATTRIB_HAS_REX2) { acc.rex2++; acc.apx++; }
            if (insn.encoding == ZYDIS_INSTRUCTION_ENCODING_EVEX) acc.evex++;
            // ISA-set / extension enums vary by Zydis version; string-match
            // keeps this robust across 4.x builds that added APX/AVX10.
            const char* iset = ZydisISASetGetString(insn.meta.isa_set);
            if (iset) {
                std::string s = iset;
                if (s.find("APX") != std::string::npos) acc.apx++;
                if (s.find("AVX10") != std::string::npos) acc.avx10++;
            }
            off += insn.length;
        } else {
            off += 1; // resync on bad byte
        }
    }
}
#endif

#ifdef USE_XED
// ---------------------------------------------------------------------------
//  XED classification tables, computed once at first use.
//
//  Neither APX nor AVX10 membership can be recovered from ISA-set *names*:
//    * XED expresses AVX10 through the CPUID mapping, not by renaming ISA-sets.
//      An AVX10.2-capable instruction usually reports AVX512F_512 / AVX512BW_128
//      and carries both an AVX10 CPUID group and a legacy AVX-512 group.
//    * Legacy instructions carrying a REX2 prefix, and EVEX instructions using
//      EGPRs, are given no new iform and no new ISA-set at all.
//  So the tables below walk the CPUID group records per ISA-set, and the scan
//  loop uses encoding-space fields plus a chip check on the decoded instruction.
// ---------------------------------------------------------------------------
namespace xedcls {

static const uint8_t REQUIRES_AVX10_2 = 1u << 0;

struct Tables {
    std::vector<uint8_t> isaFlags;                    // by xed_isa_set_enum_t
    xed_extension_enum_t apxLegacy = XED_EXTENSION_INVALID;
    xed_extension_enum_t apxEvex   = XED_EXTENSION_INVALID;
    xed_chip_enum_t      preApx    = XED_CHIP_INVALID; // newest pre-APX chip
};

// True only when *every* CPUID group satisfying this ISA-set demands AVX10
// version >= 2. A set that also has a plain AVX-512 group runs on pre-AVX10
// hardware and must not be counted as AVX10.2.
static bool requiresAvx10_2(xed_isa_set_enum_t is) {
    bool anyGroup = false;
    for (unsigned g = 0; g < XED_MAX_CPUID_GROUPS_PER_ISA_SET; ++g) {
        xed_cpuid_group_enum_t grp = xed_get_cpuid_group_enum_for_isa_set(is, g);
        if (grp == XED_CPUID_GROUP_INVALID) continue;
        anyGroup = true;
        bool groupNeedsV2 = false;
        for (unsigned k = 0; k < XED_MAX_CPUID_RECS_PER_GROUP; ++k) {
            xed_cpuid_rec_enum_t rec = xed_get_cpuid_rec_enum_for_group(grp, k);
            if (rec == XED_CPUID_REC_INVALID) continue;
            xed_cpuid_rec_t cr;
            if (!xed_get_cpuid_rec(rec, &cr)) continue;
            // CPUID leaf 0x24 carries the AVX10 converged-vector version field.
            const bool avx10Version2 =
                cr.leaf == 0x24 && cr.subleaf == 0 &&
                cr.reg == XED_REG_EBX && cr.bit_start == 0 &&
                cr.bit_end == 7 && cr.value >= 2;
            const bool avx10V2Aux =
                cr.leaf == 0x24 && cr.subleaf == 1 &&
                cr.reg == XED_REG_ECX && cr.bit_start == 3 &&
                cr.bit_end == 3 && cr.value == 1;
            if (avx10Version2 || avx10V2Aux) groupNeedsV2 = true;
        }
        if (!groupNeedsV2) return false;   // this group is satisfiable without AVX10.2
    }
    return anyGroup;
}

static const Tables& tables() {
    static const Tables t = [] {
        xed_tables_init();
        Tables x;
        x.isaFlags.assign(static_cast<size_t>(XED_ISA_SET_LAST), 0);
        for (int i = 0; i < XED_ISA_SET_LAST; ++i) {
            auto is = static_cast<xed_isa_set_enum_t>(i);
            if (requiresAvx10_2(is)) x.isaFlags[i] |= REQUIRES_AVX10_2;
        }
        // Resolved by name so the build still succeeds on a XED without APX.
        x.apxLegacy = str2xed_extension_enum_t("APXLEGACY");
        x.apxEvex   = str2xed_extension_enum_t("APXEVEX");
        x.preApx    = str2xed_chip_enum_t("GRANITE_RAPIDS");
        return x;
    }();
    return t;
}

} // namespace xedcls

static void scanIsaXed(const uint8_t* code, size_t len, bool is64,
                       IsaCounts& acc) {
    const xedcls::Tables& T = xedcls::tables();

    xed_state_t dstate;
    xed_state_zero(&dstate);
    dstate.mmode = is64 ? XED_MACHINE_MODE_LONG_64
                        : XED_MACHINE_MODE_LEGACY_32;
    dstate.stack_addr_width = is64 ? XED_ADDRESS_WIDTH_64b
                                   : XED_ADDRESS_WIDTH_32b;

    size_t off = 0;
    while (off < len) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero_set_mode(&xedd, &dstate);
        unsigned int avail = static_cast<unsigned int>(
            std::min<size_t>(len - off, XED_MAX_INSTRUCTION_BYTES));
        xed_error_enum_t err = xed_decode(&xedd, code + off, avail);
        if (err == XED_ERROR_BUFFER_TOO_SHORT) break; // tail shorter than one insn
        if (err != XED_ERROR_NONE) { off += 1; continue; } // resync on bad byte

        // vexvalid==2 is the EVEX encoding space itself. xed_classify_avx512()
        // would miss APX-EVEX and would wrongly count the VEX-encoded mask ops.
        if (xed3_operand_get_vexvalid(&xedd) == 2) acc.evex++;

        bool rex2 = xed3_operand_get_rex2(&xedd) != 0;
        if (rex2) acc.rex2++;

        xed_isa_set_enum_t   iset = xed_decoded_inst_get_isa_set(&xedd);
        xed_extension_enum_t ext  = xed_decoded_inst_get_extension(&xedd);
        bool apx = rex2
                || (T.apxLegacy != XED_EXTENSION_INVALID && ext == T.apxLegacy)
                || (T.apxEvex   != XED_EXTENSION_INVALID && ext == T.apxEvex);
        // Remaining flavor: an ordinary EVEX instruction using an EGPR keeps its
        // original ISA-set, so only a chip check on the decoded instruction sees
        // it. Gating on "ISA-set itself predates APX" keeps newer non-APX ISAs
        // (e.g. AVX10.2) from being misattributed.
        if (!apx && T.preApx != XED_CHIP_INVALID &&
            xed_isa_set_is_valid_for_chip(iset, T.preApx) &&
            !xed_decoded_inst_valid_for_chip(&xedd, T.preApx))
            apx = true;
        if (apx) acc.apx++;

        if (static_cast<size_t>(iset) < T.isaFlags.size() &&
            (T.isaFlags[iset] & xedcls::REQUIRES_AVX10_2))
            acc.avx10++;

        off += xed_decoded_inst_get_length(&xedd);
    }
}
#endif

// Finalize the AnalysisResult ISA verdict from aggregated counts.
static void finalizeIsa(Decoder dec, bool definitive, const IsaCounts& acc,
                        AnalysisResult& r) {
    r.rex2Count  = acc.rex2;
    r.evexCount  = acc.evex;
    r.apxCount   = acc.apx;
    r.avx10Count = acc.avx10;
    r.definitive = definitive;
    r.decoderName = decoderName(dec);
    std::ostringstream os;
    if (definitive) {
        r.apx     = (acc.apx > 0) || (acc.rex2 > 0);
        r.avx10_2 = (acc.avx10 > 0);
        os << r.decoderName << " decode across " << r.sectionsScanned
           << " section(s): REX2-prefixed=" << acc.rex2 << " EVEX=" << acc.evex
           << " APX-requiring=" << acc.apx << " AVX10.2-requiring=" << acc.avx10;
    } else {
        // Heuristic: never assert APX; only prove absence with 0 candidates.
        r.apx     = (acc.rex2 >= 4);
        r.avx10_2 = false;
        os << "heuristic byte scan across " << r.sectionsScanned
           << " section(s): REX2(0xD5) candidates=" << acc.rex2
           << ", EVEX(0x62) hits=" << acc.evex
           << " (EVEX cannot be resolved to AVX10.2 vs AVX-512 without a decoder)";
    }
    r.isaDetail = os.str();
}

// ---------------------------------------------------------------------------
//  Core PE walk.
//    reqDecoder : runtime-requested ISA decoder backend. Honored only if the
//                 corresponding backend was compiled in; otherwise a note is
//                 added and the byte-level heuristic is used.
//    scanAll    : when true, scan every executable section and aggregate;
//                 otherwise stop after the first (primary) code section.
// ---------------------------------------------------------------------------
static bool analyze(const std::string& path, Decoder reqDecoder, bool scanAll,
                    AnalysisResult& r) {
    r.file = path;
    std::vector<uint8_t> buf;
    if (!readFile(path, buf)) { r.notes.push_back("Cannot read file."); return false; }

    DosHeader dos;
    if (!readAt(buf, 0, dos) || dos.e_magic != 0x5A4D) {
        r.notes.push_back("Not an MZ/PE file."); return false;
    }
    size_t peOff = static_cast<size_t>(dos.e_lfanew);
    uint32_t sig = 0;
    if (!readAt(buf, peOff, sig) || sig != 0x00004550) { // 'PE\0\0'
        r.notes.push_back("Missing PE signature."); return false;
    }
    FileHeader fh;
    size_t fhOff = peOff + 4;
    if (!readAt(buf, fhOff, fh)) return false;
    r.machine = fh.Machine;
    r.isDll   = (fh.Characteristics & IMAGE_FILE_DLL) != 0;

    size_t optOff = fhOff + sizeof(FileHeader);
    OptionalHeaderCommon oh;
    if (!readAt(buf, optOff, oh)) return false;
    r.is64 = (oh.Magic == 0x20b) || (fh.Machine == MACHINE_AMD64) ||
             (fh.Machine == MACHINE_ARM64);

    {
        std::ostringstream os;
        os << static_cast<int>(oh.MajorLinkerVersion) << "."
           << static_cast<int>(oh.MinorLinkerVersion)
           << " (from Optional Header)";
        r.linkerVersion = os.str();
    }

    // Data directories: NumberOfRvaAndSizes lives after fixed fields.
    // Offsets differ between PE32 (0x60) and PE32+ (0x70) from optOff.
    size_t ddBase = optOff + (oh.Magic == 0x20b ? 0x70 : 0x60);
    uint32_t numDirs = 0;
    readAt(buf, ddBase - 4, numDirs);
    DataDirectory debugDir{0,0};
    if (numDirs > 6) readAt(buf, ddBase + 6 * sizeof(DataDirectory), debugDir);

    // Section table.
    size_t secOff = optOff + fh.SizeOfOptionalHeader;
    std::vector<SectionHeader> secs;
    for (uint16_t i = 0; i < fh.NumberOfSections; ++i) {
        SectionHeader sh;
        if (!readAt(buf, secOff + i * sizeof(SectionHeader), sh)) break;
        secs.push_back(sh);
    }
    auto rvaToOff = [&](uint32_t rva) -> size_t {
        for (auto& s : secs)
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + std::max(s.VirtualSize, s.SizeOfRawData))
                return s.PointerToRawData + (rva - s.VirtualAddress);
        return SIZE_MAX;
    };

    // --- Rich header (MSVC / clang-cl / ICX via MS linker) ---------------
    decodeRichHeader(buf, peOff, r);
    if (!r.richHeader.empty()) r.msvcScore += 30; // MS-linker fingerprint

    // --- Debug directory: CodeView + POGO + VC feature -------------------
    if (debugDir.VirtualAddress && debugDir.Size) {
        size_t dOff = rvaToOff(debugDir.VirtualAddress);
        size_t count = debugDir.Size / sizeof(DebugDirectory);
        for (size_t i = 0; dOff != SIZE_MAX && i < count; ++i) {
            DebugDirectory dd;
            if (!readAt(buf, dOff + i * sizeof(DebugDirectory), dd)) break;
            if (dd.Type == IMAGE_DEBUG_TYPE_POGO) {
                r.msvcPogo = true;
                r.pgoDetail += (r.pgoDetail.empty() ? "" : "; ");
                r.pgoDetail += "IMAGE_DEBUG_TYPE_POGO present (MSVC PGO/BBT layout)";
            }
            if (dd.Type == IMAGE_DEBUG_TYPE_ILTCG) {
                r.msvcScore += 10;
                r.notes.push_back("Incremental LTCG debug record present (/LTCG:incremental).");
            }
            if (dd.Type == IMAGE_DEBUG_TYPE_CODEVIEW && dd.PointerToRawData) {
                uint32_t cvSig = 0;
                readAt(buf, dd.PointerToRawData, cvSig);
                if (cvSig == 0x53445352) { // 'RSDS'
                    // PDB path starts at +24 (after sig+GUID+age).
                    size_t p = dd.PointerToRawData + 24;
                    std::string pdb;
                    while (p < buf.size() && buf[p] && (buf[p] >= 0x20)) pdb.push_back((char)buf[p++]);
                    if (!pdb.empty()) r.notes.push_back("PDB reference: " + pdb +
                        "  (open with DIA SDK / llvm-pdbutil for exact compiler cmd-line)");
                }
            }
        }
    }

    // --- String-based fingerprinting -------------------------------------
    std::vector<std::string> strs;
    extractStrings(buf, 6, strs);
    fingerprintFromStrings(strs, r);

    // ICX embeds a clang fingerprint too; make sure ICX outranks bare clang.
    if (r.icxScore > 0 && r.clangScore > 0) r.icxScore += 30;

    // --- PGO / HWPGO -----------------------------------------------------
    detectPgo(buf, secs, strs, r);
    if (r.llvmInstrPgo) {
        r.pgoDetail += (r.pgoDetail.empty() ? "" : "; ");
        r.pgoDetail += "LLVM instrumentation PGO sections (__llvm_prf_*) present";
        if (r.clangScore == 0 && r.icxScore == 0) r.clangScore += 20;
    }

    // --- Decide toolchain ------------------------------------------------
    struct { Toolchain t; int s; } cand[] = {
        {Toolchain::IntelICX,     r.icxScore},
        {Toolchain::IntelClassic, r.iccScore},
        {Toolchain::ClangLLVM,    r.clangScore},
        {Toolchain::MSVC,         r.msvcScore},
    };
    int best = -1;
    for (auto& c : cand) if (c.s > best) { best = c.s; r.toolchain = c.t; }
    if (best <= 0) r.toolchain = Toolchain::Unknown;
    // Rich header alone (no compiler strings) => MSVC-family linker.
    if (r.toolchain == Toolchain::Unknown && !r.richHeader.empty())
        r.toolchain = Toolchain::MSVC;

    // --- ISA scan on executable sections ---------------------------------
    // APX (REX2) and AVX10.2 (EVEX) are x86/x86-64 concepts. Skip the scan on
    // non-x86 machines (e.g. ARM64) to avoid meaningless byte matches.
    bool isX86 = (r.machine == MACHINE_AMD64 || r.machine == MACHINE_I386);
    r.isaApplicable = isX86;
    if (!isX86) {
        r.decoderName = "n/a";
        r.isaDetail = "ISA scan skipped: target is not x86/x86-64 "
                      "(APX/AVX10.2 are not applicable).";
        r.notes.push_back(r.isaDetail);
    }

    // Resolve the effective decoder: honor the request only if compiled in.
    Decoder eff = reqDecoder;
    bool definitive = false;
    if (reqDecoder == Decoder::Zydis) {
#ifdef USE_ZYDIS
        definitive = true;
#else
        eff = Decoder::Heuristic;
        if (isX86) r.notes.push_back(
            "--decoder=zydis requested but this build has no Zydis support; "
            "using the heuristic. Rebuild with CMake -DWITH_ZYDIS=ON.");
#endif
    } else if (reqDecoder == Decoder::Xed) {
#ifdef USE_XED
        definitive = true;
#else
        eff = Decoder::Heuristic;
        if (isX86) r.notes.push_back(
            "--decoder=xed requested but this build has no XED support; "
            "using the heuristic. Rebuild with CMake -DWITH_XED=ON.");
#endif
    }

    IsaCounts acc;
    for (auto& s : secs) {
        if (!isX86) break;
        bool exec = (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                    (s.Characteristics & IMAGE_SCN_CNT_CODE);
        if (!exec || !s.SizeOfRawData) continue;
        size_t start = s.PointerToRawData;
        if (start >= buf.size()) continue;
        size_t len   = std::min<size_t>(s.SizeOfRawData, buf.size() - start);
        const uint8_t* code = buf.data() + start;
        switch (eff) {
#ifdef USE_ZYDIS
            case Decoder::Zydis: scanIsaZydis(code, len, r.is64, acc); break;
#endif
#ifdef USE_XED
            case Decoder::Xed:   scanIsaXed(code, len, r.is64, acc);   break;
#endif
            default:             scanIsaHeuristic(code, len, r.is64, acc); break;
        }
        r.sectionsScanned++;
        if (!scanAll) break; // primary code section only, unless --scan-all-sections
    }
    if (isX86) finalizeIsa(eff, definitive, acc, r);

    return true;
}

// ---------------------------------------------------------------------------
//  Reporting — text.
// ---------------------------------------------------------------------------
static const char* machineName(uint16_t m) {
    switch (m) {
        case MACHINE_AMD64: return "x86-64 (AMD64)";
        case MACHINE_I386:  return "x86 (i386)";
        case MACHINE_ARM64: return "ARM64";
        default:            return "other";
    }
}

static std::string yesNo(bool b) { return b ? "Yes" : "No"; }
static std::string triState(const std::optional<bool>& o) {
    if (!o) return "Undetermined";
    return *o ? "Yes" : "No";
}

static void report(const AnalysisResult& r, bool verbose) {
    std::cout << "============================================================\n";
    std::cout << " PE Toolchain Analyzer\n";
    std::cout << "============================================================\n";
    std::cout << "File            : " << r.file << "\n";
    std::cout << "Type            : " << (r.isDll ? "DLL" : "EXE")
              << ", " << (r.is64 ? "64-bit" : "32-bit")
              << ", " << machineName(r.machine) << "\n";
    std::cout << "------------------------------------------------------------\n";
    std::cout << "Toolchain       : " << toolName(r.toolchain) << "\n";
    std::cout << "  scores        : ICX=" << r.icxScore << " ICC=" << r.iccScore
              << " Clang=" << r.clangScore << " MSVC=" << r.msvcScore << "\n";
    std::cout << "Compiler version: "
              << (r.compilerVersion.empty() ? "not embedded (see PDB)" : r.compilerVersion) << "\n";
    std::cout << "Linker version  : " << r.linkerVersion << "\n";

    std::cout << "------------------------------------------------------------\n";
    std::cout << "Command-line options (best-effort; authoritative = PDB):\n";
    if (r.commandLineHints.empty())
        std::cout << "  (none embedded in image; use DIA SDK / llvm-pdbutil on the PDB,\n"
                     "   or dumpbin /DIRECTIVES on the .obj, for S_COMPILE3/S_ENVBLOCK)\n";
    else for (auto& c : r.commandLineHints) std::cout << "  * " << c << "\n";

    std::cout << "------------------------------------------------------------\n";
    std::cout << "PGO / HWPGO:\n";
    std::cout << "  MSVC PGO (POGO)          : " << yesNo(r.msvcPogo) << "\n";
    std::cout << "  LLVM instrumentation PGO : " << yesNo(r.llvmInstrPgo) << "\n";
    std::cout << "  HWPGO / sample PGO       : " << triState(r.hwpgo)
              << "  (heuristic)\n";
    if (!r.pgoDetail.empty())
        std::cout << "  detail: " << r.pgoDetail << "\n";

    std::cout << "------------------------------------------------------------\n";
    std::cout << "ISA features:\n";
    if (r.isaApplicable)
        std::cout << "  decoder                  : " << r.decoderName
                  << " (" << r.sectionsScanned << " section"
                  << (r.sectionsScanned == 1 ? "" : "s") << " scanned)\n";
    if (!r.isaApplicable) {
        std::cout << "  APX (REX2) instructions  : N/A (non-x86 target)\n";
        std::cout << "  AVX10.2 instructions     : N/A (non-x86 target)\n";
    } else if (r.definitive) {
        std::cout << "  APX instructions         : " << yesNo(r.apx)
                  << "  (definitive; APX-requiring=" << r.apxCount
                  << ", REX2-prefixed=" << r.rex2Count << ")\n";
        std::cout << "  AVX10.2 instructions     : " << yesNo(r.avx10_2)
                  << "  (definitive; AVX10.2-requiring=" << r.avx10Count << ")\n";
    } else {
        std::cout << "  APX (REX2) instructions  : "
                  << (r.rex2Count == 0 ? "None found (heuristic)"
                                       : "Undetermined (heuristic)")
                  << "  (candidate REX2 bytes=" << r.rex2Count
                  << "; use --decoder=zydis|xed to confirm)\n";
        std::cout << "  AVX10.2 instructions     : Undetermined (heuristic)"
                  << "  (EVEX hits=" << r.evexCount
                  << "; cannot separate AVX10.2 from AVX-512 without a decoder)\n";
    }
    if (verbose) std::cout << "  detail: " << r.isaDetail << "\n";

    if (verbose && !r.richHeader.empty()) {
        std::cout << "------------------------------------------------------------\n";
        std::cout << "Rich header (MS linker fingerprint):\n";
        for (auto& l : r.richHeader) std::cout << "  " << l << "\n";
    }
    if (verbose && !r.evidence.empty()) {
        std::cout << "------------------------------------------------------------\n";
        std::cout << "Evidence:\n";
        for (auto& e : r.evidence)
            std::cout << "  [+" << e.weight << "] " << e.what << ": "
                      << (e.detail.size() > 90 ? e.detail.substr(0,90)+"..." : e.detail)
                      << "\n";
    }
    if (!r.notes.empty()) {
        std::cout << "------------------------------------------------------------\n";
        std::cout << "Notes:\n";
        for (auto& n : r.notes) std::cout << "  - " << n << "\n";
    }
    std::cout << "============================================================\n";
}

// ---------------------------------------------------------------------------
//  Reporting — JSON.
//  Minimal, dependency-free serializer with correct string escaping so the
//  output is valid JSON regardless of paths / strings in the binary.
// ---------------------------------------------------------------------------
static std::string jsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

static std::string jStr(const std::string& s) { return "\"" + jsonEscape(s) + "\""; }

static std::string jArr(const std::vector<std::string>& v) {
    std::string o = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o += ",";
        o += jStr(v[i]);
    }
    o += "]";
    return o;
}

static void reportJson(const AnalysisResult& r) {
    std::ostringstream o;
    o << "{\n";
    o << "  \"file\": " << jStr(r.file) << ",\n";
    o << "  \"image\": {\n";
    o << "    \"kind\": " << jStr(r.isDll ? "dll" : "exe") << ",\n";
    o << "    \"bits\": " << (r.is64 ? 64 : 32) << ",\n";
    o << "    \"machine\": " << jStr(machineName(r.machine)) << ",\n";
    o << "    \"machineCode\": " << r.machine << "\n";
    o << "  },\n";

    o << "  \"toolchain\": {\n";
    o << "    \"detected\": " << jStr(toolName(r.toolchain)) << ",\n";
    o << "    \"scores\": { \"icx\": " << r.icxScore << ", \"icc\": " << r.iccScore
      << ", \"clang\": " << r.clangScore << ", \"msvc\": " << r.msvcScore << " },\n";
    o << "    \"compilerVersion\": "
      << (r.compilerVersion.empty() ? "null" : jStr(r.compilerVersion)) << ",\n";
    o << "    \"linkerVersion\": " << jStr(r.linkerVersion) << "\n";
    o << "  },\n";

    o << "  \"commandLineOptions\": {\n";
    o << "    \"authoritativeSource\": " << jStr("PDB (S_COMPILE3/S_ENVBLOCK)") << ",\n";
    o << "    \"hintsFromImage\": " << jArr(r.commandLineHints) << "\n";
    o << "  },\n";

    o << "  \"pgo\": {\n";
    o << "    \"msvcPogo\": " << (r.msvcPogo ? "true" : "false") << ",\n";
    o << "    \"llvmInstrumentationPgo\": " << (r.llvmInstrPgo ? "true" : "false") << ",\n";
    o << "    \"hwpgo\": " << (r.hwpgo ? (*r.hwpgo ? "true" : "false") : "null")
      << ",\n";
    o << "    \"hwpgoConfidence\": " << jStr("heuristic") << ",\n";
    o << "    \"detail\": " << (r.pgoDetail.empty() ? "null" : jStr(r.pgoDetail)) << "\n";
    o << "  },\n";

    o << "  \"isa\": {\n";
    o << "    \"applicable\": " << (r.isaApplicable ? "true" : "false") << ",\n";
    o << "    \"decoder\": " << jStr(r.decoderName) << ",\n";
    o << "    \"sectionsScanned\": " << r.sectionsScanned << ",\n";
    o << "    \"definitive\": " << (r.definitive ? "true" : "false") << ",\n";
    // APX: null when N/A or heuristic-inconclusive; bool when definitive or proven absent.
    if (!r.isaApplicable) {
        o << "    \"apx\": null,\n";
        o << "    \"avx10_2\": null,\n";
    } else if (r.definitive) {
        o << "    \"apx\": " << (r.apx ? "true" : "false") << ",\n";
        o << "    \"avx10_2\": " << (r.avx10_2 ? "true" : "false") << ",\n";
    } else {
        // Heuristic can only prove absence (0 candidates) — otherwise unknown.
        o << "    \"apx\": " << (r.rex2Count == 0 ? "false" : "null") << ",\n";
        o << "    \"avx10_2\": null,\n";
    }
    o << "    \"rex2Candidates\": " << r.rex2Count << ",\n";
    o << "    \"evexCount\": " << r.evexCount << ",\n";
    o << "    \"apxCount\": " << r.apxCount << ",\n";
    o << "    \"avx10SetCount\": " << r.avx10Count << ",\n";
    o << "    \"detail\": " << (r.isaDetail.empty() ? "null" : jStr(r.isaDetail)) << "\n";
    o << "  },\n";

    o << "  \"richHeader\": " << jArr(r.richHeader) << ",\n";
    o << "  \"notes\": " << jArr(r.notes) << "\n";
    o << "}\n";
    std::cout << o.str();
}

// ---------------------------------------------------------------------------
//  main
// ---------------------------------------------------------------------------
static void usage(const char* argv0) {
    std::cerr <<
        "Usage: " << argv0 << " <file.exe|file.dll> [options]\n"
        "  --json                 Emit machine-readable JSON instead of text.\n"
        "  --verbose              Include Rich header, evidence, and ISA detail.\n"
        "  --decoder=<name>       ISA decoder backend for APX/AVX10.2:\n"
        "                           heuristic | zydis | xed\n"
        "                         (falls back to heuristic if the chosen backend\n"
        "                          was not compiled in).\n"
        "  --scan-all-sections    Scan every executable section (default: only\n"
        "                         the first/primary code section).\n"
        "  --zydis / --no-zydis   Aliases for --decoder=zydis / =heuristic.\n"
        "  --xed                  Alias for --decoder=xed.\n"
        "  -h, --help             Show this help.\n"
        "  [build backends:"
#ifdef USE_ZYDIS
        " zydis"
#endif
#ifdef USE_XED
        " xed"
#endif
        " heuristic]\n";
}

// Parse "--decoder=xed" or "--decoder xed" into a Decoder; returns false on bad value.
static bool parseDecoder(const std::string& val, Decoder& out) {
    if (val == "heuristic" || val == "none") { out = Decoder::Heuristic; return true; }
    if (val == "zydis")                       { out = Decoder::Zydis;     return true; }
    if (val == "xed")                         { out = Decoder::Xed;       return true; }
    return false;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 2; }

    std::string path;
    bool verbose = false;
    bool json = false;
    bool scanAll = false;
    // Default decoder: prefer a compiled-in exact backend, else heuristic.
#if defined(USE_ZYDIS)
    Decoder decoder = Decoder::Zydis;
#elif defined(USE_XED)
    Decoder decoder = Decoder::Xed;
#else
    Decoder decoder = Decoder::Heuristic;
#endif

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--verbose")               verbose = true;
        else if (a == "--json")             json = true;
        else if (a == "--scan-all-sections") scanAll = true;
        else if (a == "--zydis")            decoder = Decoder::Zydis;
        else if (a == "--no-zydis")         decoder = Decoder::Heuristic;
        else if (a == "--xed")              decoder = Decoder::Xed;
        else if (a.rfind("--decoder=", 0) == 0) {
            if (!parseDecoder(a.substr(10), decoder)) {
                std::cerr << "Invalid --decoder value: " << a.substr(10)
                          << " (expected heuristic|zydis|xed)\n";
                return 2;
            }
        }
        else if (a == "--decoder") {
            if (i + 1 >= argc || !parseDecoder(argv[++i], decoder)) {
                std::cerr << "Invalid or missing --decoder value "
                             "(expected heuristic|zydis|xed)\n";
                return 2;
            }
        }
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else if (!a.empty() && a[0] == '-') {
            std::cerr << "Unknown option: " << a << "\n";
            usage(argv[0]);
            return 2;
        } else {
            if (path.empty()) path = a;
        }
    }
    if (path.empty()) { usage(argv[0]); return 2; }

    AnalysisResult r;
    bool ok = analyze(path, decoder, scanAll, r);

    if (json) reportJson(r);
    else      report(r, verbose);

    if (!ok) {
        if (!json) std::cerr << "Analysis failed (see notes).\n";
        return 1;
    }
    return 0;
}
