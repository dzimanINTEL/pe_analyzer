cmake_minimum_required(VERSION 3.16)
project(pe_toolchain_analyzer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ===========================================================================
#  ISA decoder backends (both optional, both fetch-from-source via FetchContent)
#
#  -DWITH_ZYDIS=ON   Enable the Zydis backend  (github.com/zyantific/zydis)
#  -DWITH_XED=ON     Enable the Intel XED backend (github.com/intelxed/xed)
#
#  You may enable BOTH; the decoder is then chosen at RUNTIME via
#  --decoder=zydis|xed|heuristic. If neither is enabled, only the byte-level
#  heuristic is available.
#
#  Source selection knobs:
#    -DZYDIS_USE_SYSTEM=ON   use an installed Zydis (find_package) instead of fetch
#    -DZYDIS_TAG=<ref>       Zydis git ref (default master)
#    -DXED_TAG=<ref>         XED   git ref (default main)
# ===========================================================================
option(WITH_ZYDIS       "Enable Zydis backend (exact APX/AVX10.2 decode)" OFF)
option(WITH_XED         "Enable Intel XED backend (exact APX/AVX10.2 decode)" OFF)

# --- Convenience: build from a LOCAL source tree instead of fetching --------
#  Point these at already-extracted clones (e.g. from zydis.7z / xed.7z). They
#  simply set CMake's built-in FETCHCONTENT_SOURCE_DIR_<name> overrides, so the
#  FetchContent_Declare() URLs below remain the default for everyone else (CI,
#  clean checkouts). No fetch/network happens when a local dir is supplied.
set(ZYDIS_LOCAL_DIR "" CACHE PATH "Local Zydis source dir (overrides fetch)")
set(XED_LOCAL_DIR   "" CACHE PATH "Local Intel XED source dir (overrides fetch)")
set(MBUILD_LOCAL_DIR "" CACHE PATH "Local mbuild source dir (XED build driver)")
if(ZYDIS_LOCAL_DIR)
    set(FETCHCONTENT_SOURCE_DIR_ZYDIS "${ZYDIS_LOCAL_DIR}" CACHE INTERNAL "" FORCE)
    message(STATUS "petool: using LOCAL Zydis source: ${ZYDIS_LOCAL_DIR}")
endif()
if(XED_LOCAL_DIR)
    set(FETCHCONTENT_SOURCE_DIR_XED "${XED_LOCAL_DIR}" CACHE INTERNAL "" FORCE)
    message(STATUS "petool: using LOCAL XED source: ${XED_LOCAL_DIR}")
endif()
if(MBUILD_LOCAL_DIR)
    set(FETCHCONTENT_SOURCE_DIR_MBUILD "${MBUILD_LOCAL_DIR}" CACHE INTERNAL "" FORCE)
endif()
option(ZYDIS_USE_SYSTEM "Use an installed Zydis instead of FetchContent" OFF)
set(ZYDIS_TAG "master" CACHE STRING "Zydis git tag/branch/commit to fetch")
set(XED_TAG   "main"   CACHE STRING "Intel XED git tag/branch/commit to fetch")

add_executable(petool pe_toolchain_analyzer.cpp)

include(FetchContent)

# ---------------------------------------------------------------------------
#  Zydis  — CMake-native, FetchContent works out of the box.
# ---------------------------------------------------------------------------
if(WITH_ZYDIS)
    if(ZYDIS_USE_SYSTEM)
        find_package(Zydis CONFIG REQUIRED)
        target_link_libraries(petool PRIVATE Zydis::Zydis)
    else()
        set(ZYDIS_BUILD_TOOLS      OFF CACHE BOOL "" FORCE)
        set(ZYDIS_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)
        set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
        set(ZYAN_BUILD_TESTS       OFF CACHE BOOL "" FORCE)
        FetchContent_Declare(zydis
            GIT_REPOSITORY https://github.com/zyantific/zydis.git
            GIT_TAG        ${ZYDIS_TAG}
            GIT_SHALLOW    TRUE
            GIT_PROGRESS   TRUE)
        FetchContent_MakeAvailable(zydis)   # pulls Zycore submodule automatically
        target_link_libraries(petool PRIVATE Zydis)
    endif()
    target_compile_definitions(petool PRIVATE USE_ZYDIS)
    message(STATUS "petool: Zydis backend ENABLED (ref: ${ZYDIS_TAG})")
endif()

# ---------------------------------------------------------------------------
#  Intel XED — uses its own Python build system (mfile.py) rather than CMake,
#  so we fetch the sources and drive that builder, then import the result as an
#  IMPORTED library. Requires Python 3 on PATH.
# ---------------------------------------------------------------------------
if(WITH_XED)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    # XED needs its 'mbuild' sibling helper checked out next to it.
    FetchContent_Declare(xed
        GIT_REPOSITORY https://github.com/intelxed/xed.git
        GIT_TAG        ${XED_TAG}
        GIT_SHALLOW    TRUE
        GIT_PROGRESS   TRUE)
    FetchContent_Declare(mbuild
        GIT_REPOSITORY https://github.com/intelxed/mbuild.git
        GIT_TAG        main
        GIT_SHALLOW    TRUE)
    FetchContent_MakeAvailable(xed mbuild)

    set(_xed_kit "${CMAKE_BINARY_DIR}/xed-install")
    # Build a static libxed with XED's own builder (mbuild must be a sibling dir).
    add_custom_command(
        OUTPUT  "${_xed_kit}/lib/libxed.a"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${mbuild_SOURCE_DIR}" "${xed_SOURCE_DIR}/../mbuild"
        COMMAND ${Python3_EXECUTABLE} "${xed_SOURCE_DIR}/mfile.py"
                --static --install-dir=${_xed_kit} install
        WORKING_DIRECTORY "${xed_SOURCE_DIR}"
        COMMENT "Building Intel XED (static) via mfile.py"
        VERBATIM)
    add_custom_target(build_xed DEPENDS "${_xed_kit}/lib/libxed.a")

    add_library(xed_imported STATIC IMPORTED GLOBAL)
    set_target_properties(xed_imported PROPERTIES
        IMPORTED_LOCATION "${_xed_kit}/lib/libxed.a"
        INTERFACE_INCLUDE_DIRECTORIES "${_xed_kit}/include")
    add_dependencies(xed_imported build_xed)
    # Ensure the include dir exists at configure time for the interface.
    file(MAKE_DIRECTORY "${_xed_kit}/include")

    add_dependencies(petool build_xed)
    target_include_directories(petool PRIVATE "${_xed_kit}/include")
    target_link_libraries(petool PRIVATE xed_imported)
    target_compile_definitions(petool PRIVATE USE_XED)
    message(STATUS "petool: Intel XED backend ENABLED (ref: ${XED_TAG})")
endif()

if(NOT WITH_ZYDIS AND NOT WITH_XED)
    message(STATUS "petool: no decoder backend enabled (heuristic only). "
                   "Configure with -DWITH_ZYDIS=ON and/or -DWITH_XED=ON.")
endif()

if(MSVC)
    target_compile_options(petool PRIVATE /EHsc /W4)
else()
    target_compile_options(petool PRIVATE -O2 -Wall -Wextra)
endif()
