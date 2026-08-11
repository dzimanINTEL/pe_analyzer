<#
  build-local.ps1 — build petool against LOCAL Zydis / Intel XED sources
                    (e.g. extracted from zydis.7z / xed.7z). No network needed.

  Usage:
    ./build-local.ps1 -Zydis C:\src\zydis `
                     [-Xed C:\src\xed -Mbuild C:\src\mbuild]

  Notes:
    * Run from a "x64 Native Tools Command Prompt for VS" (so cl.exe is on PATH).
    * Zydis must include its Zycore submodule (extract the full clone).
    * XED needs its sibling 'mbuild' checkout and Python 3 on PATH.
    * The committed CMake still fetches from GitHub by default; these switches
      only set CMake's FETCHCONTENT_SOURCE_DIR_* overrides for a local build.
#>
param(
  [string]$Zydis = "",
  [string]$Xed = "",
  [string]$Mbuild = "",
  [string]$BuildDir = "build-local"
)
$ErrorActionPreference = "Stop"

$flags = @()
if ($Zydis) { $flags += "-DWITH_ZYDIS=ON"; $flags += "-DZYDIS_LOCAL_DIR=$((Resolve-Path $Zydis).Path)" }
if ($Xed)   { $flags += "-DWITH_XED=ON";   $flags += "-DXED_LOCAL_DIR=$((Resolve-Path $Xed).Path)" }
if ($Mbuild){ $flags += "-DMBUILD_LOCAL_DIR=$((Resolve-Path $Mbuild).Path)" }

if ($flags.Count -eq 0) {
  Write-Error "Nothing to do: pass -Zydis and/or -Xed (see the header comment)."
}

Write-Host ">> cmake -S . -B $BuildDir $($flags -join ' ')"
cmake -S . -B $BuildDir @flags -DCMAKE_BUILD_TYPE=Release
cmake --build $BuildDir --config Release --parallel
$exe = Join-Path $BuildDir "Release\petool.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path $BuildDir "petool.exe" }
Write-Host ">> Built: $exe"
& $exe --help
