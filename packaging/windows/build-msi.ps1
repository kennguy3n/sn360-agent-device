# Build the wda-agent.msi installer from a pre-built release binary.
#
# Requires WiX Toolset 3.x (candle.exe and light.exe on PATH). Run on
# a Windows host where the release binary has already been compiled
# via `cargo build --release -p wda-agent`.
#
# Usage:
#   pwsh packaging\windows\build-msi.ps1
#
# Output: dist\wda-agent-<version>.msi
[CmdletBinding()]
param(
    [string]$Binary = "target\x86_64-pc-windows-msvc\release\wda-agent.exe",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$cargoToml = Get-Content (Join-Path $root "Cargo.toml") -Raw
$version = ([regex]::Match($cargoToml, '^version\s*=\s*"([^"]+)"', 'Multiline')).Groups[1].Value

if (-not (Test-Path $Binary)) {
    $Binary = Join-Path $root $Binary
}
if (-not (Test-Path $Binary)) {
    throw "binary not found: $Binary — build it first with cargo build --release"
}

$outPath = Join-Path $root $OutDir
New-Item -ItemType Directory -Force -Path $outPath | Out-Null

$wxs     = Join-Path $PSScriptRoot "wda-agent.wxs"
$wixobj  = Join-Path $outPath     "wda-agent.wixobj"
$msi     = Join-Path $outPath     "wda-agent-$version.msi"

& candle.exe -nologo `
    -dVersion="$version" `
    -dBinary="$Binary" `
    -ext WixUtilExtension `
    -o "$wixobj" `
    "$wxs"
if ($LASTEXITCODE -ne 0) { throw "candle failed" }

& light.exe -nologo `
    -ext WixUtilExtension `
    -o "$msi" `
    "$wixobj"
if ($LASTEXITCODE -ne 0) { throw "light failed" }

Write-Host "built $msi"
