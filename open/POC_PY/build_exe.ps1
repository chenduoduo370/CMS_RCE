<#
Build script for the project using PyInstaller.
Usage (PowerShell, from project folder):
  # activate your virtualenv first, e.g.
  .\.venv\Scripts\Activate.ps1
  .\build_exe.ps1

Options:
  -OneFile:$false   => produce folder build instead of single exe
  -Windowed:$false  => show console window (useful for debugging)
#>
param(
    [switch]$OneFile = $true,
    [switch]$Windowed = $true
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

Write-Host "Building from: $scriptDir"

# Ensure PyInstaller is available in the active environment
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Error "pyinstaller not found in PATH. Activate your virtualenv and install pyinstaller (`pip install pyinstaller`)."
    exit 1
}

$argsList = @()
if ($OneFile) { $argsList += "--onefile" }
if ($Windowed) { $argsList += "--windowed" }
$argsList += "--name"; $argsList += "cve_poc"

# Include payloads folder and the mapping json
# Windows uses semicolon separator for --add-data "SRC;DEST"
$argsList += "--add-data"; $argsList += "payloads;payloads"
$argsList += "--add-data"; $argsList += "fingerprint_cve_mapping.json;."

# Optionally include icon if present
if (Test-Path "icon.ico") {
    $argsList += "--icon"; $argsList += "icon.ico"
}

# Entry script
$argsList += "poc_gui.py"

Write-Host "Running: pyinstaller $($argsList -join ' ')"

pyinstaller @argsList

if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Build finished. Output in `dist\` (single exe when --onefile)." -ForegroundColor Green


