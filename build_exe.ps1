param(
  [string]$OneFile = 'false'
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $Root '.venv'
$Py = Join-Path $VenvDir 'Scripts\python.exe'

if (-not (Test-Path $Py)) {
  Write-Host "[*] Creating virtual environment: $VenvDir"
  py -3 -m venv $VenvDir
}

Write-Host "[*] Installing build dependencies"
& $Py -m pip install --upgrade pip
& $Py -m pip install -r (Join-Path $Root 'requirements.txt')
& $Py -m pip install pyinstaller

$Dist = Join-Path $Root 'dist'
$Build = Join-Path $Root 'build'

$iconPath = Join-Path $Root 'assets\app.ico'
$iconArgs = @()
if (Test-Path $iconPath) {
  $iconArgs = @('--icon', $iconPath)
}

$addData = @(
  "assets;assets",
  "payloads;payloads",
  "fingerprint_cve_mapping.json;fingerprint_cve_mapping.json",
  "ai_config.json;ai_config.json"
)

$oneFileFlag = $false
if ($OneFile -eq 'true' -or $OneFile -eq '1') { $oneFileFlag = $true }

$args = @(
  '--noconfirm',
  '--clean',
  '--name', 'CVE-Payload-GUI',
  '--windowed'
)

if ($oneFileFlag) {
  $args += '--onefile'
}

foreach ($d in $addData) {
  $args += @('--add-data', $d)
}

$args += $iconArgs
$args += (Join-Path $Root 'poc_gui.py')

Write-Host "[*] Building EXE via PyInstaller"
& $Py -m PyInstaller @args

Write-Host "[*] Build done. Output: $Dist"
