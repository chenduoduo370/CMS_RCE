param(
  [switch]$NoInstall
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $Root '.venv'
$Py = Join-Path $VenvDir 'Scripts\python.exe'

if (-not (Test-Path $Py)) {
  Write-Host "[*] Creating virtual environment: $VenvDir"
  py -3 -m venv $VenvDir
}

if (-not $NoInstall) {
  Write-Host "[*] Upgrading pip"
  & $Py -m pip install --upgrade pip

  Write-Host "[*] Installing requirements"
  & $Py -m pip install -r (Join-Path $Root 'requirements.txt')
}

Write-Host "[*] Launching GUI"
& $Py (Join-Path $Root 'poc_gui.py')
