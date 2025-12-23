<#
Package distribution zip containing the built exe and auxiliary files.
Usage (PowerShell, from project folder):
  .\package_dist.ps1
#>
param()

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

$distExe = Join-Path $scriptDir 'dist\cve_poc.exe'
if (-not (Test-Path $distExe)) {
    Write-Error "Built exe not found: $distExe. Please run build_exe.ps1 first."
    exit 1
}

$outZip = Join-Path $scriptDir 'cve_poc_release.zip'
if (Test-Path $outZip) { Remove-Item $outZip -Force }

$filesToInclude = @($distExe, 'README.md', 'LICENSE')
if (Test-Path 'icon.ico') { $filesToInclude += 'icon.ico' }

Write-Host "Creating $outZip with:" -ForegroundColor Green
$filesToInclude | ForEach-Object { Write-Host "  $_" }

Compress-Archive -Path $filesToInclude -DestinationPath $outZip -Force

Write-Host "Created $outZip" -ForegroundColor Green


