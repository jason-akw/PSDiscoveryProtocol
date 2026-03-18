[CmdletBinding()]
param(
    [string]$InputFile,
    [string]$OutputFile,
    [string]$ManifestPath
)

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $InputFile) {
    $InputFile = Join-Path $scriptRoot 'PSDiscoveryProtocol.SingleFile.ps1'
}
if (-not $OutputFile) {
    $OutputFile = Join-Path $scriptRoot 'PSDiscoveryProtocol-conhost.exe'
}
if (-not $ManifestPath) {
    $ManifestPath = Join-Path $scriptRoot 'PSDiscoveryProtocol\PSDiscoveryProtocol.psd1'
}

if (-not (Test-Path -LiteralPath $InputFile)) {
    throw "Input script not found: $InputFile"
}
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest not found: $ManifestPath"
}

$manifest = Import-PowerShellDataFile -Path $ManifestPath
$version = [string]$manifest.ModuleVersion

$ps2exeManifest = Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules\ps2exe\1.0.17\ps2exe.psd1'
if (-not (Test-Path -LiteralPath $ps2exeManifest)) {
    throw "ps2exe not found at $ps2exeManifest. Install ps2exe first."
}

Import-Module $ps2exeManifest -Force

Invoke-PS2EXE `
    -InputFile $InputFile `
    -OutputFile $OutputFile `
    -requireAdmin `
    -x64 `
    -conHost `
    -UNICODEEncoding `
    -title 'PSDiscoveryProtocol' `
    -product 'PSDiscoveryProtocol' `
    -company 'jason-akw' `
    -description 'Capture and parse CDP and LLDP packets' `
    -version $version

Write-Host "Generated: $OutputFile"
Write-Host "Version:   $version"
