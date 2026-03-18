[CmdletBinding()]
param(
    [string]$ModulePath,
    [string]$OutputPath
)

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ModulePath) {
    $ModulePath = Join-Path $scriptRoot 'PSDiscoveryProtocol\PSDiscoveryProtocol.psm1'
}
if (-not $OutputPath) {
    $OutputPath = Join-Path $scriptRoot 'PSDiscoveryProtocol.SingleFile.ps1'
}

if (-not (Test-Path -LiteralPath $ModulePath)) {
    throw "Module not found: $ModulePath"
}

$moduleSource = Get-Content -Path $ModulePath -Raw

$singleFile = @"
[CmdletBinding()]
param(
    [ValidateSet('Invoke-DiscoveryProtocolCapture', 'Get-DiscoveryProtocolData', 'ConvertFrom-CDPPacket', 'ConvertFrom-LLDPPacket', 'Export-Pcap')]
    [string]`$Command,
    [hashtable]`$Arguments = @{},
    [switch]`$ListCommands
)

`$script:PSDiscoveryProtocolSource = @'
$moduleSource
'@

function Initialize-PSDiscoveryProtocolSingleFile {
    if (Get-Module -Name PSDiscoveryProtocol) {
        return
    }

    `$module = New-Module -Name PSDiscoveryProtocol -ScriptBlock ([ScriptBlock]::Create(`$script:PSDiscoveryProtocolSource))
    Import-Module -ModuleInfo `$module -Force | Out-Null
}

Initialize-PSDiscoveryProtocolSingleFile

if (`$ListCommands) {
    Get-Command -Module PSDiscoveryProtocol | Select-Object Name, CommandType
    return
}

if (`$Command) {
    & `$Command @Arguments
    return
}

`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
`$principal = New-Object Security.Principal.WindowsPrincipal `$identity
if (-not `$principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host 'Administrator privileges are required for packet capture.' -ForegroundColor Red
    Write-Host 'Please run this script from an elevated terminal or use Run-PSDiscoveryProtocol.cmd.' -ForegroundColor Yellow
    return
}

do {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Blue
    Write-Host "    Network Discovery Tool (CDP/LLDP)   " -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Blue
    Write-Host "1. Capture CDP (Cisco)"
    Write-Host "2. Capture LLDP (Standard)"
    Write-Host "3. Exit"
    `$choice = Read-Host "Select [1-3]"

    if (`$choice -eq '1' -or `$choice -eq '2') {
        `$type = if (`$choice -eq '1') { 'CDP' } else { 'LLDP' }
        `$duration = if (`$type -eq 'LLDP') { 35 } else { 65 }

        Write-Host "`n[!] Capturing `$type... Please wait for a network advertisement." -ForegroundColor Yellow
        `$captureWarnings = @()
        `$packet = Invoke-DiscoveryProtocolCapture -Type `$type -Duration `$duration -Force -WarningVariable +captureWarnings
        `$data = if (`$packet) { `$packet | Get-DiscoveryProtocolData } else { `$null }

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Blue
        Write-Host "         `$type DISCOVERY RESULTS         " -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Blue

        if (`$data) {
            `$resultIndex = 0
            foreach (`$item in @(`$data)) {
                `$resultIndex++
                Write-Host ""
                Write-Host ("----- Result #{0} -----" -f `$resultIndex) -ForegroundColor Cyan

            if (`$type -eq 'CDP') {
                `$item | Select-Object Device, SystemName, SoftwareVersion, Model, IPAddress, Management, VLAN, Port, Capabilities, Duplex, TrustBitmap, UntrustedPortCoS, Connection, Interface, Computer, Type | Format-List
            }
            else {
                `$item | Select-Object Device, SystemName, SystemDescription, Model, IPAddress, ManagementAddresses, VLAN, VLANNamedEntries, Port, PortDescription, ChassisId, ChassisIdSubtype, ChassisIdSubtypeName, PortIdSubtype, PortIdSubtypeName, TimeToLive, SystemCapabilities, EnabledCapabilities, LinkAggregation, MacPhyConfigurationStatus, ManagementInterfaceNumberingSubtype, ManagementInterfaceNumber, ManagementObjectIdentifier, Connection, Interface, Computer, Type | Format-List
            }
            }
        }
        else {
            if (`$captureWarnings.Count -gt 0) {
                Write-Host "No data parsed. Capture details:" -ForegroundColor Yellow
                `$captureWarnings | ForEach-Object { Write-Host " - `$_" -ForegroundColor DarkYellow }
            }
            else {
                Write-Host "TIMEOUT: No `$type packets received in `$duration seconds." -ForegroundColor Red
                Write-Host "Tips: Check physical connection, switch LLDP/CDP settings, or try the other protocol." -ForegroundColor Gray
            }
        }

        Write-Host "`n----------------------------------------"
        Pause
    }
} while (`$choice -ne '3')
"@

[System.IO.File]::WriteAllText(
    $OutputPath,
    $singleFile,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Generated: $OutputPath"
