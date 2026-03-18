[CmdletBinding()]
param(
    [string]$ModulePath,
    [string]$OutputPath,
    [string]$ManifestPath
)

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ModulePath) {
    $ModulePath = Join-Path $scriptRoot 'PSDiscoveryProtocol\PSDiscoveryProtocol.psm1'
}
if (-not $OutputPath) {
    $OutputPath = Join-Path $scriptRoot 'PSDiscoveryProtocol.SingleFile.ps1'
}
if (-not $ManifestPath) {
    $ManifestPath = Join-Path $scriptRoot 'PSDiscoveryProtocol\PSDiscoveryProtocol.psd1'
}

if (-not (Test-Path -LiteralPath $ModulePath)) {
    throw "Module not found: $ModulePath"
}
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest not found: $ManifestPath"
}

$moduleSource = Get-Content -Path $ModulePath -Raw
$manifest = Import-PowerShellDataFile -Path $ManifestPath
$moduleVersion = [string]$manifest.ModuleVersion

$singleFile = @"
[CmdletBinding()]
param(
    [ValidateSet('Invoke-DiscoveryProtocolCapture', 'Get-DiscoveryProtocolData', 'ConvertFrom-CDPPacket', 'ConvertFrom-LLDPPacket', 'ConvertFrom-MNDPPacket', 'Export-Pcap', 'Get-PSDiscoveryProtocolVersion')]
    [string]`$Command,
    [hashtable]`$Arguments = @{},
    [switch]`$ListCommands,
    [switch]`$ShowVersion
)

`$script:PSDiscoveryProtocolVersion = '$moduleVersion'

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

# Keep console behavior predictable in packaged EXE mode.
`$ProgressPreference = 'Continue'
try {
    [Console]::InputEncoding = [System.Text.UTF8Encoding]::new(`$false)
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(`$false)
    `$OutputEncoding = [Console]::OutputEncoding
}
catch {
}

if (`$ListCommands) {
    Get-Command -Module PSDiscoveryProtocol | Select-Object Name, CommandType
    return
}

if (`$ShowVersion) {
    [PSCustomObject]@{
        Name = 'PSDiscoveryProtocol'
        Version = `$script:PSDiscoveryProtocolVersion
    }
    return
}

if (`$Command) {
    if (`$Command -eq 'Invoke-DiscoveryProtocolCapture' -and -not `$Arguments.ContainsKey('Force')) {
        `$Arguments['Force'] = `$true
    }
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

function Convert-DisplayValue {
    param([object]`$Value)
    if (`$null -eq `$Value) { return '' }
    if (`$Value -is [string]) { return `$Value }
    if (`$Value -is [System.Collections.IEnumerable] -and -not (`$Value -is [string])) {
        `$parts = @()
        foreach (`$entry in `$Value) {
            if (`$entry -is [string]) { `$parts += `$entry }
            elseif (`$entry -is [ValueType]) { `$parts += [string]`$entry }
            elseif (`$entry.PSObject -and `$entry.PSObject.Properties.Count -gt 0) {
                `$pairs = @()
                foreach (`$p in `$entry.PSObject.Properties) {
                    if (`$p.Name -notlike 'PS*') {
                        `$pairs += ("{0}={1}" -f `$p.Name, (Convert-DisplayValue -Value `$p.Value))
                    }
                }
                `$parts += (`$pairs -join '; ')
            }
            else { `$parts += [string]`$entry }
        }
        return (`$parts -join ' | ')
    }
    if (`$Value -is [ValueType]) { return [string]`$Value }
    if (`$Value.PSObject -and `$Value.PSObject.Properties.Count -gt 0) {
        `$pairs = @()
        foreach (`$p in `$Value.PSObject.Properties) {
            if (`$p.Name -notlike 'PS*') {
                `$pairs += ("{0}={1}" -f `$p.Name, (Convert-DisplayValue -Value `$p.Value))
            }
        }
        return (`$pairs -join '; ')
    }
    return [string]`$Value
}

function Show-DiscoveryResult {
    param([psobject]`$Item, [string[]]`$Fields)
    foreach (`$name in `$Fields) {
        `$raw = `$Item.PSObject.Properties[`$name].Value
        if (`$name -eq 'LinkAggregation' -and `$raw) {
            `$state = @()
            if (`$raw.Capable) { `$state += 'Capable' } else { `$state += 'Not Capable' }
            if (`$raw.Enabled) { `$state += 'Enabled' } else { `$state += 'Disabled' }
            `$text = ("{0}; PortId={1}; Status=0x{2}" -f (`$state -join ', '), `$raw.PortId, ([int]`$raw.Status).ToString('X2'))
        }
        else {
            `$text = Convert-DisplayValue -Value `$raw
        }
        Write-Host (`$name + ': ' + `$text)
    }
}

do {
    Clear-Host
    `$HeaderWidth = 40
    `$TitleLine = 'Network Discovery Tool'
    `$VersionLine = "Version: `$script:PSDiscoveryProtocolVersion"
    Write-Host ('=' * `$HeaderWidth) -ForegroundColor Blue
    Write-Host (`$TitleLine.PadLeft([Math]::Floor((`$HeaderWidth + `$TitleLine.Length) / 2)).PadRight(`$HeaderWidth)) -ForegroundColor White
    Write-Host (`$VersionLine.PadLeft([Math]::Floor((`$HeaderWidth + `$VersionLine.Length) / 2)).PadRight(`$HeaderWidth)) -ForegroundColor DarkCyan
    Write-Host ('=' * `$HeaderWidth) -ForegroundColor Blue
    Write-Host "1. Capture CDP (Cisco)"
    Write-Host "2. Capture LLDP (Standard)"
    Write-Host "3. Capture MNDP (MikroTik)"
    Write-Host "4. Exit"
    `$choice = Read-Host "Select [1-4]"

    if (`$choice -in '1', '2', '3') {
        `$type = switch (`$choice) {
            '1' { 'CDP' }
            '2' { 'LLDP' }
            '3' { 'MNDP' }
        }
        `$duration = if (`$type -eq 'CDP') { 65 } elseif (`$type -eq 'MNDP') { 65 } else { 35 }

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
                `$fields = 'Device','SystemName','SoftwareVersion','Model','IPAddress','Management','VLAN','Port','Capabilities','Duplex','TrustBitmap','UntrustedPortCoS','Connection','Interface','Computer','Type'
                Show-DiscoveryResult -Item `$item -Fields `$fields
            }
            elseif (`$type -eq 'LLDP') {
                `$fields = 'Device','SystemName','SystemDescription','Model','IPAddress','ManagementAddresses','VLAN','VLANNamedEntries','Port','PortDescription','ChassisId','ChassisIdSubtype','ChassisIdSubtypeName','PortIdSubtype','PortIdSubtypeName','TimeToLive','SystemCapabilities','EnabledCapabilities','LinkAggregation','MacPhyConfigurationStatus','ManagementInterfaceNumberingSubtype','ManagementInterfaceNumber','ManagementObjectIdentifier','Connection','Interface','Computer','Type'
                Show-DiscoveryResult -Item `$item -Fields `$fields
            }
            else {
                `$fields = 'Device','SoftwareVersion','SoftwareID','Platform','Board','Model','Port','InterfaceName','IPAddress','IPv6Address','MACAddress','Uptime','UptimeSeconds','Unpack','Connection','Interface','Computer','Type'
                Show-DiscoveryResult -Item `$item -Fields `$fields
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
} while (`$choice -ne '4')
"@

[System.IO.File]::WriteAllText(
    $OutputPath,
    $singleFile,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Generated: $OutputPath"
