@echo off
setlocal

set "TEMP_PS1=%TEMP%\network_discovery_tmp.ps1"
set "MODULE_MANIFEST=%~dp0PSDiscoveryProtocol\PSDiscoveryProtocol.psd1"

:: 1. Check for Admin
NET SESSION >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: 2. Create the PowerShell script file
echo $ErrorActionPreference = 'Continue' > "%TEMP_PS1%"
echo $ModuleManifest = '%MODULE_MANIFEST:\=\\%' >> "%TEMP_PS1%"
echo $SessionLog = Join-Path $env:TEMP ("PSDiscoveryProtocol_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)) >> "%TEMP_PS1%"
echo Start-Transcript -Path $SessionLog -Append ^| Out-Null >> "%TEMP_PS1%"
echo Write-Host "Checking Environment..." -ForegroundColor Cyan >> "%TEMP_PS1%"
echo if (Test-Path -LiteralPath $ModuleManifest) { >> "%TEMP_PS1%"
echo     Import-Module -Name $ModuleManifest -Force >> "%TEMP_PS1%"
echo } else { >> "%TEMP_PS1%"
echo     Write-Host "ERROR: Local module manifest not found:" -ForegroundColor Red >> "%TEMP_PS1%"
echo     Write-Host "  $ModuleManifest" -ForegroundColor Red >> "%TEMP_PS1%"
echo     Write-Host "Please run this CMD from the project root folder." -ForegroundColor Yellow >> "%TEMP_PS1%"
echo     Pause >> "%TEMP_PS1%"
echo     exit 1 >> "%TEMP_PS1%"
echo } >> "%TEMP_PS1%"
echo do { >> "%TEMP_PS1%"
echo     Clear-Host >> "%TEMP_PS1%"
echo     Write-Host "========================================" -ForegroundColor Blue >> "%TEMP_PS1%"
echo     Write-Host "    Network Discovery Tool (CDP/LLDP)   " -ForegroundColor White >> "%TEMP_PS1%"
echo     Write-Host "========================================" -ForegroundColor Blue >> "%TEMP_PS1%"
echo     Write-Host "1. Capture CDP (Cisco)" >> "%TEMP_PS1%"
echo     Write-Host "2. Capture LLDP (Standard)" >> "%TEMP_PS1%"
echo     Write-Host "3. Exit" >> "%TEMP_PS1%"
echo     $choice = Read-Host "Select [1-3]" >> "%TEMP_PS1%"
echo     if ($choice -eq '1' -or $choice -eq '2') { >> "%TEMP_PS1%"
echo         $type = if($choice -eq '1') {'CDP'} else {'LLDP'} >> "%TEMP_PS1%"
echo         $wiredAdapters = Get-NetAdapter ^| Where-Object { $_.Status -eq 'Up' -and $_.InterfaceType -eq 6 } >> "%TEMP_PS1%"
echo         if (-not $wiredAdapters) { >> "%TEMP_PS1%"
echo             Write-Host "`nERROR: No active wired adapter found (InterfaceType 6)." -ForegroundColor Red >> "%TEMP_PS1%"
echo             Write-Host "LLDP/CDP capture in this tool requires a connected Ethernet adapter." -ForegroundColor Yellow >> "%TEMP_PS1%"
echo             Pause >> "%TEMP_PS1%"
echo             continue >> "%TEMP_PS1%"
echo         } >> "%TEMP_PS1%"
echo         $duration = if($type -eq 'LLDP') {35} else {65} >> "%TEMP_PS1%"
echo         Write-Host "`n[!] Capturing $type... Please wait for a network advertisement (up to 60s)." -ForegroundColor Yellow >> "%TEMP_PS1%"
echo         $captureWarnings = @() >> "%TEMP_PS1%"
echo         $packet = Invoke-DiscoveryProtocolCapture -Type $type -Duration $duration -Force -WarningVariable +captureWarnings >> "%TEMP_PS1%"
echo         $data = if ($packet) { $packet ^| Get-DiscoveryProtocolData } else { $null } >> "%TEMP_PS1%"
echo         Write-Host "========================================" -ForegroundColor Blue >> "%TEMP_PS1%"
echo         Write-Host "         $type DISCOVERY RESULTS         " -ForegroundColor Green >> "%TEMP_PS1%"
echo         Write-Host "========================================" -ForegroundColor Blue >> "%TEMP_PS1%"
echo         if ($data) { >> "%TEMP_PS1%"
echo             $resultIndex = 0 >> "%TEMP_PS1%"
echo             foreach ($item in @($data)) { >> "%TEMP_PS1%"
echo                 $resultIndex++ >> "%TEMP_PS1%"
echo                 Write-Host "" >> "%TEMP_PS1%"
echo                 Write-Host ("----- Result #{0} -----" -f $resultIndex) -ForegroundColor Cyan >> "%TEMP_PS1%"
echo             if ($type -eq 'CDP') { >> "%TEMP_PS1%"
echo                 $item ^| Select-Object Device, SystemName, SoftwareVersion, Model, IPAddress, Management, VLAN, Port, Capabilities, Duplex, TrustBitmap, UntrustedPortCoS, Connection, Interface, Computer, Type ^| Format-List >> "%TEMP_PS1%"
echo             } else { >> "%TEMP_PS1%"
echo                 $item ^| Select-Object Device, SystemName, SystemDescription, Model, IPAddress, ManagementAddresses, VLAN, VLANNamedEntries, Port, PortDescription, ChassisId, ChassisIdSubtype, ChassisIdSubtypeName, PortIdSubtype, PortIdSubtypeName, TimeToLive, SystemCapabilities, EnabledCapabilities, LinkAggregation, MacPhyConfigurationStatus, ManagementInterfaceNumberingSubtype, ManagementInterfaceNumber, ManagementObjectIdentifier, Connection, Interface, Computer, Type ^| Format-List >> "%TEMP_PS1%"
echo             } >> "%TEMP_PS1%"
echo             } >> "%TEMP_PS1%"
echo         } else { >> "%TEMP_PS1%"
echo             if ($captureWarnings.Count -gt 0) { >> "%TEMP_PS1%"
echo                 Write-Host "No data parsed. Capture details:" -ForegroundColor Yellow >> "%TEMP_PS1%"
echo                 $captureWarnings ^| ForEach-Object { Write-Host " - $_" -ForegroundColor DarkYellow } >> "%TEMP_PS1%"
echo             } else { >> "%TEMP_PS1%"
echo                 Write-Host "TIMEOUT: No $type packets received in $duration seconds." -ForegroundColor Red >> "%TEMP_PS1%"
echo                 Write-Host "Tips: Check physical connection, switch LLDP/CDP settings, or try the other protocol." -ForegroundColor Gray >> "%TEMP_PS1%"
echo             } >> "%TEMP_PS1%"
echo             Write-Host "Log file: $SessionLog" -ForegroundColor DarkCyan >> "%TEMP_PS1%"
echo         } >> "%TEMP_PS1%"
echo         Write-Host "`n----------------------------------------" >> "%TEMP_PS1%"
echo         Pause >> "%TEMP_PS1%"
echo     } >> "%TEMP_PS1%"
echo } while ($choice -ne '3') >> "%TEMP_PS1%"
echo Stop-Transcript ^| Out-Null >> "%TEMP_PS1%"

:: 3. Run the created script
powershell -NoProfile -ExecutionPolicy Bypass -File "%TEMP_PS1%"

:: 4. Cleanup
if exist "%TEMP_PS1%" del "%TEMP_PS1%"
endlocal
