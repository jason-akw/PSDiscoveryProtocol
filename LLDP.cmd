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
echo $ErrorActionPreference = 'SilentlyContinue' > "%TEMP_PS1%"
echo $ModuleManifest = '%MODULE_MANIFEST:\=\\%' >> "%TEMP_PS1%"
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
echo         Write-Host "`n[!] Capturing $type... Please wait for a network advertisement (up to 60s)." -ForegroundColor Yellow >> "%TEMP_PS1%"
echo         $data = Invoke-DiscoveryProtocolCapture -Type $type ^| Get-DiscoveryProtocolData >> "%TEMP_PS1%"
echo         Clear-Host >> "%TEMP_PS1%"
echo         Write-Host "========================================" -ForegroundColor Blue >> "%TEMP_PS1%"
echo         Write-Host "         $type DISCOVERY RESULTS         " -ForegroundColor Green >> "%TEMP_PS1%"
echo         Write-Host "========================================" -ForegroundColor Blue >> "%TEMP_PS1%"
echo         if ($data) { >> "%TEMP_PS1%"
echo             if ($type -eq 'CDP') { >> "%TEMP_PS1%"
echo                 $data ^| Format-List Device, SystemName, SoftwareVersion, Model, IPAddress, Management, VLAN, Port, Capabilities, Duplex, TrustBitmap, UntrustedPortCoS, Connection, Interface, Computer, Type >> "%TEMP_PS1%"
echo             } else { >> "%TEMP_PS1%"
echo                 $data ^| Format-List Device, SystemDescription, Model, IPAddress, VLAN, Port, PortDescription, ChassisId, ChassisIdSubtype, PortIdSubtype, TimeToLive, SystemCapabilities, EnabledCapabilities, ManagementInterfaceNumberingSubtype, ManagementInterfaceNumber, ManagementObjectIdentifier, Connection, Interface, Computer, Type >> "%TEMP_PS1%"
echo             } >> "%TEMP_PS1%"
echo         } else { >> "%TEMP_PS1%"
echo             Write-Host "TIMEOUT: No $type packets received." -ForegroundColor Red >> "%TEMP_PS1%"
echo             Write-Host "Tips: Check physical connection or try the other protocol." -ForegroundColor Gray >> "%TEMP_PS1%"
echo         } >> "%TEMP_PS1%"
echo         Write-Host "`n----------------------------------------" >> "%TEMP_PS1%"
echo         Pause >> "%TEMP_PS1%"
echo     } >> "%TEMP_PS1%"
echo } while ($choice -ne '3') >> "%TEMP_PS1%"

:: 3. Run the created script
powershell -NoProfile -ExecutionPolicy Bypass -File "%TEMP_PS1%"

:: 4. Cleanup
if exist "%TEMP_PS1%" del "%TEMP_PS1%"
endlocal
