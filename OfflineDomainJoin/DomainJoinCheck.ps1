##########################################################################################
# You running this script/function means you will not blame the author(s) if this breaks your stuff. 
# This script/function is provided AS IS without warranty of any kind. Author(s) disclaim all 
# implied warranties including, without limitation, any implied warranties of merchantability or of 
# fitness for a particular purpose. The entire risk arising out of the use or performance of the sample 
# scripts and documentation remains with you. In no event shall author(s) be held liable for any damages 
# whatsoever (including, without limitation, damages for loss of business profits, business interruption, 
# loss of business information, or other pecuniary loss) arising out of the use of or inability to use 
# the script or documentation. Neither this script/function, nor any part of it other than those parts 
# that are explicitly copied from others, may be republished without author(s) express written permission. 
# Author(s) retain the right to alter this disclaimer at any time.
##########################################################################################

##########################################################################################
# Name: DomainJoinTest.ps1
# Version: 0.6 
# Date: 23.10.2025
# Created by: Grischa Ernst gernst@omnissa.com
# Contributor: Leo Prince leo@mobinergy.com
#
# Description
# - This script waits for the Workspace ONE enrollment + domain join to complete + application installation
#
# How To
# - Run the script - if you need to change the sourcepath or the logpath, provide the parameter
#
# Example:
# DomainJoinTest.ps1 -SourcePath "C:\Source" -LogPath "C:\logs" -ComputerNamePrefix "Test"
#
##########################################################################################
#                                    Changelog 
#
# 0.6 - Bugfixing old SFD + Creating a new logic
# 0.5 - Enhanced error handling, logging, parameterization, and code structure
# 0.4 - Bugfixing the Domain Join Check part (initial value 1 - now 10 minutes)
# 0.3 - Added the computername prefix support
# 0.2 - Changed SFD detection to WMI
# 0.1 - Initial creation
##########################################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -IsValid })]
    [string]$SourcePath = "C:\Temp\ODJSource",
    
    [Parameter(Mandatory = $false)]
    [string]$ComputerNamePrefix,
    
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -IsValid })]
    [string]$LogPath = "C:\Temp",
    
    [Parameter(Mandatory = $false)]
    [int]$DomainJoinTimeoutMinutes = 10,
    
    [Parameter(Mandatory = $false)]
    [int]$SFDInstallTimeoutMinutes = 10,
    
    [Parameter(Mandatory = $false)]
    [int]$AppInstallTimeoutMinutes = 10,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipRestart
)

##########################################################################################
#                                    Functions
##########################################################################################

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        'Error' { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
    
    # Also write to transcript
    Write-Verbose $logMessage
}

function Test-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    try {
        $null = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-DeviceSerialNumber {
    [CmdletBinding()]
    param()
    
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $serialNumber = $bios.SerialNumber
        
        if ([string]::IsNullOrWhiteSpace($serialNumber)) {
            Write-Log "Serial number is empty, trying alternative method" -Level Warning
            $csProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
            $serialNumber = $csProduct.IdentifyingNumber
        }
        
        if ([string]::IsNullOrWhiteSpace($serialNumber)) {
            Write-Log "Could not retrieve device serial number" -Level Error
            return $null
        }
        
        # Clean up serial number (remove spaces and special characters that might cause issues)
        $serialNumber = $serialNumber.Trim()
        Write-Log "Device Serial Number: $serialNumber" -Level Info
        return $serialNumber
    }
    catch {
        Write-Log "Error retrieving serial number: $_" -Level Error
        return $null
    }
}

function Wait-ForCondition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Condition,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 10,
        
        [Parameter(Mandatory = $false)]
        [int]$CheckIntervalSeconds = 10
    )
    
    Write-Log "Waiting for: $Description" -Level Info
    $startTime = Get-Date
    $timeoutTime = $startTime.AddMinutes($TimeoutMinutes)
    
    while ((Get-Date) -le $timeoutTime) {
        try {
            $result = & $Condition
            Write-Log "Condition check returned: $result" -Level Info
            
            if ($result -eq $true) {
                Write-Log "Condition met: $Description" -Level Success
                return $true
            }
        }
        catch {
            Write-Log "Error evaluating condition: $_" -Level Warning
        }
        
        $elapsed = ((Get-Date) - $startTime).TotalMinutes
        Write-Log "Still waiting... (Elapsed: $([math]::Round($elapsed, 1)) minutes)" -Level Info
        Start-Sleep -Seconds $CheckIntervalSeconds
    }
    
    Write-Log "Timeout waiting for: $Description" -Level Error
    return $false
}

# Helpers (keep your existing ones or use these)
function ConvertTo-Boolean {
    param([Parameter(Mandatory)][object]$Value)
    if ($null -eq $Value) { return $false }
    $s = $Value.ToString().Trim()
    if ($s -match '^(?i:true|1|yes)$') { return $true }
    if ($s -match '^(?i:false|0|no)$') { return $false }
    try { return ([int]$Value -ne 0) } catch { return $false }
}
function ConvertTo-HResultInt {
    param([Parameter(Mandatory)][object]$Value)
    if ($null -eq $Value) { return 0 }
    $s = $Value.ToString().Trim()
    if ($s -match '^0x[0-9a-fA-F]+$') { return [int]([uint32]$s) }
    try { return [int]$s } catch { return 0 }
}

function Resolve-AppStatusPath {
    param([string]$AppId, [string[]]$SidRoots)
    foreach ($root in ($SidRoots | Sort-Object { if ($_ -match 'S-1-5-18$') { 0 } else { 1 } })) {
        $candidate = Join-Path $root $AppId
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

function Wait-AppInstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][string]$AppName,
        [Parameter(Mandatory)][string[]]$SidRoots,
        [int]$TimeoutMinutes = 10,
        [int]$CheckIntervalSeconds = 20
    )
    $start = Get-Date
    $deadline = $start.AddMinutes($TimeoutMinutes)
    $lastHr = 0
    $lastPath = $null

    while ((Get-Date) -lt $deadline) {
        $statusPath = Resolve-AppStatusPath -AppId $AppId -SidRoots $SidRoots
        if ($statusPath) {
            $lastPath = $statusPath
            try {
                $props = Get-ItemProperty -Path $statusPath -ErrorAction Stop

                $isInstalled = $false
                if ($props.PSObject.Properties.Name -contains 'IsInstalled') {
                    $isInstalled = ConvertTo-Boolean $props.IsInstalled
                }
                if ($isInstalled) {
                    Write-Log "$AppName : IsInstalled is TRUE ($statusPath)" -Level Success
                    return [pscustomobject]@{ Status = 'Installed'; HResult = 0; Path = $statusPath }
                }

                $hr = 0
                if ($props.PSObject.Properties.Name -contains 'LastErrorHRESULT') {
                    $hr = ConvertTo-HResultInt $props.LastErrorHRESULT
                }
                $lastHr = $hr

                if ($hr -ne 0) {
                    # EARLY EXIT ON ERROR
                    Write-Log "$AppName : IsInstalled=FALSE and LastErrorHRESULT=$hr ($statusPath) → FAILING immediately." -Level Error
                    return [pscustomobject]@{ Status = 'Failed'; HResult = $hr; Path = $statusPath }
                }

                Write-Log "$AppName : Pending (IsInstalled=FALSE, LastErrorHRESULT=0) ($statusPath)" -Level Info
            }
            catch {
                Write-Log "$AppName : Error reading $statusPath : $_" -Level Warning
            }
        }
        else {
            Write-Log "$AppName : No status key yet for AppId $AppId" -Level Info
        }

        Start-Sleep -Seconds $CheckIntervalSeconds
    }

    # Timed out without install and without error → pending timeout
    return [pscustomobject]@{ Status = 'TimeoutPending'; HResult = $lastHr; Path = $lastPath }
}


##########################################################################################
#                                    Pre-flight Checks
##########################################################################################

# Ensure script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script must be run as Administrator!" -Level Error
    exit 1
}

# Create paths if they don't exist
try {
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        Write-Log "Created log path: $LogPath" -Level Info
    }
    
    if (-not (Test-Path $SourcePath)) {
        Write-Log "Source path does not exist: $SourcePath" -Level Error
        exit 1
    }
}
catch {
    Write-Log "Error creating directories: $_" -Level Error
    exit 1
}

##########################################################################################
#                                    Start Script
##########################################################################################

Start-Transcript -Path "$LogPath\Provisioning_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" -Force
Write-Log "=== Starting Provisioning Script ===" -Level Info
Write-Log "SourcePath: $SourcePath" -Level Info
Write-Log "LogPath: $LogPath" -Level Info


try {
    # Disable Network Discovery popup
    Write-Log "Disabling Network Discovery popup" -Level Info
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force -ErrorAction Stop | Out-Null
    
    # Install config registry keys
    $regFile = Join-Path $SourcePath "keylock.reg"
    if (Test-Path $regFile) {
        Write-Log "Applying registry settings from: $regFile" -Level Info
        Start-Process regedit.exe -ArgumentList "/s `"$regFile`"" -Wait -NoNewWindow
    }
    else {
        Write-Log "Registry file not found: $regFile" -Level Warning
    }
    
    # Block keyboard
    $kidKeyLock = Join-Path $SourcePath "kidkeylock.exe"
    if (Test-Path $kidKeyLock) {
        Write-Log "Starting keyboard lock" -Level Info
        Start-Process $kidKeyLock -WindowStyle Hidden
    }
    else {
        Write-Log "Keyboard lock executable not found: $kidKeyLock" -Level Warning
    }
    
    # Start Splashscreen
    $splashScript = Join-Path $SourcePath "Show-OSUpgradeBackground.ps1"
    if (Test-Path $splashScript) {
        Write-Log "Starting splash screen" -Level Info
        $param = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$splashScript`""
        Start-Process "$env:SystemRoot\System32\WindowsPowershell\v1.0\powershell.exe" -ArgumentList $param
    }
    else {
        Write-Log "Splash screen script not found: $splashScript" -Level Warning
    }
    
    ##########################################################################################
    # Wait for AirWatch Installation and Enrollment
    ##########################################################################################
    
    Write-Log "=== Phase 1: AirWatch Installation and Enrollment ===" -Level Info
    
    # Wait for AirWatch installation
    $awInstalled = Wait-ForCondition -Condition {
        Test-Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
    } -Description "AirWatch installation" -TimeoutMinutes 30
    
    if (-not $awInstalled) {
        throw "AirWatch installation timeout"
    }
    
    # Wait for enrollment completion
    $enrollmentComplete = Wait-ForCondition -Condition {
        try {
            # Check enrollment status
            if (-not (Test-Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus")) {
                Write-Log "Enrollment status key not found" -Level Info
                return $false
            }
            
            $enrollTemp = Get-ItemProperty -Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus" -ErrorAction Stop
            $enrollStatus = $enrollTemp.Status -eq 'Completed'
            
            Write-Log "Enrollment Status: $($enrollTemp.Status) - Check passed: $enrollStatus" -Level Info
            
            # Check AutoLogonCount (key might not exist initially)
            $autoLogonCheck = $true
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
                $logonTemp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
                if ($logonTemp.PSObject.Properties.Name -contains 'AutoLogonCount') {
                    $autoLogonCheck = $logonTemp.AutoLogonCount -eq '0' -or $logonTemp.AutoLogonCount -eq 0
                    Write-Log "AutoLogonCount: $($logonTemp.AutoLogonCount) - Check passed: $autoLogonCheck" -Level Info
                }
                else {
                    Write-Log "AutoLogonCount property not found, considering passed" -Level Info
                }
            }
            
            $finalResult = $enrollStatus -and $autoLogonCheck
            Write-Log "Final enrollment check result: $finalResult (Enroll: $enrollStatus, AutoLogon: $autoLogonCheck)" -Level Info
            
            return $finalResult
        }
        catch {
            Write-Log "Error checking enrollment: $_" -Level Warning
            return $false
        }
    } -Description "Enrollment completion" -TimeoutMinutes 30
    
    if (-not $enrollmentComplete) {
        throw "Enrollment timeout"
    }
    
    ##########################################################################################
    # Wait for Domain Join
    ##########################################################################################
    
    Write-Log "=== Phase 2: Domain Join ===" -Level Info
    
    $domainJoined = Wait-ForCondition -Condition {
        try {
            $joinDomainPath = Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\JoinDomain"
            if (-not $joinDomainPath) {
                return $false
            }


            $computerName = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -ErrorAction Stop).ComputerName
            if ($ComputerNamePrefix) {
                return ($computerName -like "*$ComputerNamePrefix*")
            }
            else {
                $serialnumber = Get-DeviceSerialNumber
                return ($serialnumber -like "*$($computerName)")
            }
            
           
        }
        catch {
            return $false
        }
    } -Description "Domain Join" -TimeoutMinutes $DomainJoinTimeoutMinutes
    
    if (-not $domainJoined) {
        throw "Domain Join failed or timed out"
    }
    
    Start-Sleep -Seconds 60
    
    ##########################################################################################
    # Wait for Queue to Empty
    ##########################################################################################
    
    Write-Log "=== Phase 3: Application Deployment Queue ===" -Level Info
    
    $queueEmpty = Wait-ForCondition -Condition {
        try {
            $queueItems = Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\Queue' -Recurse -ErrorAction SilentlyContinue
            return ($null -eq $queueItems -or $queueItems.Count -eq 0)
        }
        catch {
            return $true  # If queue doesn't exist, consider it empty
        }
    } -Description "Application queue to empty" -TimeoutMinutes 30 -CheckIntervalSeconds 10
    
    if (-not $queueEmpty) {
        Write-Log "Queue did not empty in time, but continuing..." -Level Warning
    }
    
    ##########################################################################################
    # Wait for SFD Installation
    ##########################################################################################
    
    Write-Log "=== Phase 4: SFD Agent Installation ===" -Level Info
    
    $sfdInstalled = Wait-ForCondition -Condition {
        try {
            $paths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            $app = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like '*SFDAgent*' }
            if ($app) { return $true }

            # Or, if SFD runs as a service:
            # $svc = Get-Service -Name 'SFDAgent' -ErrorAction SilentlyContinue
            # return ($svc -and $svc.Status -eq 'Running')

            return $false
        }
        catch { return $false }
    } -Description "SFD Agent installation" -TimeoutMinutes $SFDInstallTimeoutMinutes

    
    ##########################################################################################
    # Wait for Application Installations
    ##########################################################################################
    ##########################################################################################
    # Phase 5: Application Installation Verification (SID-aware + HRESULT logic + early fail)
    ##########################################################################################

    # Helpers for robust registry parsing (place here so they're in scope for this phase)
    function ConvertTo-Boolean {
        param([Parameter(Mandatory)][object]$Value)
        if ($null -eq $Value) { return $false }
        $s = $Value.ToString().Trim()
        if ($s -match '^(?i:true|1|yes)$') { return $true }
        if ($s -match '^(?i:false|0|no)$') { return $false }
        try { return ([int]$Value -ne 0) } catch { return $false }
    }
    function ConvertTo-HResultInt {
        param([Parameter(Mandatory)][object]$Value)
        if ($null -eq $Value) { return 0 }
        $s = $Value.ToString().Trim()
        if ($s -match '^0x[0-9a-fA-F]+$') { return [int]([uint32]$s) } # hex to signed int
        try { return [int]$s } catch { return 0 }
    }

    # Resolve the status key for one AppId under any SID (S-1-5-18 preferred)
    function Resolve-AppStatusPath {
        param(
            [Parameter(Mandatory)][string]$AppId,
            [Parameter(Mandatory)][string[]]$SidRoots
        )
        foreach ($root in ($SidRoots | Sort-Object { if ($_ -match 'S-1-5-18$') { 0 } else { 1 } })) {
            $candidate = Join-Path $root $AppId
            if (Test-Path $candidate) { return $candidate }
        }
        return $null
    }

    # Waiter that exits early if LastErrorHRESULT != 0; returns object with Status/HResult/Path
    function Wait-AppInstall {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$AppId,
            [Parameter(Mandatory)][string]$AppName,
            [Parameter(Mandatory)][string[]]$SidRoots,
            [int]$TimeoutMinutes = 10,
            [int]$CheckIntervalSeconds = 20
        )
        $start = Get-Date
        $deadline = $start.AddMinutes($TimeoutMinutes)
        $lastHr = 0
        $lastPath = $null

        Write-Log "Waiting for: Installation of $AppName" -Level Info
        while ((Get-Date) -lt $deadline) {
            try {
                $statusPath = Resolve-AppStatusPath -AppId $AppId -SidRoots $SidRoots
                if ($statusPath) {
                    $lastPath = $statusPath
                    $props = Get-ItemProperty -Path $statusPath -ErrorAction Stop

                    $isInstalled = $false
                    if ($props.PSObject.Properties.Name -contains 'IsInstalled') {
                        $isInstalled = ConvertTo-Boolean $props.IsInstalled
                    }

                    if ($isInstalled) {
                        Write-Log "$AppName : IsInstalled is TRUE ($statusPath)" -Level Success
                        return [pscustomobject]@{ Status = 'Installed'; HResult = 0; Path = $statusPath }
                    }

                    $hr = 0
                    if ($props.PSObject.Properties.Name -contains 'LastErrorHRESULT') {
                        $hr = ConvertTo-HResultInt $props.LastErrorHRESULT
                    }
                    $lastHr = $hr

                    if ($hr -ne 0) {
                        # EARLY EXIT ON ERROR
                        Write-Log "$AppName : IsInstalled=FALSE and LastErrorHRESULT=$hr ($statusPath) → FAILING immediately." -Level Error
                        return [pscustomobject]@{ Status = 'Failed'; HResult = $hr; Path = $statusPath }
                    }

                    Write-Log "$AppName : Pending (IsInstalled=FALSE, LastErrorHRESULT=0) ($statusPath)" -Level Info
                }
                else {
                    Write-Log "$AppName : No status key yet for AppId $AppId" -Level Info
                }
            }
            catch {
                Write-Log "$AppName : Error while checking status: $_" -Level Warning
            }

            $elapsed = ((Get-Date) - $start).TotalMinutes
            Write-Log "Still waiting... (Elapsed: $([math]::Round($elapsed,1)) minutes)" -Level Info
            Start-Sleep -Seconds $CheckIntervalSeconds
        }

        # Timed out: not installed and no nonzero error → pending timeout
        Write-Log "Timeout waiting for: Installation of $AppName" -Level Error
        return [pscustomobject]@{ Status = 'TimeoutPending'; HResult = $lastHr; Path = $lastPath }
    }

    Write-Log "=== Phase 5: Application Installation Verification ===" -Level Info

    # Build required app map from AppManifests (AppId -> Friendly Name)
    $requiredApps = @{}
    try {
        $manifestKeys = Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests' -Recurse -ErrorAction Stop
        foreach ($k in $manifestKeys) {
            try {
                $p = Get-ItemProperty -Path $k.PSPath -ErrorAction Stop
                $appId = $k.PSChildName
                $appName = if ($p.PSObject.Properties.Name -contains 'Name') { $p.Name } else { $appId }
                $requiredApps[$appId] = $appName
            }
            catch {
                Write-Log "Error reading manifest at $($k.PSPath): $_" -Level Warning
            }
        }
        Write-Log "Found $($requiredApps.Count) required applications" -Level Info
    }
    catch {
        Write-Log "No applications found in manifest or error reading manifest" -Level Warning
    }

    # Discover all SID status roots (e.g., S-1-5-18)
    $sidRoots = @()
    try {
        $allChildren = Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent' -ErrorAction Stop
        $sidRoots = $allChildren | Where-Object { $_.PSChildName -like 'S-*' } | Select-Object -ExpandProperty PSPath
        if ($sidRoots.Count -eq 0) {
            Write-Log "No SID status roots under AppDeploymentAgent. Nothing to verify." -Level Warning
        }
        else {
            # Prefer machine context first
            $sidRoots = @($sidRoots | Sort-Object { if ($_ -match 'S-1-5-18$') { 0 } else { 1 } })
            Write-Log ("Found status roots: " + ($sidRoots -join ', ')) -Level Info
        }
    }
    catch {
        Write-Log "Error listing SID status roots: $_" -Level Warning
    }

    $failedApps = @()

    foreach ($appId in $requiredApps.Keys) {
        $appName = $requiredApps[$appId]
        Write-Log "Checking application: $appName" -Level Info

        $res = Wait-AppInstall -AppId $appId -AppName $appName -SidRoots $sidRoots `
            -TimeoutMinutes $AppInstallTimeoutMinutes -CheckIntervalSeconds 20

        switch ($res.Status) {
            'Installed' { Write-Log "$appName : Verification complete (installed)." -Level Success }
            'Failed' {
                Write-Log "Application installation FAILED (HRESULT=$($res.HResult)): $appName" -Level Error
                $failedApps += $appName
            }
            'TimeoutPending' {
                if ($res.HResult -ne 0) {
                    Write-Log "Application installation FAILED after timeout (HRESULT=$($res.HResult)): $appName" -Level Error
                    $failedApps += $appName
                }
                else {
                    Write-Log "$appName : Still pending (no error) after timeout; not marking as failed." -Level Warning
                }
            }
            default {
                Write-Log "$appName : Unexpected status '$($res.Status)'" -Level Warning
            }
        }
    }

    if ($failedApps.Count -gt 0) {
        Write-Log ("Failed applications (continuing): " + ($failedApps -join ', ')) -Level Warning
        # make them available to later phases / final summary
        $script:FailedApps = $failedApps
    }
    else {
        $script:FailedApps = @()
    }

    
    ##########################################################################################
    # Cleanup
    ##########################################################################################
    
    Write-Log "=== Phase 6: Cleanup ===" -Level Info
    
    # Remove last logged on user
    Write-Log "Clearing last logged on user information" -Level Info
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnUser -Value "" -ErrorAction SilentlyContinue
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnSAMUser -Value "" -ErrorAction SilentlyContinue
    
    # Remove the autologon
    Write-Log "Disabling auto-logon" -Level Info
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value "0" -ErrorAction SilentlyContinue
    
    # Re-enable Network Discovery popup
    Write-Log "Re-enabling Network Discovery popup" -Level Info
    Remove-Item "HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force -ErrorAction SilentlyContinue
    
    if ($script:FailedApps -and $script:FailedApps.Count -gt 0) {
        Write-Log ("Provisioning completed with application failures: " + ($script:FailedApps -join ', ')) -Level Warning
    }
    else {
        Write-Log "All required applications installed successfully." -Level Success
    }

    Write-Log "=== Provisioning completed successfully ===" -Level Success
    
    if (-not $SkipRestart) {
        Write-Log "Restarting computer in 10 seconds..." -Level Info
        Start-Sleep -Seconds 10
        Stop-Transcript
        Restart-Computer -Force
    }
    else {
        Write-Log "Skipping restart as requested" -Level Info
    }
}
catch {
    Write-Log "Critical error occurred: $_" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    Stop-Transcript
    exit 1
}
finally {
    if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) {
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
    }
}
