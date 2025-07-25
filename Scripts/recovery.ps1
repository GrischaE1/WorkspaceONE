<#
.SYNOPSIS
    Orchestrates recovery actions for non-compliant devices in the Workspace ONE UEM environment.

.DESCRIPTION
    The recovery.ps1 script serves as the central orchestrator for initiating recovery actions when issues are detected in the Workspace ONE environment.
    It integrates detection results from health checks with the re-enrollment logic to restore devices to a compliant state.
    By coordinating the remediation process to ensures that devices which have fallen out of compliance are automatically re-enrolled and returned to proper management.


.EXAMPLE
    PS> .\recovery.ps1`
    -DSServerURL          'ds137.awmdm.com' `
    -UserName             'staginguser' `
    -UserPassword         'P@ssw0rd!' `
    -OGID                 'WS1' `
    -logFilePath          'C:\Temp\deploy.log' `
    -AgentUncPath         '\\fileserver\share\AirwatchAgent.msi' `
    -LocalAgentDestination 'C:\Windows\UEMRecovery'

    Executes the recovery process to re-enroll devices and perform necessary remediation actions based on detected issues.
    It is recommended to schedule this script to run automatically .

.NOTES
    Author       : Grischa Ernst
    Date         : 2025-07-25
    Version      : 1.0.0
    Requirements : PowerShell 5.1 or later / PowerShell Core 7+, access to Workspace ONE UEM endpoints, and properly configured supporting modules.
    Purpose      : To orchestrate and execute the recovery process by integrating health check outputs with re-enrollment actions.

.LICENSE
    Distributed under the terms specified in the license.md file.
#>


param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "URL of the DS Server - e.g. ds137.awmdm.com for CN137")][String] $DSServerURL,   
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Staginguser Username")][String] $UserName,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Staginguser Password")][String] $UserPassword,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Target OG ID")][String] $OGID,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Path to the log file where script output will be saved - e.g. C:\Temp\logfile.log")][String] $logFilePath,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Enter UNC path to copy the file from a local storage")][String] $AgentUncPath,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Enter the destination path for the agent on the device")][String] $LocalAgentDestination
)


###################################################################
# Functions

# Centralized Logging Function
function Write-Log {
    param (
        [string]$message,
        [string]$severity = "INFO"
    )

    # Define severity levels for filtering based on verbosity level
    $logLevels = @("INFO", "WARNING", "ERROR")
    if ($logLevels.IndexOf($severity) -ge $logLevels.IndexOf($logLevel)) {

        # Format message with a timestamp
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $formattedMessage = "$timestamp [$severity] - $message"

        # Output to console for real-time viewing (also captured by transcript if active)
        Write-ConsoleLog -message $formattedMessage -severity $severity
    }
}

# Function to Write Console Output with Severity Colors
function Write-ConsoleLog {
    param (
        [string]$message,
        [string]$severity
    )

    switch ($severity) {
        "INFO" { Write-Host $message -ForegroundColor Green }
        "WARNING" { Write-Host $message -ForegroundColor Yellow }
        "ERROR" { Write-Host $message -ForegroundColor Red }
    }
}


function Test-EnrollmentStatus {
    [CmdletBinding()]
    param()

    # Initialize flags.
     $workspaceOneInstalled       = $false
    $workspaceOneRegistryStatus  = $false
    $isWorkspaceONEEnrolled      = $false
    $isOMADMEnrolled             = $false
    $isAirwatchMDMEnrolled       = $false
    $hasSID                      = $false    
    $hasUPN                      = $false    
    $hasEnrollmentIdentity       = $false   

    # --- Workspace ONE Enrollment Checks ---

    # 1. Check for "Workspace ONE Intelligent Hub Installer" via WMI.
    try {
        $wmiResult = Get-WmiObject -Class win32_Product -Filter "Name='Workspace ONE Intelligent Hub Installer'" -ErrorAction SilentlyContinue
        if ($wmiResult) {
            $workspaceOneInstalled = $true
        }
    }
    catch {
        # Optionally log or handle errors.
    }

    # 2. Check the registry key for Workspace ONE Enrollment Status.
    try {
        $regPath = "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
        if (Test-Path $regPath) {
            $statusValue = (Get-ItemProperty -Path $regPath -Name "Status" -ErrorAction SilentlyContinue).Status
            if ($statusValue -eq "Completed") {
                $workspaceOneRegistryStatus = $true
            }
        }
    }
    catch {
        # Optionally log or handle errors.
    }

    if ($workspaceOneInstalled -and $workspaceOneRegistryStatus) {
        $isWorkspaceONEEnrolled = $true
    }

    # --- OMA-DM Enrollment Check ---
    try {
        $omaDmAccountsPath = "HKLM:\Software\Microsoft\Provisioning\OMADM\Accounts"
        if (Test-Path $omaDmAccountsPath) {
            $subkeys = Get-ChildItem -Path $omaDmAccountsPath -ErrorAction SilentlyContinue
            if ($subkeys -and $subkeys.Count -gt 0) {
                $isOMADMEnrolled = $true
            }
        }
    }
    catch {
        # Optionally log or handle errors.
    }

    # --- Airwatch MDM Enrollment Check ---
    try {
        $ProviderID  = 'AirwatchMDM'
        $enrollPath  = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        if (Test-Path $enrollPath) {
            $match = Get-ChildItem -Path $enrollPath -ErrorAction Stop |
                     Where-Object {
                         (Get-ItemProperty -Path $_.PSPath `
                             -Name 'ProviderId' -ErrorAction SilentlyContinue).ProviderId `
                             -eq $ProviderID
                     } | Select-Object -First 1

            if ($match) {
                $isAirwatchMDMEnrolled = $true

                # --- Enrollment Identity Check ---
                $provKeyPath = Join-Path $enrollPath $match.PSChildName

                # Check for SID
                try {
                    $sidVal = (Get-ItemProperty -Path $provKeyPath `
                                -Name 'SID' -ErrorAction SilentlyContinue).SID
                    if ($sidVal) { $hasSID = $true }
                } catch {}

                # Check for UPN
                try {
                    $upnVal = (Get-ItemProperty -Path $provKeyPath `
                                -Name 'UPN' -ErrorAction SilentlyContinue).UPN
                    if ($upnVal) { $hasUPN = $true }
                } catch {}

                # Composite
                if ($hasSID -or $hasUPN) {
                    $hasEnrollmentIdentity = $true
                }
            }
        }
    } catch {}

    # Return a custom object with the results.
    $result = [PSCustomObject]@{
        WorkspaceONEInstalled       = $workspaceOneInstalled
        WorkspaceONERegistryStatus  = $workspaceOneRegistryStatus
        IsWorkspaceONEEnrolled      = $isWorkspaceONEEnrolled
        IsOMADMEnrolled             = $isOMADMEnrolled
        IsAirwatchMDMEnrolled       = $isAirwatchMDMEnrolled
        HasSID                      = $hasSID
        HasUPN                      = $hasUPN
        HasEnrollmentIdentity       = $hasEnrollmentIdentity
    }

    return $result
}



###################################################################
# Execution

# Start PowerShell Transcript to Capture Console Output
if ($logFilePath) {
    if (Test-Path $logFilePath) {
        Remove-Item -Path $logFilePath -Force
    }
    
    Start-Transcript -Path $logFilePath -NoClobber -ErrorAction SilentlyContinue
}

# Run the enrollment checks
$enrollmentStatus = Test-EnrollmentStatus

# Grab all boolean property values
$allBoolValues = $enrollmentStatus.PSObject.Properties `
    | Where-Object { $_.Value -is [bool] } `
    | Select-Object -ExpandProperty Value

# If any flag is $false → continue; if none are $false (all true) → exit
if ($allBoolValues -contains $false) {

    Write-Log "One or more enrollment checks failed (flag false). Continuing script." -Severity "INFO"
    

    Write-Log "Starting recovery execution" -Severity "INFO"

    #Wait for explorer to be started
    do {
        Write-Log "Waiting for explorer to get started" -Severity "INFO"
        $Process = Get-Process -Name explorer
        Start-Sleep 20         
    }while (!$Process)

    # Download Workspace ONE Agent
    # Attempt to get the agent from UNC share first, otherwise download it from UEM Server
    try {
        if ($AgentUncPath) {
            Write-Log "Copying Workspace ONE Agent from UNC path $AgentUncPath" -Severity "INFO"
            Copy-Item -Path $AgentUncPath -Destination $LocalAgentDestination -Force
            Write-Log "Workspace ONE Agent copied successfully to $LocalAgentDestination." -Severity "INFO"
        }
        else {
            $AgentDownloadUrl = "https://$($DSServerURL)/agents/ProtectionAgent_autoseed/airwatchagent.msi"
            Write-Log "UNC path not found; downloading Workspace ONE Agent from $AgentDownloadUrl" -Severity "INFO"
            $WebClient = New-Object System.Net.WebClient
            $WebClient.DownloadFile($AgentDownloadUrl, "$($LocalAgentDestination)\AirwatchAgent.msi")
            Write-Log "Workspace ONE Agent downloaded successfully to $LocalAgentDestination." -Severity "INFO"
        }
    }
    catch {
        Write-Log "Failed to obtain Workspace ONE Agent: $_" -Severity "ERROR"
        exit 1
    }

    # Get Enrollment ID
    try {
        # Retrieve all items under the Enrollment registry key
        $AllItems = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments -Recurse -ErrorAction Stop
        $AirWatchMDMKey = $AllItems | Where-Object { $_.Name -like "*AirWatchMDM" }

        # Ensure the AirWatchMDMKey exists
        if (-not $AirWatchMDMKey) {
            throw "No AirWatchMDM key found in the registry."
        }

        # Extract the Enrollment Key using regex
        $pattern = "Enrollments\\(.*?)\\DMClient"
        $EnrollmentKey = ([regex]::Match(($AirWatchMDMKey.PSPath), $pattern).Groups[1].Value).Replace("\\", "")

        if (-not $EnrollmentKey) {
            throw "Failed to extract Enrollment Key using the specified regex pattern."
        }

        Write-Log "Enrollment key retrieved successfully: $EnrollmentKey."
    }
    catch {
        Write-Log "Failed to retrieve Enrollment ID: $_" -Severity "ERROR"
    }

    
    # Uninstall SFD to avoid application uninstallation
    Write-Log "Attempting to uninstall SFD Agent."
    try {
        # Retrieve the SFD Agent registry entry
        $Registry = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction Stop | Where-Object { $_.GetValue('DisplayName') -like "*SfdAgent*" }

        # Ensure the registry entry exists
        if (-not $Registry) {
            throw "SFD Agent registry entry not found."
        }

        # Construct the uninstall command
        $SFDUninstall = "/x $($Registry.PSChildName) /q"

        # Execute the uninstall process
        Start-Process MsiExec.exe -ArgumentList $SFDUninstall -Wait -ErrorAction Stop
        Write-Log "SFD Agent uninstalled successfully."
    }
    catch {
        Write-Log "Failed to uninstall SFD Agent: $_" -Severity "ERROR"
    }


    # Remove SFD and OMA-DM Registry keys
    Write-Log "Attempting to remove SFD and OMA-DM registry keys."
    try {
        # Remove Registry Keys
        $registryKeys = @(
            "HKLM:\\SOFTWARE\\Microsoft\\EnterpriseDesktopAppManagement",
            "HKLM:\\SOFTWARE\\AirWatchMDM"
        )

        foreach ($key in $registryKeys) {
            try {
                if (Test-Path $key) {
                    Remove-Item $key -Recurse -Force -ErrorAction Stop
                    Write-Log "Successfully removed registry key: $key."
                }
                else {
                    Write-Log "Registry key not found: $key." -Severity "WARNING"
                }
            }
            catch {
                Write-Log "Failed to remove registry key: $key. Error: $_" -Severity "ERROR"
            }
        }
    }
    catch {
        Write-Log "Error occurred while attempting to remove SFD and OMA-DM registry keys: $_" -Severity "ERROR"
    }

    # Uninstall Intelligent Hub
    Write-Log "Attempting to uninstall Intelligent Hub."
    if ($enrollmentStatus.WorkspaceONEInstalled -eq $True) {
        try {
            # Retrieve Intelligent Hub installation data
            $HubData = Get-WmiObject Win32_Product -ErrorAction Stop | Where-Object { $_.Name -like "*Intelligent HUB Installer*" }

            # Validate if Intelligent Hub is found
            if ($HubData) {
                # Construct the uninstall command
                $HubUninstall = "/x $($HubData.IdentifyingNumber) /q"

                # Execute the uninstall process
                Start-Process MsiExec.exe -ArgumentList $HubUninstall -Wait -ErrorAction Stop
                Write-Log "Intelligent Hub uninstalled successfully."
            }
            else {
                Write-Log "Intelligent Hub is not installed or could not be found." -Severity "WARNING"
            }
        }
        catch {
            Write-Log "Failed to uninstall Intelligent Hub: $_" -Severity "ERROR"
        }


        #Sleep for 60 seconds to make sure Hub is uninstalled
        Start-Sleep -Seconds 60

        # Uninstall WS1 App
        Write-Log "Attempting to uninstall WS1 app."
        try {
            # Retrieve the WS1 app package
            $WS1App = Get-AppxPackage *AirWatchLLC* -ErrorAction SilentlyContinue

            # Validate if the app package exists
            if ($WS1App) {
                # Attempt to remove the app package
                $WS1App | Remove-AppxPackage -ErrorAction SilentlyContinue
                Write-Log "WS1 app uninstalled successfully."
            }
            else {
                Write-Log "WS1 app is not installed or could not be found." -Severity "WARNING"
            }
        }
        catch {
            Write-Log "Failed to uninstall WS1 app: $_" -Severity "ERROR"
    
        }
    }

    # Remove Enrollment Registry Keys
    Write-Log "Attempting to remove Enrollment registry keys."
    $registryKeys = @(
        "HKLM:\SOFTWARE\AirWatch",
        "HKLM:\SOFTWARE\Microsoft\Enrollments",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\logger",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxDefault\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\_ContainerAdmxDefault\*",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\device\ApplicationManagement\*",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Session\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAnytimeUpgrade\Attempts\*"
        "HKLM:\SOFTWARE\WorkspaceONE"
        "HKLM:\SOFTWARE\AirWatchMDMBackup"
        "HKLM:\SOFTWARE\VMware, Inc.\VMware EUC"
        "HKLM:\SOFTWARE\VMware, Inc.\VMware Endpoint Telemetry"

    )

    foreach ($key in $registryKeys) {
        try {
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Successfully removed registry key: $key."
            }
            else {
                Write-Log "Registry key not found: $key." -Severity "WARNING"
            }
        }
        catch {
            Write-Log "Failed to remove registry key: $key. Error: $_" -Severity "ERROR"
        }
    }

    Write-Log "Delete files and information that may have been left behind"


    #Delete folders
    $directorypaths = @(
        "$env:ProgramData\AirWatch",
        "$env:ProgramData\VMware\SfdAgent",
        "$env:ProgramFiles\WorkspaceONE",
        "$env:ProgramData\VMware\vmwetlm",
        "$env:ProgramData\VMware\EUC",
        "$env:ProgramData\WorkspaceONE"
    )

    foreach ($directory in $directorypaths) {
        try {
            if (Test-Path $directory) {
                Remove-Item $directory -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Successfully removed directory: $directory."
            }
            else {
                Write-Log "Directory  not found: $directory." -Severity "WARNING"
            }
        }
        catch {
            Write-Log "Failed to remove directory: $directory. Error: $_" -Severity "ERROR"
        }
    }

    #Clean Scheduled Tasks - SFD
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$($EnrollmentKey)\*" | Unregister-ScheduledTask  -Confirm:$false

    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
    $rootFolder.DeleteFolder("$($EnrollmentKey)", $null)

    #Clean Scheduled Tasks - SFD - before 24.10
    Get-ScheduledTask -TaskPath "\vmware\SfdAgent\*" | Unregister-ScheduledTask  -Confirm:$false

    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\vmware")
    $rootFolder.DeleteFolder("SfdAgent", $null)

    #Clean Scheduled Tasks - SFD - after 24.10
    Get-ScheduledTask -TaskPath "\Workspace ONE\SfdAgent\*" | Unregister-ScheduledTask  -Confirm:$false

    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\Workspace ONE")
    $rootFolder.DeleteFolder("SfdAgent", $null)
    

    #Delete user certificates
    $UserCerts = Get-ChildItem cert:"CurrentUser" -Recurse
    $UserCerts | Where-Object { $_.Issuer -like "*AirWatch*" -or $_.Issuer -like "*AwDeviceRoot*" } | Remove-Item -Force

    #Delete device certificates
    $DeviceCerts = Get-ChildItem cert:"LocalMachine" -Recurse
    $DeviceCerts | Where-Object { $_.Issuer -like "*AirWatch*" -or $_.Issuer -like "*AwDeviceRoot*" } | Remove-Item -Force

    # Enroll the device to UEM
    Write-Log "Starting enrollment process for the device."
    try {
        # Construct the argument list for enrollment
        $List = "/q ENROLL=Y SERVER=https://$($DSServerURL) LGName=$($OGID) USERNAME=$($UserName) PASSWORD=$($UserPassword) ASSIGNTOLOGGEDINUSER=Y"
    
        # Execute the enrollment process
        Start-Process "$($LocalAgentDestination)\AirwatchAgent.msi" -ArgumentList $List -Wait -ErrorAction Stop
        Write-Log "Device enrollment initiated successfully."
    }
    catch {
        Write-Log "Failed to install Intelligent Hub: $_" -Severity "ERROR"
        $global:scriptError = $true
        exit 1
    }



    #Generate 10 minute timer
    $timeout = new-timespan -Minutes 10
    $sw = [diagnostics.stopwatch]::StartNew()
    $enrollcheck = $false
    $i = 0
    do {
        $i++
        Start-Sleep -Seconds 10
        Write-Log "Start enrollment check No. $($i)"

        #Check every 10 seconds if the device is enrolled
        $enrolltemp = Get-Item -Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus" -ErrorAction SilentlyContinue
        if ($enrolltemp) {
            If ($enrolltemp.GetValue("Status") -eq 'Completed') {
                $enrollcheck = $true
        
                Write-Log "Device enrolled successfully."
            }
        }
    }while ($enrollcheck -eq $false -and $sw.elapsed -lt $timeout)

}
else {
    Write-Log "All checks returned true. Exiting script." -Severity "INFO"
    exit 0
}
