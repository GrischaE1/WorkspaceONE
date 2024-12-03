<#
    ============================================================
    Script Name:      MDM_WNS_Validation.ps1
    Author:           Grischa Ernst
    Version:          1.0.0
    Date:             December 2, 2024
    Purpose:          This script validates the health and configuration of Mobile Device Management (MDM)
                      services, specifically focusing on Workspace ONE, OMA-DM, and WNS. The script checks
                      MDM enrollment, service statuses, scheduled tasks, connection health, and MDM event logs.

    Parameters:
                      -providerID           Specify the MDM provider ID (e.g., "AirwatchMDM", "IntuneMDM", "CustomMDM")
                      -logFilePath          Specify the log file path where script output will be saved
                      -logLevel             Control verbosity of log output (Options: "INFO", "WARNING", "ERROR")
                      -showDetailedLogs     Include detailed logs in the output (enabled by default)
                      -separateLogFile      Create a separate log file for capturing script execution details (enabled by default)
                      -enableSummaryOutput  Enable summary output at the end of the script (enabled by default)
                      -includeMDMEventLogs  Optional: Include MDM Event Logs retrieval (disabled by default)

    Change Log:
                      Version 1.0.0 - Initial release
                          - Added MDM Enrollment validation
                          - Added OMA-DM Connection validation
                          - Added Scheduled Task validation
                          - Added Workspace ONE Hub status validation
                          - Added Windows Notification Service (WNS) validation
                          - Added MDM Enrollment State validation
                          - Added Certificate validation
                          - Added categorized and optional detailed event log retrieval

    Disclaimer:
    ============================================================
    This script is provided "as-is" without any warranties or guarantees of any kind. The author(s) and 
    distributor(s) are not liable for any damages, loss of data, or issues that may arise from using or 
    modifying this script. It is recommended to run the script in a controlled environment and ensure that 
    appropriate backups are taken prior to executing this script on any production system. This script 
    requires administrative privileges and should be executed by personnel with adequate knowledge of 
    Windows systems, MDM services, and registry settings.

    Usage Example:
                      .\MDM_WNS_Validation.ps1 -providerID "AirwatchMDM" -logFilePath "C:\Logs\MDM_WNS_Validation_Log.txt" `
                      -logLevel "INFO" -showDetailedLogs -separateLogFile -enableSummaryOutput -includeMDMEventLogs
    ============================================================
#>





# Configurations
param(
    # Specify the MDM provider ID (e.g., "AirwatchMDM", "IntuneMDM", "CustomMDM")
    [ValidateSet("AirwatchMDM", "IntuneMDM", "CustomMDM")]
    [Parameter(HelpMessage = "Specify the MDM provider ID (e.g., 'AirwatchMDM', 'IntuneMDM', 'CustomMDM')")]
    [string]$providerID = "AirwatchMDM",

    # Path to the log file where script output will be saved
    [Parameter(HelpMessage = "Path to the log file where script output will be saved")]
    [string]$logFilePath = "C:\Logs\MDM_WNS_Validation_Log.txt",

    # Specify the log level to control verbosity (Options: INFO, WARNING, ERROR)
    [ValidateSet("INFO", "WARNING", "ERROR")]
    [Parameter(HelpMessage = "Specify the log level to control verbosity (Options: INFO, WARNING, ERROR)")]
    [string]$logLevel = "INFO", # Options: INFO, WARNING, ERROR

    # Include detailed logs in the output (default: enabled)
    [Parameter(HelpMessage = "Include detailed logs in the output (default: enabled)")]
    [switch]$showDetailedLogs = $true,   # Enabled by default

    # Create a separate log file for capturing script execution details (default: enabled)
    [Parameter(HelpMessage = "Create a separate log file for capturing script execution details (default: enabled)")]
    [switch]$separateLogFile = $true,    # Enabled by default

    # Enable summary output at the end of the script (default: enabled)
    [Parameter(HelpMessage = "Enable summary output at the end of the script (default: enabled)")]
    [switch]$enableSummaryOutput = $true, # Enabled by default

    # Include MDM Event Logs retrieval (optional, default: disabled)
    [Parameter(HelpMessage = "Include MDM Event Logs retrieval (optional, default: disabled)")]
    [switch]$includeMDMEventLogs = $false # Disabled by default
)

# Start PowerShell Transcript to Capture Console Output
if ($separateLogFile) {
    if (Test-Path $logFilePath) {
        Remove-Item -Path $logFilePath -Force
    }

    Start-Transcript -Path $logFilePath -NoClobber -ErrorAction SilentlyContinue
}

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

# Function to Measure Script Section Execution Time
function Measure-ScriptSection {
    param (
        [scriptblock]$code,
        [string]$sectionName
    )

    Write-Log "**************************************" -Severity "INFO"
    Write-Log "Starting Section: $sectionName" -Severity "INFO"
    Write-Log "**************************************" -Severity "INFO"

    $start = Get-Date
    & $code
    $end = Get-Date
    $duration = $end - $start

    Write-Log "Completed section: $sectionName in $($duration.TotalSeconds) seconds." -Severity "INFO"
    Write-Log ""
}

# Function to Convert OMA-DM Timestamps
function Convert-TimestampToDate {
    param ([string]$timestamp)

    # Ensure the timestamp has at least 15 characters (YYYYMMDDHHMMSS)
    if ($timestamp.Length -lt 15) {
        Write-Log "Invalid timestamp format: $timestamp" -Severity "WARNING"
        return $null
    }

    try {
        # Extract components of the timestamp
        $year = $timestamp.Substring(0, 4)
        $month = $timestamp.Substring(4, 2)
        $day = $timestamp.Substring(6, 2)
        $hour = $timestamp.Substring(9, 2)
        $minute = $timestamp.Substring(11, 2)
        $second = $timestamp.Substring(13, 2)

        # Construct and return a DateTime object
        return Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second $second
    } catch {
        Write-Log "Error converting timestamp: $($_.Exception.Message)" -Severity "ERROR"
        return $null
    }
}

# Function to Get the Active MDM Enrollment Details
function Get-MDMEnrollmentDetails {
    Write-Log "Starting retrieval of Current MDM User Output..." -Severity "INFO"

    $activeMDMID = (Get-ChildItem HKLM:\SOFTWARE\MICROSOFT\ENROLLMENTS | Where-Object {
        $_.GetValue('ProviderId') -eq $providerID
    }).Name | Split-Path -Leaf

    if ($activeMDMID) {
        try {
            $activeMDMUserSID = Get-ItemPropertyValue "HKLM:\SOFTWARE\MICROSOFT\ENROLLMENTS\$activeMDMID" -Name SID -ErrorAction Stop
            New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

            $registryTest = Test-Path "HKU:\$activeMDMUserSID"
            $MDMUserName = if ($registryTest) {
                Get-ItemPropertyValue "HKU:\$activeMDMUserSID\Volatile Environment" -Name USERNAME
            }

            $userProfileTest = if ($registryTest) {
                Test-Path (Get-ItemPropertyValue "HKU:\$activeMDMUserSID\Volatile Environment" -Name USERPROFILE)
            }

            Write-Log "Current active MDM ID:            $activeMDMID" -Severity "INFO"
            Write-Log "Current active MDM UserSID:       $activeMDMUserSID" -Severity "INFO"
            Write-Log "User SID in Registry:             $registryTest" -Severity "INFO"
            if ($MDMUserName) { Write-Log "Current active MDM Username:      $MDMUserName" -Severity "INFO" }
            Write-Log "User Profile Path still active:   $userProfileTest" -Severity "INFO"
        } catch {
            Write-Log "Error accessing registry key for Active MDM User SID: $($_.Exception.Message)" -Severity "ERROR"
            $global:scriptError = $true
        }
    } else {
        Write-Log "No active MDM enrollment found." -Severity "WARNING"
    }

    return $activeMDMID
}

# Function to Get Workspace ONE Intelligent Hub Status
function Get-WorkspaceONEHubStatus {
    Write-Log "Retrieving Workspace ONE Intelligent Hub Status..." -Severity "INFO"

    # Define the services to check
    $services = @(
        @{ Name = "AirWatchService"; DisplayName = "AirWatch Service" },
        @{ Name = "VMware Hub Health Monitoring Service"; DisplayName = "Health Monitoring Service" }
    )

    foreach ($service in $services) {
        $status = (Get-Service -Name $service.Name -ErrorAction SilentlyContinue).Status
        Write-Log "$($service.DisplayName): $status" -Severity "INFO"
    }

    # Define processes to check
    $processes = @("VMwareHubHealthMonitoring", "AWACMClient", "AwWindowsIpc")
    foreach ($process in $processes) {
        $running = Get-Process -Name $process -ErrorAction SilentlyContinue
        if ($running) {
            Write-Log "$process Process: Running" -Severity "INFO"
        } else {
            Write-Log "$process Process: Not Running" -Severity "WARNING"
        }
    }

    # Check the AirWatch Agent Status
    try {
        $agentStatus = Get-ItemPropertyValue "HKLM:\SOFTWARE\AIRWATCH" -Name AgentStatus -ErrorAction SilentlyContinue
        if ($agentStatus -like "Started*") {
            $agentStartTime = Get-Date $agentStatus.Substring(8)
            Write-Log "AirWatch Agent Started at $agentStartTime" -Severity "INFO"
        } else {
            Write-Log "AirWatch Agent not started." -Severity "WARNING"
        }
    } catch {
        Write-Log "Unable to retrieve AirWatch Agent Status." -Severity "ERROR"
    }
}

# Function to Get OMA-DM Connection Info
function Get-OMADMConnectionInfo {
    param ([string]$activeMDMID)

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping OMA-DM Connection Info." -Severity "WARNING"
        return
    }

    Write-Log "Starting retrieval of OMA-DM Connection Information..." -Severity "INFO"

    $connInfoPath = "HKLM:\Software\Microsoft\Provisioning\OMADM\Accounts\$activeMDMID\Protected\ConnInfo"

    $lastAttemptTimestamp = Get-ItemPropertyValue -Path $connInfoPath -Name ServerLastAccessTime -ErrorAction SilentlyContinue
    $lastSuccessTimestamp = Get-ItemPropertyValue -Path $connInfoPath -Name ServerLastSuccessTime -ErrorAction SilentlyContinue

    if ($lastAttemptTimestamp) {
        $lastAttemptDate = Convert-TimestampToDate -timestamp $lastAttemptTimestamp
        Write-Log "Last connection attempt: $lastAttemptDate" -Severity "INFO"
    }

    if ($lastSuccessTimestamp) {
        $lastSuccessDate = Convert-TimestampToDate -timestamp $lastSuccessTimestamp
        Write-Log "Last successful connection: $lastSuccessDate" -Severity "INFO"

        # Calculate time since last successful connection
        $timeDifference = (Get-Date) - $lastSuccessDate
        Write-Log "Time since last successful connection: $($timeDifference.Days) days and $($timeDifference.Hours) hours" -Severity "INFO"
    }
}

# Function to Validate Scheduled Tasks
function Validate-ScheduledTasks {
    param ([string]$activeMDMID)

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping Scheduled Task Validation." -Severity "WARNING"
        return
    }

    Write-Log "Validating scheduled tasks for MDM..." -Severity "INFO"

    $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$activeMDMID\"
    $tasks = @(
        @{ Name = "Schedule #3 created by enrollment client"; Description = "8-hour sync" },
        @{ Name = "Schedule to run OMADMClient by client"; Description = "Main sync task" }
    )

    foreach ($task in $tasks) {
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $task.Name -ErrorAction Stop
            Write-Log "$($task.Description) - Last Runtime: $($taskInfo.LastRunTime)" -Severity "INFO"
            Write-Log "$($task.Description) - Last Result: $($taskInfo.LastTaskResult)" -Severity "INFO"
        } catch {
            Write-Log "Task '$($task.Name)' not found or could not be retrieved." -Severity "WARNING"
        }
    }
}

# Function to Get WNS Status
function Get-WNSStatus {
    param ([string]$activeMDMID)

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping WNS Status Retrieval." -Severity "WARNING"
        return
    }

    Write-Log "Retrieving WNS status..." -Severity "INFO"

    $pushPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$activeMDMID\Push"
    $wnsServiceStatus = (Get-Service WpnService -ErrorAction SilentlyContinue).Status
    $wnsStatus = Get-ItemPropertyValue -Path $pushPath -Name Status -ErrorAction SilentlyContinue
    $lastRenewalTime = [DateTime]::FromFileTime((Get-ItemPropertyValue -Path $pushPath -Name LastRenewalTime -ErrorAction SilentlyContinue))
    $channelExpiryTime = [DateTime]::FromFileTime((Get-ItemPropertyValue -Path $pushPath -Name ChannelExpiryTime -ErrorAction SilentlyContinue))

    Write-Log "WNS Service Status: $wnsServiceStatus" -Severity "INFO"
    Write-Log "WNS Status: $wnsStatus" -Severity "INFO"
    Write-Log "Last Renewal Time: $lastRenewalTime" -Severity "INFO"
    Write-Log "Channel Expiry Time: $channelExpiryTime" -Severity "INFO"

    if ((Get-Date) -le $channelExpiryTime -and $wnsStatus -eq 0 -and $wnsServiceStatus -eq "Running") {
        Write-Log "WNS Channel is active and healthy" -Severity "INFO"
    } else {
        Write-Log "WNS Channel is expired or unhealthy" -Severity "WARNING"
    }
}

# Function to Validate MDM Certificates
function Validate-MDMCertificates {
    Write-Log "Validating MDM Certificates..." -Severity "INFO"
    
    try {
        $certificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -like "*MDM*" }
        if ($certificates.Count -gt 0) {
            Write-Log "MDM Certificates found:" -Severity "INFO"
            foreach ($cert in $certificates) {
                Write-Log "Certificate: $($cert.Subject) - Expiration: $($cert.NotAfter)" -Severity "INFO"
            }
        } else {
            Write-Log "No MDM Certificates found." -Severity "WARNING"
        }
    } catch {
        Write-Log "Error retrieving MDM Certificates: $($_.Exception.Message)" -Severity "ERROR"
    }
}

# Function to Get Categorized MDM Event Logs
function Get-CategorizedEventLogs {
    Write-Log "Starting retrieval of Categorized MDM Diagnostic Event Logs..." -Severity "INFO"

    $eventLogName = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational"
    try {
        $events = Get-WinEvent -LogName $eventLogName -ErrorAction SilentlyContinue
        if ($events) {
            $errorCount = ($events | Where-Object { $_.LevelDisplayName -eq "Error" }).Count
            $warningCount = ($events | Where-Object { $_.LevelDisplayName -eq "Warning" }).Count
            $infoCount = ($events | Where-Object { $_.LevelDisplayName -eq "Information" }).Count

            Write-Log "Number of Error events: $errorCount" -Severity "ERROR"
            Write-Log "Number of Warning events: $warningCount" -Severity "WARNING"
            Write-Log "Number of Information events: $infoCount" -Severity "INFO"
        } else {
            Write-Log "No events found in $eventLogName." -Severity "INFO"
        }
    } catch {
        Write-Log "Error accessing MDM Event Logs: $($_.Exception.Message)" -Severity "ERROR"
    }
}

# Function to Get MDM Event Logs
function Get-MDMEventLogs {
    Write-Log "Retrieving MDM Event Logs..." -Severity "INFO"

    try {
        $eventLogName = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational"
        $events = Get-WinEvent -LogName $eventLogName -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            Write-Log "Event ID: $($event.Id) - $($event.Message)" -Severity "INFO"
        }
    } catch {
        Write-Log "Error accessing MDM Event Logs: $($_.Exception.Message)" -Severity "ERROR"
    }
}

# Function to Validate MDM Enrollment State
function Validate-MDMEnrollmentState {
    param ([string]$activeMDMID)

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping MDM Enrollment State Validation." -Severity "WARNING"
        return
    }

    Write-Log "Validating MDM Enrollment State..." -Severity "INFO"

    try {
        $enrollmentPath = "HKLM:\Software\Microsoft\Enrollments\$activeMDMID"
        $discoveryURL = Get-ItemPropertyValue -Path $enrollmentPath -Name DiscoveryServiceFullURL -ErrorAction SilentlyContinue

        if ($discoveryURL) {
            Write-Log "Discovery Service Full URL: $discoveryURL" -Severity "INFO"
        } else {
            Write-Log "No Discovery Service URL found for MDM Enrollment." -Severity "WARNING"
        }
    } catch {
        Write-Log "Error validating MDM Enrollment State: $($_.Exception.Message)" -Severity "ERROR"
    }
}

# Function to Print Script Summary with Enable/Disable Option
function Print-ScriptSummary {
    if ($enableSummaryOutput) {
        Write-Log "**************************************" -Severity "INFO"
        Write-Log "Script Execution Summary:" -Severity "INFO"
        Write-Log "**************************************" -Severity "INFO"

        $summary = [PSCustomObject]@{
            ErrorsDetected    = $global:scriptError
            LogFileLocation   = $logFilePath
            ExecutionStatus   = if ($global:scriptError) { "Failed" } else { "Successful" }
        }

        Write-Log ($summary | Format-Table -AutoSize | Out-String).Trim()
    }
}

# Main Script Execution with Performance Measurement
$global:scriptError = $false

Measure-ScriptSection -code { $activeMDMID = Get-MDMEnrollmentDetails } -sectionName "Get MDM Enrollment Details"
Measure-ScriptSection -code { Get-OMADMConnectionInfo -activeMDMID $activeMDMID } -sectionName "OMA-DM Connection Info"
Measure-ScriptSection -code { Validate-ScheduledTasks -activeMDMID $activeMDMID } -sectionName "Validate Scheduled Tasks"
Measure-ScriptSection -code { Get-WorkspaceONEHubStatus } -sectionName "WorkspaceONE Hub Status"
Measure-ScriptSection -code { Get-WNSStatus -activeMDMID $activeMDMID } -sectionName "WNS Status"
Measure-ScriptSection -code { Validate-MDMEnrollmentState -activeMDMID $activeMDMID } -sectionName "Validate MDM Enrollment State"
if ($includeMDMEventLogs) {
    Measure-ScriptSection -code { Get-MDMEventLogs } -sectionName "Get MDM Diagnostic Event Logs"
}
Measure-ScriptSection -code { Get-CategorizedEventLogs } -sectionName "Categorized MDM Event Logs"
Measure-ScriptSection -code { Validate-MDMCertificates } -sectionName "Validate MDM Certificates"

Print-ScriptSummary

# Stop PowerShell Transcript if it's running
if ($separateLogFile) {
    Stop-Transcript
}

# Exit code handling
$global:exitCode = 0
if ($global:scriptError) {
    $global:exitCode = 2
}

$severity = if ($global:exitCode -eq 0) { "INFO" } else { "ERROR" }
Write-Log "Script completed with exit code $global:exitCode." -Severity $severity
Exit $global:exitCode
