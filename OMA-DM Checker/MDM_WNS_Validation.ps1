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
        [Parameter(Mandatory = $true)]
        [scriptblock]$code,

        [Parameter(Mandatory = $true)]
        [string]$sectionName
    )

    Write-Log "**************************************" -Severity "INFO"
    Write-Log "Starting Section: $sectionName" -Severity "INFO"
    Write-Log "**************************************" -Severity "INFO"

    $start = Get-Date

    try {
        # Execute the code in the script block and capture the result
        $result = & $code
    } catch {
        Write-Log "Error while executing section: $sectionName. Error: $($_.Exception.Message)" -Severity "ERROR"
    }

    $end = Get-Date
    $duration = $end - $start

    Write-Log "Completed section: $sectionName in $($duration.TotalSeconds) seconds." -Severity "INFO"
    Write-Log ""

    # Return the result from the script block
    return $result
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
        
        if ($status -eq "Running") {
            Write-Log "$($service.DisplayName): $status" -Severity "INFO"
            Add-Result -Category "Workspace ONE Hub Status" -Test "$($service.DisplayName) Status" -Result "Success" -Details "$($service.DisplayName) is running"
        } else {
            Write-Log "$($service.DisplayName): Not Running" -Severity "WARNING"
            Add-Result -Category "Workspace ONE Hub Status" -Test "$($service.DisplayName) Status" -Result "Failure" -Details "$($service.DisplayName) is not running"
        }
    }

    # Define processes to check
    $processes = @("VMwareHubHealthMonitoring", "AWACMClient", "AwWindowsIpc")
    foreach ($process in $processes) {
        $running = Get-Process -Name $process -ErrorAction SilentlyContinue
        if ($running) {
            Write-Log "$process Process: Running" -Severity "INFO"
            Add-Result -Category "Workspace ONE Hub Status" -Test "$process Process Check" -Result "Success" -Details "$process is running"
        } else {
            Write-Log "$process Process: Not Running" -Severity "WARNING"
            Add-Result -Category "Workspace ONE Hub Status" -Test "$process Process Check" -Result "Failure" -Details "$process is not running"
        }
    }

    # Check the AirWatch Agent Status
    try {
        $agentStatus = Get-ItemPropertyValue "HKLM:\SOFTWARE\AIRWATCH" -Name AgentStatus -ErrorAction SilentlyContinue
        if ($agentStatus -like "Started*") {
            $agentStartTime = Get-Date $agentStatus.Substring(8)
            Write-Log "AirWatch Agent Started at $agentStartTime" -Severity "INFO"
            Add-Result -Category "Workspace ONE Hub Status" -Test "AirWatch Agent Status" -Result "Success" -Details "AirWatch Agent started at $agentStartTime"
        } else {
            Write-Log "AirWatch Agent not started." -Severity "WARNING"
            Add-Result -Category "Workspace ONE Hub Status" -Test "AirWatch Agent Status" -Result "Failure" -Details "AirWatch Agent not started"
        }
    } catch {
        Write-Log "Unable to retrieve AirWatch Agent Status." -Severity "ERROR"
        Add-Result -Category "Workspace ONE Hub Status" -Test "AirWatch Agent Status Retrieval" -Result "Failure" -Details "Unable to retrieve AirWatch Agent Status: $($_.Exception.Message)"
    }

    # Debug log to verify that results are being added
    Write-Log "Current Output Results: $($global:outputResults.Count) entries" -Severity "INFO"
}

# Function to Get OMA-DM Connection Info
function Get-OMADMConnectionInfo {
    param ([string]$activeMDMID)

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping OMA-DM Connection Info." -Severity "WARNING"
        Add-Result -Category "OMA-DM Connection Info" -Test "Active MDM ID Check" -Result "Failure" -Details "Active MDM ID is not available. Skipping OMA-DM Connection Info."
        return
    }

    Write-Log "Starting retrieval of OMA-DM Connection Information..." -Severity "INFO"

    $connInfoPath = "HKLM:\Software\Microsoft\Provisioning\OMADM\Accounts\$activeMDMID\Protected\ConnInfo"

    try {
        # Retrieve the last connection attempt timestamp
        $lastAttemptTimestamp = Get-ItemPropertyValue -Path $connInfoPath -Name ServerLastAccessTime -ErrorAction SilentlyContinue

        if ($lastAttemptTimestamp) {
            $lastAttemptDate = Convert-TimestampToDate -timestamp $lastAttemptTimestamp
            Write-Log "Last connection attempt: $lastAttemptDate" -Severity "INFO"
            Add-Result -Category "OMA-DM Connection Info" -Test "Last Connection Attempt" -Result "Success" -Details "Last connection attempt was at: $lastAttemptDate"
        } else {
            Write-Log "No record of the last connection attempt found." -Severity "WARNING"
            Add-Result -Category "OMA-DM Connection Info" -Test "Last Connection Attempt" -Result "Failure" -Details "No record of the last connection attempt found"
        }

        # Retrieve the last successful connection timestamp
        $lastSuccessTimestamp = Get-ItemPropertyValue -Path $connInfoPath -Name ServerLastSuccessTime -ErrorAction SilentlyContinue

        if ($lastSuccessTimestamp) {
            $lastSuccessDate = Convert-TimestampToDate -timestamp $lastSuccessTimestamp
            Write-Log "Last successful connection: $lastSuccessDate" -Severity "INFO"
            Add-Result -Category "OMA-DM Connection Info" -Test "Last Successful Connection" -Result "Success" -Details "Last successful connection was at: $lastSuccessDate"

            # Calculate the time since the last successful connection
            $timeDifference = (Get-Date) - $lastSuccessDate
            Write-Log "Time since last successful connection: $($timeDifference.Days) days and $($timeDifference.Hours) hours" -Severity "INFO"

            # Add a result for the elapsed time since last connection
            if ($timeDifference.TotalHours -le 8) {
                Add-Result -Category "OMA-DM Connection Info" -Test "Recent Successful Connection" -Result "Success" -Details "Last successful connection was within the past 8 hours"
            } else {
                Add-Result -Category "OMA-DM Connection Info" -Test "Recent Successful Connection" -Result "Failure" -Details "Last successful connection was more than 8 hours ago"
            }
        } else {
            Write-Log "No record of the last successful connection found." -Severity "WARNING"
            Add-Result -Category "OMA-DM Connection Info" -Test "Last Successful Connection" -Result "Failure" -Details "No record of the last successful connection found"
        }
    } catch {
        Write-Log "Error retrieving OMA-DM Connection Info: $($_.Exception.Message)" -Severity "ERROR"
        Add-Result -Category "OMA-DM Connection Info" -Test "OMA-DM Retrieval Error" -Result "Failure" -Details "Error retrieving OMA-DM Connection Info: $($_.Exception.Message)"
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
        Add-Result -Category "WNS Status" -Test "Active MDM ID Check" -Result "Failure" -Details "Active MDM ID is not available. Skipping WNS Status Retrieval."
        return
    }

    Write-Log "Retrieving WNS status..." -Severity "INFO"

    try {
        $pushPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$activeMDMID\Push"
        
        # Retrieve WNS Service Status
        $wnsServiceStatus = (Get-Service WpnService -ErrorAction SilentlyContinue).Status
        Write-Log "WNS Service Status: $wnsServiceStatus" -Severity "INFO"
        if ($wnsServiceStatus -eq "Running") {
            Add-Result -Category "WNS Status" -Test "WNS Service Status Check" -Result "Success" -Details "WNS Service is running."
        } else {
            Add-Result -Category "WNS Status" -Test "WNS Service Status Check" -Result "Failure" -Details "WNS Service is not running."
        }

        # Retrieve WNS Status
        $wnsStatus = Get-ItemPropertyValue -Path $pushPath -Name Status -ErrorAction SilentlyContinue
        Write-Log "WNS Status: $wnsStatus" -Severity "INFO"
        if ($wnsStatus -eq 0) {
            Add-Result -Category "WNS Status" -Test "WNS Status Check" -Result "Success" -Details "WNS Status indicates no issues (Status Code: $wnsStatus)."
        } else {
            Add-Result -Category "WNS Status" -Test "WNS Status Check" -Result "Failure" -Details "WNS Status indicates an issue (Status Code: $wnsStatus)."
        }

        # Retrieve Last Renewal Time
        $lastRenewalTime = [DateTime]::FromFileTime((Get-ItemPropertyValue -Path $pushPath -Name LastRenewalTime -ErrorAction SilentlyContinue))
        Write-Log "Last Renewal Time: $lastRenewalTime" -Severity "INFO"
        Add-Result -Category "WNS Status" -Test "WNS Last Renewal Time Check" -Result "Info" -Details "Last Renewal Time: $lastRenewalTime"

        # Retrieve Channel Expiry Time
        $channelExpiryTime = [DateTime]::FromFileTime((Get-ItemPropertyValue -Path $pushPath -Name ChannelExpiryTime -ErrorAction SilentlyContinue))
        Write-Log "Channel Expiry Time: $channelExpiryTime" -Severity "INFO"
        Add-Result -Category "WNS Status" -Test "WNS Channel Expiry Time Check" -Result "Info" -Details "Channel Expiry Time: $channelExpiryTime"

        # Determine WNS Health
        if ((Get-Date) -le $channelExpiryTime -and $wnsStatus -eq 0 -and $wnsServiceStatus -eq "Running") {
            Write-Log "WNS Channel is active and healthy" -Severity "INFO"
            Add-Result -Category "WNS Status" -Test "WNS Channel Health Check" -Result "Success" -Details "WNS Channel is active and healthy."
        } else {
            Write-Log "WNS Channel is expired or unhealthy" -Severity "WARNING"
            Add-Result -Category "WNS Status" -Test "WNS Channel Health Check" -Result "Failure" -Details "WNS Channel is expired or unhealthy."
        }
    } catch {
        Write-Log "Error retrieving WNS status: $($_.Exception.Message)" -Severity "ERROR"
        Add-Result -Category "WNS Status" -Test "WNS Status Retrieval Error" -Result "Failure" -Details "Error retrieving WNS status: $($_.Exception.Message)"
    }
}

# Function to Validate MDM Certificates
function Validate-MDMCertificates {
    Write-Log "Validating MDM Certificates..." -Severity "INFO"

    try {
        # Retrieve certificates with subjects containing "AirWatch" or "AwDeviceRoot"
        $certificates = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*AirWatch*" -or $_.Subject -like "*AwDeviceRoot*" }

        if ($certificates.Count -gt 0) {
            Write-Log "MDM Certificates found:" -Severity "INFO"

            # Loop through each certificate and log its details
            foreach ($cert in $certificates) {
                Write-Log "Certificate: $($cert.Subject) - Expiration: $($cert.NotAfter)" -Severity "INFO"

                # Check if the certificate is valid
                $daysUntilExpiration = ($cert.NotAfter - (Get-Date)).Days
                if ($daysUntilExpiration -gt 0) {
                    Add-Result -Category "MDM Certificates" -Test "Certificate Validity Check" -Result "Success" -Details "Certificate '$($cert.Subject)' is valid. Expiration: $($cert.NotAfter)"
                } else {
                    Add-Result -Category "MDM Certificates" -Test "Certificate Validity Check" -Result "Failure" -Details "Certificate '$($cert.Subject)' has expired. Expiration: $($cert.NotAfter)"
                }
            }
        } else {
            Write-Log "No MDM Certificates found." -Severity "WARNING"
            Add-Result -Category "MDM Certificates" -Test "Certificate Presence Check" -Result "Failure" -Details "No MDM Certificates found."
        }
    } catch {
        Write-Log "Error retrieving MDM Certificates: $($_.Exception.Message)" -Severity "ERROR"
        Add-Result -Category "MDM Certificates" -Test "Certificate Retrieval Error" -Result "Failure" -Details "Error retrieving MDM Certificates: $($_.Exception.Message)"
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
        Add-Result -Category "MDM Enrollment State" -Test "Active MDM ID Check" -Result "Failure" -Details "Active MDM ID is not available. Skipping validation."
        return
    }

    Write-Log "Validating MDM Enrollment State..." -Severity "INFO"

    try {
        $enrollmentPath = "HKLM:\Software\Microsoft\Enrollments\$activeMDMID"
        $discoveryURL = Get-ItemPropertyValue -Path $enrollmentPath -Name DiscoveryServiceFullURL -ErrorAction SilentlyContinue

        if ($discoveryURL) {
            Write-Log "Discovery Service Full URL: $discoveryURL" -Severity "INFO"

            # Extract only the protocol and domain part of the URL (e.g., https://subdomain.domain.TLD)
            if ($discoveryURL -match "^(https?://[^/]+)") {
                $baseURL = $matches[1]
                Write-Log "Testing URL Reachability: $baseURL" -Severity "INFO"

                # Test the URL to see if it's reachable
                try {
                    $response = Invoke-WebRequest -Uri $baseURL -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                    if ($response.StatusCode -eq 200) {
                        Write-Log "URL is reachable: $baseURL" -Severity "INFO"
                        Add-Result -Category "MDM Enrollment State" -Test "URL Reachability" -Result "Success" -Details "URL is reachable: $baseURL"
                    } else {
                        Write-Log "URL responded but with unexpected status code: $($response.StatusCode)" -Severity "WARNING"
                        Add-Result -Category "MDM Enrollment State" -Test "URL Reachability" -Result "Warning" -Details "URL responded with status code: $($response.StatusCode)"
                    }
                } catch {
                    Write-Log "URL is not reachable: $baseURL. Error: $($_.Exception.Message)" -Severity "ERROR"
                    Add-Result -Category "MDM Enrollment State" -Test "URL Reachability" -Result "Failure" -Details "URL is not reachable: $baseURL. Error: $($_.Exception.Message)"
                }
            } else {
                Write-Log "Unable to parse base URL from discovery URL: $discoveryURL" -Severity "WARNING"
                Add-Result -Category "MDM Enrollment State" -Test "URL Parsing" -Result "Failure" -Details "Unable to parse base URL from discovery URL: $discoveryURL"
            }
        } else {
            Write-Log "No Discovery Service URL found for MDM Enrollment." -Severity "WARNING"
            Add-Result -Category "MDM Enrollment State" -Test "Discovery URL Check" -Result "Failure" -Details "No Discovery Service URL found for MDM Enrollment."
        }
    } catch {
        Write-Log "Error validating MDM Enrollment State: $($_.Exception.Message)" -Severity "ERROR"
        Add-Result -Category "MDM Enrollment State" -Test "Enrollment State Validation" -Result "Failure" -Details "Error validating MDM Enrollment State: $($_.Exception.Message)"
    }
}

# Function to check if the AWCM is communicating successfully with the server
function Check-AWCMCommunication {
    param (
        [Parameter(Mandatory = $false)]
        [string]$logFolderPath = "C:\ProgramData\AirWatch\UnifiedAgent\Logs"
    )

    # Get today's date in the required format to match the log naming convention
    $todayDateString = (Get-Date).ToString("yyyyMMdd")
    $logFileName = "AWACMClient-$todayDateString.log"
    $logFilePath = Join-Path -Path $logFolderPath -ChildPath $logFileName

    # Initialize variables to keep track of communication success
    $successfulResponses = 0
    $postRequests = 0
    $lastSuccessfulTimestamp = $null

    # Check if the log file exists
    if (-not (Test-Path -Path $logFilePath)) {
        Write-Log "Log file not found at path: $logFilePath" -Severity "ERROR"
        Add-Result -Category "AWCM Communication Check" -Test "Log File Existence" -Result "Failure" -Details "Log file not found at path: $logFilePath"
        return
    }

    Write-Log "Analyzing communication logs from file: $logFilePath" -Severity "INFO"

    # Read the log file line by line and analyze content
    Get-Content -Path $logFilePath | ForEach-Object {
        $line = $_

        # Check for successful server response
        if ($line -match 'Received response from server') {
            $successfulResponses++
            # Extract the timestamp of the successful response
            if ($line -match '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})') {
                $lastSuccessfulTimestamp = [datetime]::ParseExact($matches[1], "yyyy-MM-ddTHH:mm:ss", $null)
            }
        }

        # Check for sending post to AWCM server
        if ($line -match 'Sending Post AWCM Server Url') {
            $postRequests++
        }
    }

    # Determine the result of the communication check
    if ($successfulResponses -gt 0 -and $postRequests -gt 0) {
        Write-Log "Device is communicating successfully with the server." -Severity "INFO"
        Write-Log "Successful Responses: $successfulResponses, Post Requests: $postRequests" -Severity "INFO"
        Add-Result -Category "AWCM Communication Check" -Test "Successful Communication" -Result "Success" -Details "Successful Responses: $successfulResponses, Post Requests: $postRequests"

        # Check if the last successful response was within the last 8 hours
        if ($lastSuccessfulTimestamp -ne $null) {
            $timeDifference = (Get-Date) - $lastSuccessfulTimestamp
            if ($timeDifference.TotalHours -le 8) {
                Write-Log "Last successful communication was within the past 8 hours." -Severity "INFO"
                Add-Result -Category "AWCM Communication Check" -Test "Recent Communication Check" -Result "Success" -Details "Last successful communication was within the past 8 hours"
            } else {
                Write-Log "Warning: Last successful communication was more than 8 hours ago." -Severity "WARNING"
                Add-Result -Category "AWCM Communication Check" -Test "Recent Communication Check" -Result "Failure" -Details "Last successful communication was more than 8 hours ago"
            }
        } else {
            Write-Log "Warning: Unable to determine the timestamp of the last successful communication." -Severity "WARNING"
            Add-Result -Category "AWCM Communication Check" -Test "Timestamp Check" -Result "Failure" -Details "Unable to determine the timestamp of the last successful communication"
        }
    } else {
        Write-Log "No successful communication detected in the log file." -Severity "WARNING"
        Write-Log "Successful Responses: $successfulResponses, Post Requests: $postRequests" -Severity "WARNING"
        Add-Result -Category "AWCM Communication Check" -Test "Successful Communication" -Result "Failure" -Details "Successful Responses: $successfulResponses, Post Requests: $postRequests"
    }
}

# Function to Print Script Summary with Enable/Disable Option
function Print-FinalSummary {
    param (
        [Parameter(Mandatory = $false)]
        [switch]$UseGridView,  # Switch to enable Out-GridView for interactive display
        [switch]$SaveToFile,   # Switch to save the summary to a text file
        [string]$FilePath = "C:\Logs\MDM_WNS_Summary.txt"  # Default path for the output file if $SaveToFile is specified
    )

    Write-Host "**************************************" -ForegroundColor Cyan
    Write-Host "Script Execution Final Summary:" -ForegroundColor Cyan
    Write-Host "**************************************" -ForegroundColor Cyan

    if ($global:outputResults.Count -gt 0) {
        if ($UseGridView) {
            # Display the summary in Out-GridView for better user interactivity
            $global:outputResults | Out-GridView -Title "MDM & WNS Validation Summary"
        } elseif ($SaveToFile) {
            # Save the summary to a text file
            $global:outputResults | Format-Table -AutoSize | Out-String | Set-Content -Path $FilePath
            Write-Host "Summary has been saved to $FilePath" -ForegroundColor Green
        } else {
            # Default: Display in the console
            $global:outputResults | Format-Table -AutoSize
        }
    } else {
        Write-Host "No results to display." -ForegroundColor Yellow
    }
}

# Function to add the result for each category and store it in the results array
function Add-Result {
    param (
        [string]$Category,    # The category of the test (e.g., "OMA-DM Connection Info")
        [string]$Test,        # The specific test being performed (e.g., "Last Successful Connection")
        [string]$Result,      # The result of the test (e.g., "Success" or "Failure")
        [string]$Details = "" # Optional details about the test result
    )

    # Ensure $global:outputResults is treated as an array
    if ($null -eq $global:outputResults) {
        $global:outputResults = @()
    }

    # Add a custom object to the output results array
    $global:outputResults += [PSCustomObject]@{
        Category = $Category
        Test     = $Test
        Result   = $Result
        Details  = $Details
    }

    # Debug to verify if the result was added correctly
    #Write-Host "Add-Result Called: Added Result to outputResults (Total Count Now: $($global:outputResults.Count))" -ForegroundColor Green
}




# Main Script Execution with Performance Measurement
$global:scriptError = $false

# Initialize an array to store all the results for each function at the script level
$global:outputResults = @()



# Modify the call to return the activeMDMID value
$activeMDMID = Measure-ScriptSection -code {
    # Return value from the function
    return Get-MDMEnrollmentDetails
} -sectionName "Get MDM Enrollment Details"

Measure-ScriptSection -code { Get-OMADMConnectionInfo -activeMDMID $activeMDMID } -sectionName "OMA-DM Connection Info"
Measure-ScriptSection -code { Validate-ScheduledTasks -activeMDMID $activeMDMID } -sectionName "Validate Scheduled Tasks"
Measure-ScriptSection -code { Get-WorkspaceONEHubStatus } -sectionName "WorkspaceONE Hub Status"
Measure-ScriptSection -code { Get-WNSStatus -activeMDMID $activeMDMID } -sectionName "WNS Status"
Measure-ScriptSection -code { Check-AWCMCommunication } -sectionName "Check AWCM Communication"
Measure-ScriptSection -code { Validate-MDMEnrollmentState -activeMDMID $activeMDMID } -sectionName "Validate MDM Enrollment State"
if ($includeMDMEventLogs) {
    Measure-ScriptSection -code { Get-MDMEventLogs } -sectionName "Get MDM Diagnostic Event Logs"
}
Measure-ScriptSection -code { Get-CategorizedEventLogs } -sectionName "Categorized MDM Event Logs"
Measure-ScriptSection -code { Validate-MDMCertificates } -sectionName "Validate MDM Certificates"

Print-FinalSummary -UseGridView

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
