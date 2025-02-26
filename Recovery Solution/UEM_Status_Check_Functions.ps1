<#
DISCLAIMER:
This script is provided "as is," without warranty of any kind, express or implied, 
including but not limited to the warranties of merchantability, fitness for a 
particular purpose, and noninfringement. In no event shall the authors or 
copyright holders be liable for any claim, damages, or other liability, whether 
in an action of contract, tort, or otherwise, arising from, out of, or in 
connection with the script or the use or other dealings in the script.

This script is designed for educational and operational use. Use it at your 
own risk and ensure you understand its implications before running in 
production environments.
===============================================================================

===============================================================================
Script Name: UEM_Status_Check_Functions.ps1
Description: Provides UEM related status queries

Author:      Grischa Ernst
Date:        2025-01-01
Version:     1.0
===============================================================================

#>

function Get-DeviceEnrollmentUUID {
    [CmdletBinding()]
    param(
        # Optional: The folder where the logs are stored.
        [Parameter(Mandatory=$false)]
        [string]$LogFolder = "C:\ProgramData\AirWatch\UnifiedAgent\Logs"
    )

    Write-Host "Searching for the latest DeviceEnrollment log in $LogFolder..." -ForegroundColor Cyan

    # Get all log files matching the pattern.
    $files = Get-ChildItem -Path $LogFolder -Filter "DeviceEnrollment-*.log" -ErrorAction SilentlyContinue

    if (-not $files) {
        Write-Warning "No DeviceEnrollment log files found in $LogFolder."
        return $null
    }

    # Sort the files by LastWriteTime descending and select the latest one.
    $latestFile = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Host "Latest log file found: $($latestFile.FullName)" -ForegroundColor Green

    # Read all lines from the latest log file.
    try {
        $lines = Get-Content -Path $latestFile.FullName -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to read the log file $($latestFile.FullName): $($_.Exception.Message)"
        return $null
    }

    # Define the regular expression pattern to extract the DeviceUUID.
    $pattern = 'FetchDeviceUuidAsync\s*=\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'

    # Search each line until we find a match.
    foreach ($line in $lines) {
        if ($line -match $pattern) {
            Write-Host "DeviceUUID found: $($matches[1])" -ForegroundColor Green
            return $matches[1]
        }
    }

    Write-Warning "No DeviceUUID found in the latest log file: $($latestFile.FullName)."
    return $null
}

#Get Workspace ONE Intelligent Hub Version
function Get-WorkspaceOneIntelligentHubVersion {
    [CmdletBinding()]
    Param()

    # Attempt to retrieve the 'Workspace ONE Intelligent Hub Installer' product from WMI
    $installer = Get-WmiObject -Class win32_Product -Filter "Name='Workspace ONE Intelligent Hub Installer'" -ErrorAction SilentlyContinue

    if (-not $installer) {
        Write-Verbose "Workspace ONE Intelligent Hub Installer not found on this machine."
        return $null
    }

    # Cast the version string to a System.Version object for easier comparison
    $version = [Version]$installer.Version

    # Compare the version to 24.10.0.0
    if ($version -ge [Version]"24.10.0.0") {
        # Paths for 24.10 or higher
        $paths = [PSCustomObject]@{
            Version              = $version.ToString()
            HubScheduledTaskName = "WorkspaceONEHubHealthMonitoringJob"
            SFDScheduledTaskPath = "\Workspace ONE\SfdAgent\"
        }
    }
    else {
        # Paths for older versions
        $paths = [PSCustomObject]@{
            Version              = $version.ToString()
            HubScheduledTaskName = "VMwareHubHealthMonitoringJob"
            SFDScheduledTaskPath = "\VMware\SfdAgent\"
        }
    }

    $SFDinstaller = Get-WmiObject -Class win32_Product -Filter "Name LIKE '%SFD%'" -ErrorAction SilentlyContinue

    $General = @{
        HubVersion       = $installer.Version
        DeviceUUID       = Get-DeviceEnrollmentUUID
        SFDVersion       = $SFDinstaller.Version
        SFDQueuedInstallations = (Get-ChildItem "HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\Queue").count
    }

    $GroupMapping = @{
        HubVersion       = "HUB Information"
        SFDVersion       = "HUB Information"
        SFDQueuedInstallations  = "HUB Information"
        DeviceUUID  = "HUB Information"
    }

    Insert-GeneralData -DbPath $DbPath -Data $General -GroupMapping $GroupMapping

    return $paths
}


# Function to Get Workspace ONE Intelligent Hub Status
function Get-WorkspaceONEHubStatus {
    [CmdletBinding()]
    param(
        # Path to the SQLite database file.
        [Parameter(Mandatory = $true)]
        [string]$DbPath
    )

    Write-Log "Retrieving Workspace ONE Intelligent Hub Status..." -Severity "INFO"

    $IntelligentHubError = $false
    
    # ----------------------------
    # Log Service Status
    # ----------------------------
    # Define the services to check
    $services = @(
        @{ Name = "AirWatchService"; DisplayName = "AirWatch Service" }
    )

    foreach ($service in $services) {
        $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Log "$($service.DisplayName): Running" -Severity "INFO"
            $data = @{
                Test      = "$($service.DisplayName) Service Status"
                Result    = "Running"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
        }
        else {
            Write-Log "$($service.DisplayName): Not Running" -Severity "WARNING"
            $IntelligentHubError = $true
            $data = @{
                Test      = "$($service.DisplayName) Service Status"
                Result    = "Not Running"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
        }
    }

    # ----------------------------
    # Log Process Status
    # ----------------------------
    # Define processes to check 
    $processes = @("AWACMClient", "AwWindowsIpc")
    foreach ($process in $processes) {
        $running = Get-Process -Name $process -ErrorAction SilentlyContinue
        if ($running) {
            Write-Log "$process Process: Running" -Severity "INFO"
            $data = @{
                Test      = "$process Process Status"
                Result    = "Running"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
        }
        else {
            Write-Log "$process Process: Not Running" -Severity "WARNING"
            $IntelligentHubError = $true
            $data = @{
                Test      = "$process Process Status"
                Result    = "Not Running"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
        }
    }

    # ----------------------------
    # Log Scheduled Task Status
    # ----------------------------
    # Check if WorkspaceONEHubHealthMonitoringJob ran successfully in last 24 hours.
    $HubInformation = Get-WorkspaceOneIntelligentHubVersion
    $taskName = "$($HubInformation.HubScheduledTaskName)"
    $taskPath = "\"  # Root folder of the Task Scheduler library

    try {
        $task = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
        if ($null -ne $task) {
            $lastRunTime = $task.LastRunTime
            $lastTaskResult = $task.LastTaskResult  # Typically 0 means success
            $time24HoursAgo = (Get-Date).AddHours(-24)
    
            Write-Log "Task '$taskName' last ran at: $lastRunTime (Result: $lastTaskResult)" -Severity "INFO"
            $data = @{
                Test      = "Scheduled Task '$taskName' Last Run"
                Result    = "Last Run Time: $lastRunTime, Result: $lastTaskResult"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
    
            if (($lastRunTime -lt $time24HoursAgo) -or ($lastTaskResult -ne 0)) {
                Write-Log "Task '$taskName' did not run successfully in the last 24 hours, or the result was non-zero." -Severity "WARNING"
                $IntelligentHubError = $true
                $data = @{
                    Test      = "Scheduled Task '$taskName' Failure"
                    Result    = "Did not run successfully within 24 hours or non-zero result"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
    
                Write-Log "Attempting to start scheduled task '$taskName' again..." -Severity "INFO"
                Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath
                Start-Sleep -Seconds 5
    
                $retries = 0
                $maxRetries = 12  # total wait time = maxRetries * 10 seconds = 120s
                while ($retries -lt $maxRetries) {
                    $currentTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Get-ScheduledTaskInfo
                    if ($currentTask.State -eq 'Running') {
                        Write-Log "Scheduled task '$taskName' is still running..." -Severity "INFO"
                        Start-Sleep -Seconds 10
                        $retries++
                    }
                    else {
                        if ($currentTask.LastTaskResult -eq 0) {
                            Write-Log "Scheduled task '$taskName' completed successfully after being re-triggered." -Severity "INFO"
                            $IntelligentHubError = $false
                            $data = @{
                                Test      = "Scheduled Task '$taskName' Retry Success"
                                Result    = "Completed successfully"
                                Timestamp = (Get-Date).ToString("s")
                            }
                            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
                        }
                        else {
                            Write-Log "Scheduled task '$taskName' completed with a non-zero result: $($currentTask.LastTaskResult)" -Severity "WARNING"
                            $IntelligentHubError = $true
                            $data = @{
                                Test      = "Scheduled Task '$taskName' Retry Failure"
                                Result    = "Completed with result: $($currentTask.LastTaskResult)"
                                Timestamp = (Get-Date).ToString("s")
                            }
                            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
                        }
                        break
                    }
                }
    
                if ($retries -eq $maxRetries) {
                    Write-Log "Scheduled task '$taskName' did not finish within the allowed time ([$($maxRetries*10)]s)." -Severity "ERROR"
                    $data = @{
                        Test      = "Scheduled Task '$taskName' Timeout"
                        Result    = "Did not finish within allowed time"
                        Timestamp = (Get-Date).ToString("s")
                    }
                    Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
                }
            }
            else {
                Write-Log "Task '$taskName' ran successfully within the last 24 hours." -Severity "INFO"
                $data = @{
                    Test      = "Scheduled Task '$taskName' Status"
                    Result    = "Ran successfully within the last 24 hours"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
            }
        }
        else {
            Write-Log "Scheduled Task '$taskName' not found in path '$taskPath'." -Severity "WARNING"
            $IntelligentHubError = $true
            $data = @{
                Test      = "Scheduled Task '$taskName' Not Found"
                Result    = "Task not found in path '$taskPath'"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
        }
    }
    catch {
        Write-Log "Error retrieving scheduled task '$taskName': $($_.Exception.Message)" -Severity "ERROR"
        $IntelligentHubError = $true
        $data = @{
            Test      = "Scheduled Task '$taskName' Error"
            Result    = "Error: $($_.Exception.Message)"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
    }

    # ----------------------------
    # Log AirWatch Agent Status
    # ----------------------------
    try {
        $agentStatus = Get-ItemPropertyValue "HKLM:\SOFTWARE\AIRWATCH" -Name AgentStatus -ErrorAction SilentlyContinue
        if ($agentStatus -like "Started*") {
            $agentStartTime = Get-Date $agentStatus.Substring(8)
            Write-Log "AirWatch Agent Started at $agentStartTime" -Severity "INFO"
            $data = @{
                Test      = "AirWatch Agent Status"
                Result    = "Started at $agentStartTime"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
        }
        else {
            Write-Log "AirWatch Agent not started." -Severity "WARNING"
            $IntelligentHubError = $true
            $data = @{
                Test      = "AirWatch Agent Status"
                Result    = "Not Started"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
        }
    }
    catch {
        Write-Log "Unable to retrieve AirWatch Agent Status: $($_.Exception.Message)" -Severity "ERROR"
        $IntelligentHubError = $true
        $data = @{
            Test      = "AirWatch Agent Status"
            Result    = "Error: $($_.Exception.Message)"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data
    }

    # ----------------------------
    # Final Summary Logging
    # ----------------------------
    Write-Log "Get-WorkspaceONEHubStatus result is: $($IntelligentHubError)" -Severity "INFO"
    $data = @{
        Test      = "Workspace ONE Intelligent Hub Overall Status"
        Result    = if ($IntelligentHubError) { "Error detected" } else { "Success" }
        Timestamp = (Get-Date).ToString("s")
    }
    Insert-SQLiteRecord -DbPath $DbPath -TableName "HUB" -Data $data

    Update-ErrorColumn -DbPath $DbPath -ErrorColumn "HUB_Errorcount" -IsError $IntelligentHubError
    # --- Increase HUB_Errorcount in the Errors table ---
    

    Write-Log "Updated HUB_Errorcount to $newHubErrorCount in the Errors table." -Severity "INFO"


    return $IntelligentHubError
}

function Test-SFDTasks {
    param(
        # Ensure you have a parameter or variable for the DB path:
        [Parameter(Mandatory=$true)]
        [string]$DbPath
    )

    # Initialize the error flag for SFD tasks.
    $SFD_ErrorFlag = $false

    # Location of the scheduled tasks
    $HubInformation = Get-WorkspaceOneIntelligentHubVersion
    $taskPath = "$($HubInformation.SFDScheduledTaskPath)"

    # Define tasks, their display names, and required run frequency (in minutes)
    $tasksToCheck = @(
        [PSCustomObject]@{
            Name             = "Software Distribution Queue Task"
            FrequencyMinutes = 240  # 4 hours
        },
        [PSCustomObject]@{
            Name             = "Install Validation Task"
            FrequencyMinutes = 240  # 4 hours
        },
        [PSCustomObject]@{
            Name             = "Check Required Apps"
            FrequencyMinutes = 15   # 15 minutes
        }
    )

    foreach ($taskDefinition in $tasksToCheck) {
        $taskName = $taskDefinition.Name
        $frequencyMins = $taskDefinition.FrequencyMinutes

        # Attempt to retrieve the task info
        try {
            $taskInfo = Get-ScheduledTask -TaskName "$($taskName)" -TaskPath $taskPath | Get-ScheduledTaskInfo
        }
        catch {
            Write-Log "Task '$taskName' could not be found in path '$taskPath' (Error: $($_.Exception.Message))" -Severity "WARNING"
            # Log non-compliance for this task.
            $data = @{
                Test      = "SFD Task: $taskName"
                Result    = "Not Found"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "SFD" -Data $data
            $SFD_ErrorFlag = $true
            continue
        }

        if (-not $taskInfo) {
            Write-Log "Task '$taskName' not found in path '$taskPath'." -Severity "WARNING"
            $data = @{
                Test      = "SFD Task: $taskName"
                Result    = "Not Found"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "SFD" -Data $data
            $SFD_ErrorFlag = $true
            continue
        }

        $lastRunTime = $taskInfo.LastRunTime
        $lastTaskResult = $taskInfo.LastTaskResult  # 0 typically indicates success

        Write-Log "Task '$taskName' last ran at: $lastRunTime (Result: $lastTaskResult)" -Severity "INFO"

        # Calculate the threshold time (e.g., 4 hours or 15 minutes ago)
        $thresholdTime = (Get-Date).AddMinutes(-$frequencyMins)
        $taskCompliant = $false

        # Check if the task has run within the expected interval AND last result is 0
        if (($lastRunTime -lt $thresholdTime) -or ($lastTaskResult -ne 0)) {

            Write-Log "Task '$taskName' is out of compliance or did not complete successfully. Attempting to start..." -Severity "WARNING"
            Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath

            Start-Sleep -Seconds 2

            # Poll for completion
            $maxRetries = 10
            $retry = 0
            $taskCompleted = $false

            while ($retry -lt $maxRetries) {
                Start-Sleep -Seconds 10
                $currentTaskInfo = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Get-ScheduledTaskInfo
                if ($currentTaskInfo.State -ne 'Running') {
                    $taskCompleted = $true
                    if ($currentTaskInfo.LastTaskResult -eq 0) {
                        Write-Log "Task '$taskName' completed successfully after re-trigger." -Severity "INFO"
                        $taskCompliant = $true
                    }
                    else {
                        Write-Log "Task '$taskName' re-triggered but completed with a non-zero result: $($currentTaskInfo.LastTaskResult)" -Severity "ERROR"
                        $taskCompliant = $false
                    }
                    break
                }
                else {
                    Write-Log "Task '$taskName' is still running..." -Severity "INFO"
                }
                $retry++
            }

            if (-not $taskCompleted) {
                Write-Log "Task '$taskName' did not finish within the allowed wait period." -Severity "WARNING"
                $taskCompliant = $false
            }
        }
        else {
            Write-Log "Task '$taskName' ran successfully within the last $frequencyMins minute(s)." -Severity "INFO"
            $taskCompliant = $true
        }

        # Log an entry in the SFD table for this task with its compliance status.
        $taskStatusData = @{
            Test      = "SFD Task: $taskName"
            Result    = if ($taskCompliant) { "Compliant" } else { "Non-compliant" }
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "SFD" -Data $taskStatusData

        # If any task is non-compliant, flag the overall SFD error.
        if (-not $taskCompliant) {
            $SFD_ErrorFlag = $true
        }
    }

    # --- Update the Errors table for SFD_Errorcount ---
    # This call updates the SFD_Errorcount in the Errors table:
    Update-ErrorColumn -DbPath $DbPath -ErrorColumn "SFD_Errorcount" -IsError $SFD_ErrorFlag

    # Log an overall summary record to the SFD table.
    $overallSFDData = @{
        Test      = "SFD Tasks Overall Status"
        Result    = if ($SFD_ErrorFlag) { "Non-compliant" } else { "Compliant" }
        Timestamp = (Get-Date).ToString("s")
    }
    Insert-SQLiteRecord -DbPath $DbPath -TableName "SFD" -Data $overallSFDData

    Write-Log "SFD task status updated in Errors table and summary logged to SFD table." -Severity "INFO"

    # Optionally, return the overall compliance flag.
    return $SFD_ErrorFlag
}


function Test-AWCMCommunication {
    param (
        [Parameter(Mandatory = $false)]
        [string]$logFolderPath = "C:\ProgramData\AirWatch\UnifiedAgent\Logs",
        
        # Database path for logging results to the HUB and Errors tables.
        [Parameter(Mandatory = $true)]
        [string]$DbPath
    )

    # Get today's date in the required format to match the log naming convention.
    $todayDateString = (Get-Date).ToString("yyyyMMdd")
    $logFileName = "AWACMClient-$todayDateString.log"
    $logFilePath = Join-Path -Path $logFolderPath -ChildPath $logFileName

    # Initialize counters and timestamp variables.
    $successfulResponses = 0
    $postRequests = 0
    $lastSuccessfulTimestamp = $null

    # Flag for overall AWCM communication failure.
    $AWCM_Error = $false

    # Check if the log file exists.
    if (-not (Test-Path -Path $logFilePath)) {
        Write-Log "Log file not found at path: $logFilePath" -Severity "ERROR"
        $data = @{
            Test      = "AWCM Communication Check - Log File Existence"
            Result    = "Failure: Log file not found at path: $logFilePath"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $data
        # Mark as error and update AWCM_Errorcount later.
        $AWCM_Error = $true
        return
    }

    Write-Log "Analyzing communication logs from file: $logFilePath" -Severity "INFO"
    $data = @{
        Test      = "AWCM Communication Check - Log File Found"
        Result    = "Success: Log file found at $logFilePath"
        Timestamp = (Get-Date).ToString("s")
    }
    Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $data

    # Read the log file line by line and analyze content.
    Get-Content -Path $logFilePath | ForEach-Object {
        $line = $_

        # Check for a successful server response.
        if ($line -match 'Received response from server') {
            $successfulResponses++
            # Extract the timestamp of the successful response.
            if ($line -match '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})') {
                $lastSuccessfulTimestamp = [datetime]::ParseExact($matches[1], "yyyy-MM-ddTHH:mm:ss", $null)
            }
        }

        # Check for sending post to AWCM server.
        if ($line -match 'Sending Post AWCM Server Url') {
            $postRequests++
        }
    }

    # Log the communication counts to the AWCM table.
    $data = @{
        Test      = "AWCM Communication Check - Counts"
        Result    = "Successful Responses: $successfulResponses, Post Requests: $postRequests"
        Timestamp = (Get-Date).ToString("s")
    }
    Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $data

    # Determine the result of the communication check.
    if ($successfulResponses -gt 0 -and $postRequests -gt 0) {
        Write-Log "Device is communicating successfully with the server." -Severity "INFO"
        $data = @{
            Test      = "AWCM Communication Check - Communication Status"
            Result    = "Success: Communication detected (Responses: $successfulResponses, Posts: $postRequests)"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $data

        # Check if the last successful response was within the last 8 hours.
        if ($lastSuccessfulTimestamp -ne $null) {
            $timeDifference = (Get-Date) - $lastSuccessfulTimestamp
            if ($timeDifference.TotalHours -le 8) {
                Write-Log "Last successful communication was within the past 8 hours." -Severity "INFO"
                $data = @{
                    Test      = "AWCM Communication Check - Recent Communication"
                    Result    = "Success: Last successful communication within the past 8 hours"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $data
            }
            else {
                Write-Log "Warning: Last successful communication was more than 8 hours ago." -Severity "WARNING"
                $data = @{
                    Test      = "AWCM Communication Check - Recent Communication"
                    Result    = "Failure: Last successful communication was more than 8 hours ago"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $data
                $AWCM_Error = $true
            }
        }
        else {
            Write-Log "Warning: Unable to determine the timestamp of the last successful communication." -Severity "WARNING"
            $data = @{
                Test      = "AWCM Communication Check - Timestamp"
                Result    = "Failure: Unable to determine last successful communication timestamp"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $data
            $AWCM_Error = $true
        }
    }
    else {
        Write-Log "No successful communication detected in the log file." -Severity "WARNING"
        Write-Log "Successful Responses: $successfulResponses, Post Requests: $postRequests" -Severity "WARNING"
        $data = @{
            Test      = "AWCM Communication Check - Communication Status"
            Result    = "Failure: Successful Responses: $successfulResponses, Post Requests: $postRequests"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $data
        $AWCM_Error = $true
    }

    # --- Update AWCM_Errorcount in the Errors table ---
    # Use Update-ErrorColumn to update only the AWCM_Errorcount column.
    Update-ErrorColumn -DbPath $DbPath -ErrorColumn "AWCM_Errorcount" -IsError $AWCM_Error

    # Log an overall summary entry to the AWCM table.
    $overallData = @{
        Test      = "AWCM Communication Check - Overall Status"
        Result    = if ($AWCM_Error) { "Failure" } else { "Success" }
        Timestamp = (Get-Date).ToString("s")
    }
    Insert-SQLiteRecord -DbPath $DbPath -TableName "AWCM" -Data $overallData

    Write-Log "Check-AWCMCommunication completed. AWCM_Error: $AWCM_Error" -Severity "INFO"
    return $AWCM_Error
}



