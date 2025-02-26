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
Description: Provides OMA-DM and WNS related status queries

Author:      Grischa Ernst
Date:        2025-01-01
Version:     1.0
===============================================================================

#>


function Get-MDMEnrollmentDetails {
    [CmdletBinding()]
    param(
        [string]$ProviderID,
        [string]$DbPath  # Path to the SQLite database (e.g., "C:\Temp\MyAppDB.sqlite")
    )

    Write-Log "Starting retrieval of Current MDM User Output..." -Severity "INFO"

    $MDMError = $false
    $activeMDMID = $null
    
    # Locate the active MDM enrollment key
    $activeMDMID = (Get-ChildItem HKLM:\SOFTWARE\MICROSOFT\ENROLLMENTS -ErrorAction SilentlyContinue |
        Where-Object { $_.GetValue('ProviderId') -eq $ProviderID }).Name | Split-Path -Leaf
    
    if ($activeMDMID) {

        # --- 1) Determine domain-join state ---
        $domainStatus = Get-DomainStatus

        Write-Log "Domain Join States: AADJoined=$($domainStatus.AADJoined) | ADJoined=$($domainStatus.ADJoined) | HybridJoined=$($domainStatus.HybridJoined)" -Severity "INFO"

        # --- 2) Check enrollment details based on join state ---
        if ($domainStatus.AADJoined -and -not $domainStatus.ADJoined) {
            # =============== AAD-Joined Logic ===============
            Write-Log "Device is AAD Joined (not AD Joined). Checking Enrollment UPN..." -Severity "INFO"
            try {
                $upn = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\ENROLLMENTS\$activeMDMID" -Name 'UPN' -ErrorAction Stop
            
                if (-not $upn) {
                    Write-Log "Enrollment UPN was not found or was empty." -Severity "ERROR"
                    Set-RegistryValue -Category "MDM User Status" -Name "User UPN" -Value "ERROR" 
                    # Log detailed status to OMADM table
                    $omadmData = @{
                        Test      = "User UPN"
                        Result    = "ERROR"
                        Timestamp = (Get-Date).ToString("s")
                    }
                    Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $omadmData
                    $MDMError = $true
                }
                else {
                    Write-Log "Enrollment UPN is set to: $upn" -Severity "INFO"
                    Set-RegistryValue -Category "MDM User Status" -Name "User UPN" -Value $upn 
                    $omadmData = @{
                        Test      = "User UPN"
                        Result    = "$upn"
                        Timestamp = (Get-Date).ToString("s")
                    }
                    Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $omadmData
                }
            }
            catch {
                Write-Log "Failed to retrieve Enrollment UPN for AAD-joined device: $($_.Exception.Message)" -Severity "ERROR"
                $MDMError = $true
            }
        }
        else {
            # =============== AD-Joined or Hybrid-Joined Logic ===============
            Write-Log "Device is AD Joined or Hybrid Joined. Proceeding with SID-based MDM checks..." -Severity "INFO"

            try {
                # Grab the SID from the enrollment key
                $activeMDMUserSID = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\MICROSOFT\ENROLLMENTS\$activeMDMID" -Name 'SID' -ErrorAction Stop
                Set-RegistryValue -Category "MDM User Status" -Name "User SID" -Value $activeMDMUserSID 
                $omadmData = @{
                    Test      = "User SID"
                    Result    = "$activeMDMUserSID"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $omadmData

                New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
            
                # Check if the user's SID is currently loaded under HKU
                $registryTest = Test-Path "HKU:\$activeMDMUserSID"
                if ($registryTest) {
                    # Attempt to read from the Volatile Environment
                    $MDMUserName = Get-ItemPropertyValue -Path "HKU:\$activeMDMUserSID\Volatile Environment" -Name 'USERNAME' -ErrorAction SilentlyContinue
                    $userProfilePath = Get-ItemPropertyValue -Path "HKU:\$activeMDMUserSID\Volatile Environment" -Name 'USERPROFILE' -ErrorAction SilentlyContinue
                    $userProfileTest = Test-Path $userProfilePath
            
                    Write-Log "Found HKU:\$activeMDMUserSID loaded. USERNAME=$MDMUserName, USERPROFILE=$userProfilePath" -Severity "INFO"
                    Set-RegistryValue -Category "MDM User Status" -Name "Username" -Value $MDMUserName 


                    if (-not $MDMUserName -or -not $userProfileTest) {
                        Write-Log "Either USERNAME or USERPROFILE is not set/valid. Possibly a local account or ephemeral session." -Severity "WARNING"
                        $MDMUserName = Get-UserNameFromSid -Sid $activeMDMUserSID
                        Set-RegistryValue -Category "MDM User Status" -Name "Username" -Value "ERROR" 
                    }
                }
                else {
                    Write-Log "HKU:\$activeMDMUserSID is not mounted. Trying .NET lookup..." -Severity "INFO"
                    $MDMUserName = Get-UserNameFromSid -Sid $activeMDMUserSID
                }
            
                if ($MDMUserName) {
                    Write-Log "Resolved user name from SID: $MDMUserName" -Severity "INFO"
                    $omadmData = @{
                        Test      = "Username"
                        Result    = "$MDMUserName"
                        Timestamp = (Get-Date).ToString("s")
                    }
                    Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $omadmData
                }
                else {
                    Write-Log "Could not resolve user name for SID: $activeMDMUserSID" -Severity "WARNING"
                    $omadmData = @{
                        Test      = "Username"
                        Result    = "ERROR"
                        Timestamp = (Get-Date).ToString("s")
                    }
                    Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $omadmData
                    $MDMError = $true
                }
            
            }
            catch {
                Write-Log "Error accessing registry key for Active MDM User SID: $($_.Exception.Message)" -Severity "ERROR"
                $MDMError = $true
            }
        }
    }    
    else {
        Write-Log "No active MDM enrollment found." -Severity "WARNING"
        $MDMError = $true
        $activeMDMID = 0
    }

    Write-Log "Get-MDMEnrollmentDetails result is: $($MDMError)" -Severity "INFO"

    # --- Update the Errors table using Update-ErrorColumn ---
    Update-ErrorColumn -DbPath $dbPath -ErrorColumn "OMADM_Errorcount" -IsError $MDMError

    return $activeMDMID, $MDMError
}

# Function to Validate Scheduled Tasks
function Test-ScheduledTasks {
    param (
        [Parameter(Mandatory = $true)]
        [string]$activeMDMID,
        
        [Parameter(Mandatory = $true)]
        [string]$DbPath
    )

    $ScheduledTaskError = $false

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping Scheduled Task Validation." -Severity "WARNING"
        $ScheduledTaskError = $true
        Write-Log "Test-ScheduledTasks result is: $($ScheduledTaskError)" -Severity "INFO"
        
        # Log overall summary in the TaskScheduler table.
        $summaryData = @{
            Test      = "Scheduled Tasks Overall Status"
            Result    = "Not executed due to missing Active MDM ID"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "TaskScheduler" -Data $summaryData
        
        return $ScheduledTaskError
    }
    else {
        Write-Log "Active MDM ID is $($activeMDMID)" -Severity "INFO"
    }

    Write-Log "Validating scheduled tasks for MDM..." -Severity "INFO"

    # All tasks are expected to run every 8 hours
    $eightHours = 8
    $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$activeMDMID\"
    $tasks = @(
        @{
            Name        = "Schedule #3 created by enrollment client"
            Description = "8-hour sync"
        },
        @{
            Name        = "Schedule to run OMADMClient by client"
            Description = "8-hour sync"
        }
    )

    foreach ($task in $tasks) {
        $isCompliant = $false
        try {
            # Retrieve task information
            $taskInfo = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $task.Name -ErrorAction Stop

            # Log basic task details
            Write-Log "$($task.Description) - Last Runtime: $($taskInfo.LastRunTime)" -Severity "INFO"
            Write-Log "$($task.Description) - Last Result: $($taskInfo.LastTaskResult)" -Severity "INFO"

            # Check if the task's last run was successful
            $isTaskResultOk = ($taskInfo.LastTaskResult -eq 0)

            # Check if the task has run within the last 8 hours
            $timeDifference = (Get-Date) - [datetime]$taskInfo.LastRunTime
            $isTimeCompliance = ($timeDifference.TotalHours -le $eightHours)

            # Combine compliance checks
            $isCompliant = $isTaskResultOk -and $isTimeCompliance

            if (-not $isCompliant) {
                Write-Log "Task '$($task.Name)' is out of compliance. Attempting to start..." -Severity "WARNING"
                Start-ScheduledTask -TaskName $task.Name -TaskPath $taskPath

                # Optional brief wait before checking status again
                Start-Sleep -Seconds 2

                # Poll for completion
                $maxRetries = 10
                $retry = 0
                $taskFinished = $false

                while ($retry -lt $maxRetries) {
                    Start-Sleep -Seconds 10
                    $currentTaskInfo = Get-ScheduledTask -TaskName $task.Name -TaskPath $taskPath | Get-ScheduledTaskInfo
                    if ($currentTaskInfo.State -eq 'Running') {
                        Write-Log "Task '$($task.Name)' is still running..." -Severity "INFO"
                    }
                    else {
                        Write-Log "Task '$($task.Name)' has finished running. Checking final result..." -Severity "INFO"
                        if ($currentTaskInfo.LastTaskResult -eq 0) {
                            Write-Log "Task '$($task.Name)' completed successfully after re-trigger." -Severity "INFO"
                            $isCompliant = $true
                        }
                        else {
                            Write-Log "Task '$($task.Name)' completed with a non-zero result: $($currentTaskInfo.LastTaskResult)" -Severity "WARNING"
                            $ScheduledTaskError = $true
                        }
                        $taskFinished = $true
                        break
                    }
                    $retry++
                }

                if (-not $taskFinished) {
                    Write-Log "Task '$($task.Name)' did not finish within the expected time." -Severity "WARNING"
                    $ScheduledTaskError = $true
                }
            }
            else {
                Write-Log "Task '$($task.Name)' is in compliance (recent successful run within 8 hours)." -Severity "INFO"
            }
        }
        catch {
            Write-Log "Task '$($task.Name)' not found or could not be retrieved. $($_.Exception.Message)" -Severity "WARNING"
            $ScheduledTaskError = $true
        }

        # Prepare task-specific log data for the TaskScheduler table.
        $taskStatusData = @{
            Test      = "Scheduled Task: $($task.Name) - $($task.Description)"
            Result    = if ($isCompliant) {
                            "Compliant. LastRunTime: $($taskInfo.LastRunTime), LastResult: $($taskInfo.LastTaskResult)"
                        }
                        else {
                            "Non-compliant. LastRunTime: $($taskInfo.LastRunTime), LastResult: $($taskInfo.LastTaskResult)"
                        }
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "TaskScheduler" -Data $taskStatusData
    }

    # Log an overall summary in the TaskScheduler table.
    $overallData = @{
        Test      = "Scheduled Tasks Overall Status"
        Result    = if ($ScheduledTaskError) { "Non-compliant" } else { "Compliant" }
        Timestamp = (Get-Date).ToString("s")
    }
    Insert-SQLiteRecord -DbPath $DbPath -TableName "TaskScheduler" -Data $overallData

    Write-Log "Test-ScheduledTasks result is: $($ScheduledTaskError)" -Severity "INFO"
    return $ScheduledTaskError
}

function Get-CategorizedEventLogs {
    [CmdletBinding()]
    param(
        # Path to the SQLite database file for logging.
        [Parameter(Mandatory = $true)]
        [string]$DbPath
    )

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

            # Log individual counts to the Eventlog table.
            $dataError = @{
                Test      = "MDM Event Log - Error Count"
                Result    = "$errorCount"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "Eventlog" -Data $dataError

            $dataWarning = @{
                Test      = "MDM Event Log - Warning Count"
                Result    = "$warningCount"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "Eventlog" -Data $dataWarning

            $dataInfo = @{
                Test      = "MDM Event Log - Information Count"
                Result    = "$infoCount"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "Eventlog" -Data $dataInfo
        }
        else {
            Write-Log "No events found in $eventLogName." -Severity "INFO"
            $dataNone = @{
                Test      = "MDM Event Log - No Events Found"
                Result    = "0"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "Eventlog" -Data $dataNone
        }
    }
    catch {
        Write-Log "Error accessing MDM Event Logs: $($_.Exception.Message)" -Severity "ERROR"
        $dataErrorAccess = @{
            Test      = "MDM Event Log - Access Error"
            Result    = "$($_.Exception.Message)"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "Eventlog" -Data $dataErrorAccess
    }
}

function Get-WNSStatus {
    [CmdletBinding()]
    param (
        # The active MDM ID used in the registry paths.
        [Parameter(Mandatory = $true)]
        [string]$activeMDMID,
        # Path to the SQLite database for logging.
        [Parameter(Mandatory = $true)]
        [string]$DbPath
    )

    # Initialize overall error flag for WNS tests.
    $WNS_ErrorFlag = $false

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping WNS Status Retrieval." -Severity "WARNING"
        $data = @{
            Test      = "WNS Status - Active MDM ID Check"
            Result    = "Failure: Active MDM ID not available."
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $data
        $WNS_ErrorFlag = $true
        return
    }

    Write-Log "Retrieving WNS status..." -Severity "INFO"

    try {
        $pushPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$activeMDMID\Push"
        
        # --- Retrieve and log WNS Service Status ---
        $wnsService = Get-Service -Name WpnService -ErrorAction SilentlyContinue
        $wnsServiceStatus = $wnsService.Status
        Write-Log "WNS Service Status: $wnsServiceStatus" -Severity "INFO"
        $data = @{
            Test      = "WNS Service Status Check"
            Result    = if ($wnsServiceStatus -eq "Running") { "Success: WNS Service is running" } else { "Failure: WNS Service is not running" }
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $data
        if ($wnsServiceStatus -ne "Running") { $WNS_ErrorFlag = $true }

        # --- Retrieve and log WNS Status (registry) ---
        $wnsStatus = Get-ItemPropertyValue -Path $pushPath -Name Status -ErrorAction SilentlyContinue
        Write-Log "WNS Status: $wnsStatus" -Severity "INFO"
        $data = @{
            Test      = "WNS Status Check"
            Result    = if ($wnsStatus -eq 0) { "Success: WNS Status indicates no issues (Status Code: $wnsStatus)" } else { "Failure: WNS Status indicates an issue (Status Code: $wnsStatus)" }
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $data
        if ($wnsStatus -ne 0) { $WNS_ErrorFlag = $true }

        # --- Retrieve and log Last Renewal Time ---
        $lastRenewalTimeRaw = Get-ItemPropertyValue -Path $pushPath -Name LastRenewalTime -ErrorAction SilentlyContinue
        $lastRenewalTime = [DateTime]::FromFileTime($lastRenewalTimeRaw)
        Write-Log "Last Renewal Time: $lastRenewalTime" -Severity "INFO"
        $data = @{
            Test      = "WNS Last Renewal Time Check"
            Result    = "Last Renewal Time: $lastRenewalTime"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $data

        # --- Retrieve and log Channel Expiry Time ---
        $channelExpiryTimeRaw = Get-ItemPropertyValue -Path $pushPath -Name ChannelExpiryTime -ErrorAction SilentlyContinue
        $channelExpiryTime = [DateTime]::FromFileTime($channelExpiryTimeRaw)
        Write-Log "Channel Expiry Time: $channelExpiryTime" -Severity "INFO"
        $data = @{
            Test      = "WNS Channel Expiry Time Check"
            Result    = "Channel Expiry Time: $channelExpiryTime"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $data

        # --- Determine Overall WNS Health ---
        if ((Get-Date) -le $channelExpiryTime -and $wnsStatus -eq 0 -and $wnsServiceStatus -eq "Running") {
            Write-Log "WNS Channel is active and healthy" -Severity "INFO"
            $data = @{
                Test      = "WNS Channel Health Check"
                Result    = "Success: WNS Channel is active and healthy."
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $data
        }
        else {
            Write-Log "WNS Channel is expired or unhealthy" -Severity "WARNING"
            $data = @{
                Test      = "WNS Channel Health Check"
                Result    = "Failure: WNS Channel is expired or unhealthy."
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $data
            $WNS_ErrorFlag = $true
        }
    }
    catch {
        Write-Log "Error retrieving WNS status: $($_.Exception.Message)" -Severity "ERROR"
        $data = @{
            Test      = "WNS Status Retrieval Error"
            Result    = "Failure: Error retrieving WNS status: $($_.Exception.Message)"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $data
        $WNS_ErrorFlag = $true
    }

    # --- Update the Errors table for WNS_Errorcount ---
    # Use Update-ErrorColumn to update only the WNS_Errorcount column based on the overall WNS error flag.
    Update-ErrorColumn -DbPath $DbPath -ErrorColumn "WNS_Errorcount" -IsError $WNS_ErrorFlag

    # Optionally, log an overall summary to the WNS table.
    $overallData = @{
        Test      = "WNS Status Overall Status"
        Result    = if ($WNS_ErrorFlag) { "Failure" } else { "Success" }
        Timestamp = (Get-Date).ToString("s")
    }
    Insert-SQLiteRecord -DbPath $DbPath -TableName "WNS" -Data $overallData

    Write-Log "Get-WNSStatus completed. Overall WNS error flag: $WNS_ErrorFlag" -Severity "INFO"
    return $WNS_ErrorFlag
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
    }
    catch {
        Write-Log "Error converting timestamp: $($_.Exception.Message)" -Severity "ERROR"
        return $null
    }
}

function Get-OMADMConnectionInfo {
    [CmdletBinding()]
    param (
        # Active MDM ID used in registry paths.
        [Parameter(Mandatory = $true)]
        [string]$activeMDMID,
        # Path to the SQLite database file for logging.
        [Parameter(Mandatory = $true)]
        [string]$DbPath
    )

    # Initialize overall error flag for connection info.
    # Note: Errors from the service checks below will only be logged,
    #       but not count toward the overall OMADM connection error.
    $OMADM_ErrorFlag = $false

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping OMA-DM Connection Info." -Severity "WARNING"
        $data = @{
            Test      = "OMA-DM Connection Info - Active MDM ID Check"
            Result    = "Failure: Active MDM ID not available"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
        # For connection info, mark error and exit.
        $OMADM_ErrorFlag = $true
        # Update the Errors table accordingly.
        Update-ErrorColumn -DbPath $DbPath -ErrorColumn "OMADM_Errorcount" -IsError $OMADM_ErrorFlag
        return
    }

    Write-Log "Starting retrieval of OMA-DM Connection Information..." -Severity "INFO"

    # --- Log the service checks (do not affect overall OMADM error flag) ---
    $servicesToCheck = @(
        @{ Name = "Winmgmt"; DisplayName = "Windows Management Instrumentation (WMI)" },
        @{ Name = "dmwappushservice"; DisplayName = "Device Management Wireless Application Protocol Push" },
        @{ Name = "UsoSvc"; DisplayName = "Update Orchestrator Service" },
        @{ Name = "WpnService"; DisplayName = "Windows Push Notification Service" }
    )

    foreach ($service in $servicesToCheck) {
        try {
            $serviceStatus = (Get-Service -Name $service.Name -ErrorAction SilentlyContinue).Status
            if ($serviceStatus -eq "Running") {
                Write-Log "$($service.DisplayName) is running." -Severity "INFO"
                $data = @{
                    Test      = "OMA-DM Service Check - $($service.DisplayName) Status"
                    Result    = "Success: $($service.DisplayName) is running"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
            }
            else {
                Write-Log "$($service.DisplayName) is not running." -Severity "WARNING"
                $data = @{
                    Test      = "OMA-DM Service Check - $($service.DisplayName) Status"
                    Result    = "Failure: $($service.DisplayName) is not running"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
                # Note: Service check errors are logged but not counted in $OMADM_ErrorFlag.
            }
        }
        catch {
            Write-Log "Error retrieving status for $($service.DisplayName): $($_.Exception.Message)" -Severity "ERROR"
            $data = @{
                Test      = "OMA-DM Service Check - $($service.DisplayName) Status"
                Result    = "Failure: Error retrieving status: $($_.Exception.Message)"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
        }
    }

    # --- Connection Information Retrieval ---
    $connInfoPath = "HKLM:\Software\Microsoft\Provisioning\OMADM\Accounts\$activeMDMID\Protected\ConnInfo"

    try {
        # Retrieve the last connection attempt timestamp.
        $lastAttemptTimestamp = Get-ItemPropertyValue -Path $connInfoPath -Name ServerLastAccessTime -ErrorAction SilentlyContinue

        if ($lastAttemptTimestamp) {
            $lastAttemptDate = Convert-TimestampToDate -timestamp $lastAttemptTimestamp
            Write-Log "Last connection attempt: $lastAttemptDate" -Severity "INFO"
            $data = @{
                Test      = "OMA-DM Connection Info - Last Connection Attempt"
                Result    = "Success: Last connection attempt was at $lastAttemptDate"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
        }
        else {
            Write-Log "No record of the last connection attempt found." -Severity "WARNING"
            $data = @{
                Test      = "OMA-DM Connection Info - Last Connection Attempt"
                Result    = "Failure: No record of last connection attempt found"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
            $OMADM_ErrorFlag = $true
        }

        # Retrieve the last successful connection timestamp.
        $lastSuccessTimestamp = Get-ItemPropertyValue -Path $connInfoPath -Name ServerLastSuccessTime -ErrorAction SilentlyContinue

        if ($lastSuccessTimestamp) {
            $lastSuccessDate = Convert-TimestampToDate -timestamp $lastSuccessTimestamp
            Write-Log "Last successful connection: $lastSuccessDate" -Severity "INFO"
            $data = @{
                Test      = "OMA-DM Connection Info - Last Successful Connection"
                Result    = "Success: Last successful connection was at $lastSuccessDate"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data

            # Calculate time since the last successful connection.
            $timeDifference = (Get-Date) - $lastSuccessDate
            Write-Log "Time since last successful connection: $($timeDifference.Days) days and $($timeDifference.Hours) hours" -Severity "INFO"
            $data = @{
                Test      = "OMA-DM Connection Info - Time Since Last Successful Connection"
                Result    = "Elapsed time: $($timeDifference.Days) days, $($timeDifference.Hours) hours"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data

            if ($timeDifference.TotalHours -le 8) {
                $data = @{
                    Test      = "OMA-DM Connection Info - Recent Successful Connection"
                    Result    = "Success: Last successful connection was within the past 8 hours"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
            }
            else {
                $data = @{
                    Test      = "OMA-DM Connection Info - Recent Successful Connection"
                    Result    = "Failure: Last successful connection was more than 8 hours ago"
                    Timestamp = (Get-Date).ToString("s")
                }
                Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
                $OMADM_ErrorFlag = $true
            }
        }
        else {
            Write-Log "No record of the last successful connection found." -Severity "WARNING"
            $data = @{
                Test      = "OMA-DM Connection Info - Last Successful Connection"
                Result    = "Failure: No record of last successful connection found"
                Timestamp = (Get-Date).ToString("s")
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
            $OMADM_ErrorFlag = $true
        }
    }
    catch {
        Write-Log "Error retrieving OMA-DM Connection Info: $($_.Exception.Message)" -Severity "ERROR"
        $data = @{
            Test      = "OMA-DM Connection Info Retrieval"
            Result    = "Failure: Error retrieving OMA-DM Connection Info: $($_.Exception.Message)"
            Timestamp = (Get-Date).ToString("s")
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "OMADM" -Data $data
        $OMADM_ErrorFlag = $true
    }

    # --- Update Errors Table for OMA-DM Connection ---
    # Update only the OMADM_Errorcount column in the Errors table based on the overall connection error flag.
    Update-ErrorColumn -DbPath $DbPath -ErrorColumn "OMADM_Errorcount" -IsError $OMADM_ErrorFlag

    Write-Log "Get-OMADMConnectionInfo completed. Overall OMA-DM Connection error flag: $OMADM_ErrorFlag" -Severity "INFO"
    return $OMADM_ErrorFlag
}
