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
Script Name: ws1_autorepair.ps1
Description: Validates the Workspace ONE environment by checking MDM enrollment, 
scheduled tasks, and Workspace ONE services. Automatically triggers recovery 
if issues are detected.

Author:      Grischa Ernst
Date:        2024-12-12
Version:     1.2
===============================================================================

USAGE:
.\ws1_autorepair.ps1 -providerID "AirwatchMDM" -logFilePath "C:\Logs\Log.txt" 
                     -ExpectedHash "<HashValue>"
===============================================================================

PARAMETERS:
- providerID: Specifies the MDM provider (default: AirwatchMDM).
- logFilePath: Path for saving logs (default: C:\Windows\UEMRecovery\Logs\MDM_WNS_Validation_Log.txt).
- ExpectedHash: Expected SHA-256 hash of the script for integrity verification.
===============================================================================

NOTES:
- Requires administrative privileges to execute.
- Automatically triggers `recovery.ps1` if validation fails.
- Logs are created at the specified `logFilePath` for troubleshooting.
===============================================================================

===============================================================================
Changelog: 
1.0 - published
1.1 - Bugfixing + added AD and AAD support
1.2 - updated reference for Workspace ONE Intelligent HUB 24.10 and newer
    - Included auto remediation for Scheduled Tasks
#>


param(
    # Specify the MDM provider ID (e.g., "AirwatchMDM", "IntuneMDM", "CustomMDM")
    [ValidateSet("AirwatchMDM", "IntuneMDM", "CustomMDM")]
    [Parameter(HelpMessage = "Specify the MDM provider ID (e.g., 'AirwatchMDM', 'IntuneMDM', 'CustomMDM')")]
    [string]$providerID = "AirwatchMDM",

    # Path to the log file where script output will be saved
    [Parameter(HelpMessage = "Path to the log file where script output will be saved")]
    [string]$logFilePath = "C:\Windows\UEMRecovery\Logs\MDM_WNS_Validation_Log.txt",

    [Parameter(Mandatory = $true)]
    [string]$ExpectedHash

)


# Start PowerShell Transcript to Capture Console Output
if ($logFilePath) {
    Stop-Transcript -ErrorAction SilentlyContinue
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


#Check the Domain Join status
function Get-DomainStatus {
    [CmdletBinding()]
    param()

    try {
        # Gather dsregcmd output and trim each line
        $dsregLines = dsregcmd /status | ForEach-Object { $_.Trim() }
    }
    catch {
        Write-Error "Failed to run 'dsregcmd /status': $_"
        return
    }

    # Convert only lines containing " : " into Name/Value pairs
    $dsregPairs = $dsregLines |
    Where-Object { $_ -match ' : ' } |
    ConvertFrom-String -PropertyNames 'Name', 'Value' -Delimiter ' : '

    # Create a hashtable for quick lookups (e.g., $hash["AzureAdJoined"])
    $hash = @{}
    foreach ($item in $dsregPairs) {
        $hash[$item.Name] = $item.Value
    }

    # Booleans for each relevant status
    $AADJoined = ($hash["AzureAdJoined"] -eq 'YES')
    $ADJoined = ($hash["DomainJoined"] -eq 'YES')
    $HybridJoined = $AADJoined -and $ADJoined

    # Return status as a structured object
    [PSCustomObject]@{
        AADJoined    = $AADJoined
        ADJoined     = $ADJoined
        HybridJoined = $HybridJoined
    }
}

function Get-UserNameFromSid {
    param(
        [Parameter(Mandatory)]
        [string]$Sid
    )
    try {
        $sidObj    = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount])

        # $ntAccount.Value is usually "DOMAIN\Username" or "COMPUTERNAME\Username"
        # We'll split on the first backslash and return only the username part.
        $parts = $ntAccount.Value -split '\\', 2
        return $parts[1]  # Just the username
    }
    catch {
        # If translation fails for any reason, return $null (or handle differently).
        Write-Warning "Failed to translate SID [$Sid] to a username. Error: $($_.Exception.Message)"
        return $null
    }
}


function Get-MDMEnrollmentDetails {
    [CmdletBinding()]
    param(
        [string]$ProviderID
    )

    Write-Log "Starting retrieval of Current MDM User Output..." -Severity "INFO"

    $MDMError = $false
    $activeMDMID = $null
    
    # Locate the active MDM enrollment key
    $activeMDMID = (Get-ChildItem HKLM:\SOFTWARE\MICROSOFT\ENROLLMENTS -ErrorAction SilentlyContinue | Where-Object { $_.GetValue('ProviderId') -eq $ProviderID }).Name | Split-Path -Leaf
    
    if ($activeMDMID) {

        # --- 1) Determine domain-join state ---
        $domainStatus = Get-DomainStatus

        # For demonstration/logging:
        Write-Log "Domain Join States: AADJoined=$($domainStatus.AADJoined) | ADJoined=$($domainStatus.ADJoined) | HybridJoined=$($domainStatus.HybridJoined)" -Severity "INFO"

        # --- 2) If AAD joined *only*, check enrollment UPN. Otherwise, fall back to SID checks ---
        if ($domainStatus.AADJoined -and -not $domainStatus.ADJoined) {
            # =============== AAD-Joined Logic ===============
            Write-Log "Device is AAD Joined (not AD Joined). Checking Enrollment UPN..." -Severity "INFO"
            try {
                # Example: read the UPN from somewhere in the registry or from the dsregcmd data
                # (Replace 'SomeRegistryPath' / 'SomeValueName' with your actual location)
                $upn = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\ENROLLMENTS\$activeMDMID" -Name 'UPN' -ErrorAction Stop
            
                if (-not $upn) {
                    Write-Log "Enrollment UPN was not found or was empty." -Severity "ERROR"
                    $MDMError = $true
                }
                else {
                    Write-Log "Enrollment UPN is set to: $upn" -Severity "INFO"
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
                New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
            
                # Check if the user's SID is currently loaded under HKU
                $registryTest = Test-Path "HKU:\$activeMDMUserSID"
                if ($registryTest) {
                    # Attempt to read from the Volatile Environment
                    $MDMUserName = Get-ItemPropertyValue -Path "HKU:\$activeMDMUserSID\Volatile Environment" -Name 'USERNAME' -ErrorAction SilentlyContinue
                    $userProfilePath = Get-ItemPropertyValue -Path "HKU:\$activeMDMUserSID\Volatile Environment" -Name 'USERPROFILE' -ErrorAction SilentlyContinue
                    $userProfileTest = Test-Path $userProfilePath
            
                    Write-Log "Found HKU:\$activeMDMUserSID loaded. USERNAME=$MDMUserName, USERPROFILE=$userProfilePath" -Severity "INFO"
            
                    if (-not $MDMUserName -or -not $userProfileTest) {
                        Write-Log "Either USERNAME or USERPROFILE is not set/valid. Possibly a local account or ephemeral session." -Severity "WARNING"
                        # Attempt fallback .NET resolution
                        $MDMUserName = Get-UserNameFromSid -Sid $activeMDMUserSID
                    }
                }
                else {
                    # If HKU:\SID is not loaded, we definitely need an alternative approach.
                    Write-Log "HKU:\$activeMDMUserSID is not mounted. Trying .NET lookup..." -Severity "INFO"
                    $MDMUserName = Get-UserNameFromSid -Sid $activeMDMUserSID
                }
            
                # Now log the final discovered user name
                if ($MDMUserName) {
                    Write-Log "Resolved user name from SID: $MDMUserName" -Severity "INFO"
                }
                else {
                    Write-Log "Could not resolve user name for SID: $activeMDMUserSID" -Severity "WARNING"
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
    # --- 3) Return what you need to consume outside the function ---
    # Return both the MDM ID and an error state. You can also include domain status, if desired.
    Write-Log "Get-MDMEnrollmentDetails result is: $($MDMError)" -Severity "INFO"
    return $activeMDMID, $MDMError
}

# Function to Validate Scheduled Tasks
function Test-ScheduledTasks {
    param ([string]$activeMDMID)

    $ScheduledTaskError = $False

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping Scheduled Task Validation." -Severity "WARNING"
        $ScheduledTaskError = $true
        Write-Log "Test-ScheduledTasks result is: $($ScheduledTaskError)" -Severity "INFO"
        return $ScheduledTaskError
    }
    else {
        Write-Log "Active MDM ID is $($activeMDMID)" -Severity "INFO"
    }

    Write-Log "Validating scheduled tasks for MDM..." -Severity "INFO"

    # All tasks are expected to run every 8 hours
    $eightHours = 8
    $taskPath   = "\Microsoft\Windows\EnterpriseMgmt\$activeMDMID\"
    $tasks      = @(
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
        try {
            # Retrieve task information
            $taskInfo = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $task.Name -ErrorAction Stop

            # Log task details
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
                $maxRetries   = 10
                $retry        = 0
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
            # Log the task retrieval failure and add result to the summary
            Write-Log "Task '$($task.Name)' not found or could not be retrieved. $($_.Exception.Message)" -Severity "WARNING"
            $ScheduledTaskError = $true
        }
    }

    Write-Log "Test-ScheduledTasks result is: $($ScheduledTaskError)" -Severity "INFO"
    return $ScheduledTaskError
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
            Version             = $version.ToString()
            HubScheduledTaskName   = "WorkspaceONEHubHealthMonitoringJob"
            SFDScheduledTaskPath   = "\Workspace ONE\SfdAgent\"
        }
    }
    else {
        # Paths for older versions
        $paths = [PSCustomObject]@{
            Version             = $version.ToString()
            HubScheduledTaskName   = "VMwareHubHealthMonitoringJob"
            SFDScheduledTaskPath   = "\VMware\SfdAgent\"
        }
    }

    return $paths
}


# Function to Get Workspace ONE Intelligent Hub Status
function Get-WorkspaceONEHubStatus {
    Write-Log "Retrieving Workspace ONE Intelligent Hub Status..." -Severity "INFO"

    $IntelligentHubError = $false
    
    # Define the services to check (remove VMware Hub Health Monitoring Service)
    $services = @(
        @{ Name = "AirWatchService"; DisplayName = "AirWatch Service" }
    )

    foreach ($service in $services) {
        $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Log "$($service.DisplayName): Running" -Severity "INFO"
        }
        else {
            Write-Log "$($service.DisplayName): Not Running" -Severity "WARNING"
            $IntelligentHubError = $true
        }
    }

    # Define processes to check (remove VMwareHubHealthMonitoring)
    $processes = @("AWACMClient", "AwWindowsIpc")
    foreach ($process in $processes) {
        $running = Get-Process -Name $process -ErrorAction SilentlyContinue
        if ($running) {
            Write-Log "$process Process: Running" -Severity "INFO"
        }
        else {
            Write-Log "$process Process: Not Running" -Severity "WARNING"
            $IntelligentHubError = $true
        }
    }

    # Check if WorkspaceONEHubHealthMonitoringJob ran successfully in last 24 hours
    $HubInformation = Get-WorkspaceOneIntelligentHubPaths
    $taskName = "$($HubInformation.HubScheduledTaskName)"
    $taskPath = "\"  # root folder of the Task Scheduler library

    try {
        $task = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
        if ($null -ne $task) {
            # Check Last Run Time and Last Task Result
            $lastRunTime     = $task.LastRunTime
            $lastTaskResult  = $task.LastTaskResult  # Typically 0 means success
            $time24HoursAgo  = (Get-Date).AddHours(-24)
    
            Write-Log "Task '$taskName' last ran at: $lastRunTime (Result: $lastTaskResult)" -Severity "INFO"
    
            # Condition: If not run in last 24 hours OR last run was not successful
            if (($lastRunTime -lt $time24HoursAgo) -or ($lastTaskResult -ne 0)) {
                Write-Log "Task '$taskName' did not run successfully in the last 24 hours, or the result was non-zero." -Severity "WARNING"
                $IntelligentHubError = $true
    
                # Attempt to re-trigger the task
                Write-Log "Attempting to start scheduled task '$taskName' again..." -Severity "INFO"
                Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    
                # Optional brief wait before checking status again
                Start-Sleep -Seconds 5
    
                # Wait loop: poll the task state for a certain amount of time
                $retries     = 0
                $maxRetries  = 12  # total wait time = maxRetries * 10 seconds = 120s
                while ($retries -lt $maxRetries) {
                    $currentTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Get-ScheduledTaskInfo
                    if ($currentTask.State -eq 'Running') {
                        Write-Log "Scheduled task '$taskName' is still running..." -Severity "INFO"
                        Start-Sleep -Seconds 10
                        $retries++
                    }
                    else {
                        # The task is no longer running; check result
                        if ($currentTask.LastTaskResult -eq 0) {
                            Write-Log "Scheduled task '$taskName' completed successfully after being re-triggered." -Severity "INFO"
                            $IntelligentHubError = $false
                        }
                        else {
                            Write-Log "Scheduled task '$taskName' completed with a non-zero result: $($currentTask.LastTaskResult)" -Severity "WARNING"
                            $IntelligentHubError = $true
                        }
                        break
                    }
                }
    
                # If we exit the loop and task is still running, handle as desired
                if ($retries -eq $maxRetries) {
                    Write-Log "Scheduled task '$taskName' did not finish within the allowed time ([$($maxRetries*10)]s)." -Severity "ERROR"
                }
            }
            else {
                # The task ran within last 24 hours with a successful result
                Write-Log "Task '$taskName' ran successfully within the last 24 hours." -Severity "INFO"
            }
        }
        else {
            Write-Log "Scheduled Task '$taskName' not found in path '$taskPath'." -Severity "WARNING"
            $IntelligentHubError = $true
        }
    }
    catch {
        Write-Log "Error retrieving scheduled task '$taskName': $($_.Exception.Message)" -Severity "ERROR"
        $IntelligentHubError = $true
    }

    # Check the AirWatch Agent Status
    try {
        $agentStatus = Get-ItemPropertyValue "HKLM:\SOFTWARE\AIRWATCH" -Name AgentStatus -ErrorAction SilentlyContinue
        if ($agentStatus -like "Started*") {
            $agentStartTime = Get-Date $agentStatus.Substring(8)
            Write-Log "AirWatch Agent Started at $agentStartTime" -Severity "INFO"
        }
        else {
            Write-Log "AirWatch Agent not started." -Severity "WARNING"
            $IntelligentHubError = $true
        }
    }
    catch {
        Write-Log "Unable to retrieve AirWatch Agent Status: $($_.Exception.Message)" -Severity "ERROR"
        $IntelligentHubError = $true
    }

    # Debug log to verify results are being added
    Write-Log "Current Output Results: $($global:outputResults.Count) entries" -Severity "INFO"

    Write-Log "Get-WorkspaceONEHubStatus result is: $($IntelligentHubError)" -Severity "INFO"
    return $IntelligentHubError
}

function Test-SFDTasks {
    param()

    # Location of the scheduled tasks
    $taskPath = "\WorkspaceONE\SfdAgent\"

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
        $taskName       = $taskDefinition.Name
        $frequencyMins  = $taskDefinition.FrequencyMinutes

        # Attempt to retrieve the task info
        try {
            $taskInfo = Get-ScheduledTask -TaskName "$($taskName)" -TaskPath $taskPath | Get-ScheduledTaskInfo
        }
        catch {
            Write-Log "Task '$taskName' could not be found in path '$taskPath' (Error: $($_.Exception.Message))" -Severity "WARNING"
            continue
        }

        if (-not $taskInfo) {
            Write-Log "Task '$taskName' not found in path '$taskPath'." -Severity "WARNING"
            continue
        }

        $lastRunTime     = $taskInfo.LastRunTime
        $lastTaskResult  = $taskInfo.LastTaskResult  # 0 typically indicates success

        Write-Log "Task '$taskName' last ran at: $lastRunTime (Result: $lastTaskResult)" -Severity "INFO"

        # Calculate the threshold time (e.g., 4 hours or 15 minutes ago)
        $thresholdTime = (Get-Date).AddMinutes(-$frequencyMins)

        # Check if the task has run within the expected interval AND last result is 0
        if (($lastRunTime -lt $thresholdTime) -or ($lastTaskResult -ne 0)) {

            Write-Log "Task '$taskName' is out of compliance or did not complete successfully. Attempting to start..." -Severity "WARNING"
            Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath

            # Optional short sleep before checking status again
            Start-Sleep -Seconds 2

            # Poll for completion
            $maxRetries    = 10
            $retry         = 0
            $taskCompleted = $false

            while ($retry -lt $maxRetries) {
                Start-Sleep -Seconds 10
                $currentTaskInfo = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Get-ScheduledTaskInfo
                if ($currentTaskInfo.State -ne 'Running') {
                    $taskCompleted = $true
                    # Check final task result
                    if ($currentTaskInfo.LastTaskResult -eq 0) {
                        Write-Log "Task '$taskName' completed successfully after re-trigger." -Severity "INFO"
                    }
                    else {
                        Write-Log "Task '$taskName' re-triggered but completed with a non-zero result: $($currentTaskInfo.LastTaskResult)" -Severity "ERROR"
                    }
                    break
                }
                else {
                    Write-Log "Task '$taskName' is still running..." -Severity "INFO"
                }
                $retry++
            }

            # If the loop ends and the task is still running
            if (-not $taskCompleted) {
                Write-Log "Task '$taskName' did not finish within the allowed wait period." -Severity "WARNING"
            }
        }
        else {
            Write-Log "Task '$taskName' ran successfully within the last $frequencyMins minute(s)." -Severity "INFO"
        }
    }
}


#Function to check if a user is currently logged in to the device
function Get-UserLoggedIn {
    $usersession = $true
    try {
        # Run the 'query user' command to get session information
        $queryResult = query user 2>$null

        # Check if there is any result from the command
        if ($queryResult) {
            # Parse the result to list logged-in users
            $loggedInUsers = $queryResult | ForEach-Object {
                # Extract the username and other session details
                ($_ -split '\s{2,}')[0]
            }

            Write-Host "Logged-in users:"
            $loggedInUsers | ForEach-Object { Write-host $_ }
            $usersession = $true
        }
        else {
            Write-Host "No users are currently logged in."
            $usersession = $false
        }
    }
    catch {
        Write-Error "An error occurred while checking logged-in users: $_"
    }
    return $usersession
}

####################################################################
#Script Validation

# Path to the current script
$scriptPath = $MyInvocation.MyCommand.Path

try {
    # Calculate the hash of the current script
    $actualHash = Get-FileHash -Path $scriptPath -Algorithm SHA256

    # Compare the actual hash with the expected hash
    if ($actualHash.hash -ne $ExpectedHash) {
        Write-Error "File hash mismatch! The script may have been modified."
        exit 1
    }

    Write-Output "File hash validation passed. Executing the script..."

}
catch {
    Write-Error "An error occurred during hash validation or script execution: $_"
    exit 1
}


####################################################################
# Start Script if no user is logged in

if ((Get-UserLoggedIn) -eq $false) {

    #Get the MDM ernollment error status
    $MDMEnrollmentErrorStatus = Get-MDMEnrollmentDetails -ProviderID $providerID
    $ScheduledTaskErrorStatus = Test-ScheduledTasks -activeMDMID $MDMEnrollmentErrorStatus[0]
    $IntelligentHubErrorStatus = Get-WorkspaceONEHubStatus


    #If an error is detected, re-enroll the device
    if ($MDMEnrollmentErrorStatus[1] -eq $true -or $ScheduledTaskErrorStatus -eq $true -or $IntelligentHubErrorStatus -eq $true) {
        #Gerneate a new password for the local user "UEMEnrollment"
        add-type -AssemblyName System.Web
        $Password = [System.Web.Security.Membership]::GeneratePassword(16, 4) 
        $EncryptedPassword = $Password |  ConvertTo-SecureString -AsPlainText -Force

        #Check if the local user already is created, if not, create the user
        if (!(Get-LocalUser | Where-Object { $_.Name -eq "UEMEnrollment" } -ErrorAction SilentlyContinue)) {

            $NewUserData = @{
                Name                     = "UEMEnrollment"
                Password                 = $EncryptedPassword
                FullName                 = "UEM Enrollment Account"
                Description              = "Do NOT delete this account"
                AccountNeverExpires      = $true
                PasswordNeverExpires     = $true
                UserMayNotChangePassword = $true
            }
            
            New-LocalUser @NewUserData
            
            $LocalAdminGroup = Get-LocalGroup | Where-Object { $_.name -like "admin*" }
            Enable-LocalUser -Name "UEMEnrollment"
            Add-LocalGroupMember -Group $LocalAdminGroup -Member "UEMEnrollment"
        }
        else {
            Set-LocalUser -Name "UEMEnrollment" -Password $EncryptedPassword
            Enable-LocalUser -Name "UEMEnrollment"
            $LocalAdminGroup = Get-LocalGroup | Where-Object { $_.name -like "admin*" }
            Add-LocalGroupMember -Group $LocalAdminGroup -Member "UEMEnrollment"
        }

        #Confogure Autologon for the "installer" user
        $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
        Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "UEMEnrollment" -type String 
        Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$($Password)" -type String
        Set-ItemProperty $RegistryPath 'EnableFirstLogonAnimation' -Value "0" -Type String

        #Skip user prompts after login
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "PrivacyConsentStatus" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "SkipUserOOBE" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "PrivacyConsentStatus" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "SkipUserOOBE" /t REG_DWORD /d 1 /f

        #Register the scheduled task to run the Workspace ONE enrollment after the device is rebooted and logged in as "Installer"
        schtasks.exe /create  /tn "WorkspaceONE Recovery" /RU UEMEnrollment /RP "$($Password)" /sc ONLOGON /tr "powershell -executionpolicy bypass -file C:\Windows\UEMRecovery\recovery.ps1"

        #Create a scheduled task to trigger the screen lock during the autologon 
        $action = New-ScheduledTaskAction -Execute "%windir%\System32\rundll32.exe" -Argument "user32.dll,LockWorkStation"
        $User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users"
        $Task = New-ScheduledTask -Action $action -Principal $User 
        Register-ScheduledTask "Screenlock" -InputObject $Task -Force


        #Trigger restart to restart into the autologon 
        $shutdown = "/r /t 20 /f"
        Start-Process shutdown.exe -ArgumentList $shutdown

    }
    else{
        #No MDM errors found - check SFD status
        Test-SFDTasks
    }

}
else { break }

