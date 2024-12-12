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

# Function to add the result for each category and store it in the results array
function Add-Result {
    param (
        [string]$Category, # The category of the test (e.g., "OMA-DM Connection Info")
        [string]$Test, # The specific test being performed (e.g., "Last Successful Connection")
        [string]$Result, # The result of the test (e.g., "Success" or "Failure")
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


# Function to Get the Active MDM Enrollment Details
function Get-MDMEnrollmentDetails {
    Write-Log "Starting retrieval of Current MDM User Output..." -Severity "INFO"

    $MDMError = $false

    $activeMDMID = (Get-ChildItem HKLM:\SOFTWARE\MICROSOFT\ENROLLMENTS | Where-Object {
            $_.GetValue('ProviderId') -eq $providerID
        }).Name | Split-Path -Leaf

    if ($activeMDMID) {
        Add-Result -Category "MDM Enrollment Details" -Test "MDM Enrollment Found" -Result "Success" -Details "Active MDM ID found: $activeMDMID"

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

            # Log results
            Write-Log "Current active MDM ID:            $activeMDMID" -Severity "INFO"
            Add-Result -Category "MDM Enrollment Details" -Test "Current Active MDM ID" -Result "Success" -Details "MDM ID: $activeMDMID"

            Write-Log "Current active MDM UserSID:       $activeMDMUserSID" -Severity "INFO"
            Add-Result -Category "MDM Enrollment Details" -Test "Current Active MDM UserSID" -Result "Success" -Details "User SID: $activeMDMUserSID"

            Write-Log "User SID in Registry:             $registryTest" -Severity "INFO"
            if ($registryTest -eq $true) {
                Add-Result -Category "MDM Enrollment Details" -Test "User SID in Registry" -Result "Success" -Details "User SID exists in Registry: $registryTest"
            }
            else {
                Add-Result -Category "MDM Enrollment Details" -Test "User SID in Registry" -Result "Failure" -Details "User SID does not exist in Registry."
                $MDMError = $true
            }

            if ($MDMUserName) {
                Write-Log "Current active MDM Username:      $MDMUserName" -Severity "INFO"
                Add-Result -Category "MDM Enrollment Details" -Test "MDM Username" -Result "Success" -Details "Username: $MDMUserName"
            }
            else {
                Add-Result -Category "MDM Enrollment Details" -Test "MDM Username" -Result "Failure" -Details "No Username found"
                $MDMError = $true
            }

            Write-Log "User Profile Path still active:   $userProfileTest" -Severity "INFO"
            if ($userProfileTest -eq $true) {
                Add-Result -Category "MDM Enrollment Details" -Test "User Profile Path Active" -Result "Success" -Details "User Profile Path Active: $userProfileTest"
            }
            else {
                Add-Result -Category "MDM Enrollment Details" -Test "User Profile Path Active" -Result "Failure" -Details "User Profile Path is not active."
                $MDMError = $true
            }

        }
        catch {
            Write-Log "Error accessing registry key for Active MDM User SID: $($_.Exception.Message)" -Severity "ERROR"
            Add-Result -Category "MDM Enrollment Details" -Test "Registry Access Error" -Result "Failure" -Details "Error accessing registry key for Active MDM User SID: $($_.Exception.Message)"
            $global:scriptError = $true
            $MDMError = $true
        }
    }
    else {
        Write-Log "No active MDM enrollment found." -Severity "WARNING"
        Add-Result -Category "MDM Enrollment Details" -Test "MDM Enrollment Found" -Result "Failure" -Details "No active MDM enrollment found."
        $MDMError = $true
        $activeMDMID = 0
    }

    return $activeMDMID, $MDMError
}


# Function to Validate Scheduled Tasks
function Test-ScheduledTasks {
    param ([string]$activeMDMID)

    $ScheduledTaskError = $False

    if (-not $activeMDMID) {
        Write-Log "Active MDM ID is not available. Skipping Scheduled Task Validation." -Severity "WARNING"
        Add-Result -Category "Scheduled Task Validation" -Test "Active MDM ID Check" -Result "Failure" -Details "Active MDM ID is not available. Skipping Scheduled Task Validation."
        $ScheduledTaskError = $true
        return $ScheduledTaskError
    }

    Write-Log "Validating scheduled tasks for MDM..." -Severity "INFO"

    $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$activeMDMID\"
    $tasks = @(
        @{ Name = "Schedule #3 created by enrollment client"; Description = "8-hour sync" },
        @{ Name = "Schedule to run OMADMClient by client"; Description = "Main sync task" }
    )

    foreach ($task in $tasks) {
        try {
            # Retrieve task information
            $taskInfo = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $task.Name -ErrorAction Stop
            
            # Log task details
            Write-Log "$($task.Description) - Last Runtime: $($taskInfo.LastRunTime)" -Severity "INFO"
            Write-Log "$($task.Description) - Last Result: $($taskInfo.LastTaskResult)" -Severity "INFO"
            
            # Determine if the task ran successfully
            if ($taskInfo.LastTaskResult -eq 0) {
                Add-Result -Category "Scheduled Task Validation" -Test "$($task.Description) Status" -Result "Success" -Details "Task ran successfully. Last Runtime: $($taskInfo.LastRunTime)"
            }
            else {
                Add-Result -Category "Scheduled Task Validation" -Test "$($task.Description) Status" -Result "Failure" -Details "Task failed or had issues. Last Result Code: $($taskInfo.LastTaskResult)"
                $ScheduledTaskError = $true
            }

            # Check if the task has run in the last 8 hours (for the 8-hour sync task)
            if ($task.Description -eq "8-hour sync") {
                $timeDifference = (Get-Date) - [datetime]$taskInfo.LastRunTime
                if ($timeDifference.TotalHours -le 8) {
                    Add-Result -Category "Scheduled Task Validation" -Test "$($task.Description) Recent Run Check" -Result "Success" -Details "Task has run within the last 8 hours. Last Runtime: $($taskInfo.LastRunTime)"
                }
                else {
                    Add-Result -Category "Scheduled Task Validation" -Test "$($task.Description) Recent Run Check" -Result "Failure" -Details "Task has not run within the last 8 hours. Last Runtime: $($taskInfo.LastRunTime)"
                    $ScheduledTaskError = $true
                }
            }
        }
        catch {
            # Log the task retrieval failure and add result to the summary
            Write-Log "Task '$($task.Name)' not found or could not be retrieved." -Severity "WARNING"
            Add-Result -Category "Scheduled Task Validation" -Test "$($task.Description) Retrieval" -Result "Failure" -Details "Task '$($task.Name)' not found or could not be retrieved."
            $ScheduledTaskError = $true
        }
    }

    return $ScheduledTaskError
}

# Function to Get Workspace ONE Intelligent Hub Status
function Get-WorkspaceONEHubStatus {
    Write-Log "Retrieving Workspace ONE Intelligent Hub Status..." -Severity "INFO"

    $IntelligentHubError = $False
    
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
        }
        else {
            Write-Log "$($service.DisplayName): Not Running" -Severity "WARNING"
            Add-Result -Category "Workspace ONE Hub Status" -Test "$($service.DisplayName) Status" -Result "Failure" -Details "$($service.DisplayName) is not running"
            $IntelligentHubError = $True
        }
    }

    # Define processes to check
    $processes = @("VMwareHubHealthMonitoring", "AWACMClient", "AwWindowsIpc")
    foreach ($process in $processes) {
        $running = Get-Process -Name $process -ErrorAction SilentlyContinue
        if ($running) {
            Write-Log "$process Process: Running" -Severity "INFO"
            Add-Result -Category "Workspace ONE Hub Status" -Test "$process Process Check" -Result "Success" -Details "$process is running"
        }
        else {
            Write-Log "$process Process: Not Running" -Severity "WARNING"
            Add-Result -Category "Workspace ONE Hub Status" -Test "$process Process Check" -Result "Failure" -Details "$process is not running"
            $IntelligentHubError = $True
        }
    }

    # Check the AirWatch Agent Status
    try {
        $agentStatus = Get-ItemPropertyValue "HKLM:\SOFTWARE\AIRWATCH" -Name AgentStatus -ErrorAction SilentlyContinue
        if ($agentStatus -like "Started*") {
            $agentStartTime = Get-Date $agentStatus.Substring(8)
            Write-Log "AirWatch Agent Started at $agentStartTime" -Severity "INFO"
            Add-Result -Category "Workspace ONE Hub Status" -Test "AirWatch Agent Status" -Result "Success" -Details "AirWatch Agent started at $agentStartTime"
        }
        else {
            Write-Log "AirWatch Agent not started." -Severity "WARNING"
            Add-Result -Category "Workspace ONE Hub Status" -Test "AirWatch Agent Status" -Result "Failure" -Details "AirWatch Agent not started"
            $IntelligentHubError = $True
        }
    }
    catch {
        Write-Log "Unable to retrieve AirWatch Agent Status." -Severity "ERROR"
        Add-Result -Category "Workspace ONE Hub Status" -Test "AirWatch Agent Status Retrieval" -Result "Failure" -Details "Unable to retrieve AirWatch Agent Status: $($_.Exception.Message)"
        $IntelligentHubError = $True
    }

    # Debug log to verify that results are being added
    Write-Log "Current Output Results: $($global:outputResults.Count) entries" -Severity "INFO"

    return $IntelligentHubError
}



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

} catch {
    Write-Error "An error occurred during hash validation or script execution: $_"
    exit 1
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

            Write-Output "Logged-in users:"
            $loggedInUsers | ForEach-Object { Write-Output $_ }
            $usersession = $true
        }
        else {
            Write-Output "No users are currently logged in."
            $usersession = $false
        }
    }
    catch {
        Write-Error "An error occurred while checking logged-in users: $_"
    }
    return $usersession
}


if(Get-UserLoggedIn -eq $false) {

    #Get the MDM ernollment error status
    $MDMEnrollmentErrorStatus = Get-MDMEnrollmentDetails
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

}
else { break }

