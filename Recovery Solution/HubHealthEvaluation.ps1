param(
    # Specify the MDM provider ID (e.g., "AirwatchMDM", "IntuneMDM", "CustomMDM")
    [ValidateSet("AirwatchMDM", "IntuneMDM", "CustomMDM")]
    [Parameter(HelpMessage = "Specify the MDM provider ID (e.g., 'AirwatchMDM', 'IntuneMDM', 'CustomMDM')")]
    [string]$providerID = "AirwatchMDM",

    # Path to the log file where script output will be saved
    [Parameter(HelpMessage = "Path to the log file where script output will be saved")]
    [string]$logFilePath = "C:\Windows\UEMRecovery\Logs\MDM_Validation_Log.txt",

    #The Hash value for this script, to make sure the script was not modified
    [Parameter(Mandatory = $true)]
    [string]$ExpectedHash,

    #Switch parameter to enable the automatic re-enollment when an error was detected
    [Parameter(HelpMessage = "Switch parameter to enable the automatic re-enollment when an error was detected")]
    [switch]$EnableReEnrollment

)

#Set the install directory
$DestinationPath = "C:\Windows\UEMRecovery"

# Define the path to the SQLLite Data
$SQLPath = "$($DestinationPath)\SQLite"

# Adjust the path to where your System.Data.SQLite.dll is located and unblock files
Get-ChildItem -Path $SQLPath | Unblock-File

# Add the .dll to work with SQLite
Add-Type -Path "$($SQLPath)\System.Data.SQLite.dll"

# Define the SQLite database file path
$dbPath = "$DestinationPath\HUBHealth.sqlite"


#Import Functions
. "$PSScriptRoot\UEM_Status_Check_Functions.ps1"
. "$PSScriptRoot\OMA-DM_Status_Check_Functions.ps1"
. "$PSScriptRoot\General_Functions.ps1"
. "$PSScriptRoot\SQL_Functions.ps1"

# Start PowerShell Transcript to Capture Console Output
if ($logFilePath) {
    Stop-Transcript -ErrorAction SilentlyContinue
    if (Test-Path $logFilePath) {
        Remove-Item -Path $logFilePath -Force
    }
    
    Start-Transcript -Path $logFilePath -NoClobber -ErrorAction SilentlyContinue
}


###################################################################
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
# Start Script 

if (Wait-ForSQLiteUnlock -DbPath $dbPath -MaxAttempts 10 -DelaySeconds 1) {
    # Proceed with your database operations.
}
else {
    Write-Error "Cannot proceed because the database remains locked."
}



#Get the configuration
$Configuration = Read-SQLiteTable -DbPath $dbPath -TableName "Configurations"

#Cleanup the DB 
$CleanupTables = @("OMADM", "HUB", "SFD", "WNS", "Eventlog", "TaskScheduler")
Foreach ($Table in $CleanupTables) {
    Remove-SQLiteOldEntries -DbPath $dbPath -TableName "OMADM" -Days '14'
}

# Check if Device is enrolled (Workspace ONE and OMA-DM)
$EnrollmentStatus = Test-EnrollmentStatus

#Run the different health checks
if ($EnrollmentStatus.PSObject.Properties.Value -notcontains $false) {

    $MDMEnrollmentErrorStatus = Get-MDMEnrollmentDetails -ProviderID "AirwatchMDM" -DbPath $dbPath
    Test-ScheduledTasks -activeMDMID $MDMEnrollmentErrorStatus[0]  -DbPath $dbPath
    Get-WorkspaceONEHubStatus -DbPath $dbPath
    Get-CategorizedEventLogs -DbPath $dbPath
    Get-WNSStatus -DbPath $dbPath -activeMDMID $MDMEnrollmentErrorStatus[0]
    Get-OMADMConnectionInfo -DbPath $dbPath -activeMDMID $MDMEnrollmentErrorStatus[0]
    Test-AWCMCommunication -DbPath $dbPath 
    Test-SFDTasks -DbPath $dbPath
    Test-ProxyConfig -DbPath $dbPath
    Test-PendingReboot -DbPath $dbPath
    Test-SFDTasks -DbPath $dbPath


    # CHeck if the Error Threshold is reached
    $ErrorThresholdReached = Test-ErrorsThreshold -DbPath $dbPath -IndividualThreshold ($Configuration.IndividualThreshold) -OverallThreshold ($Configuration.OverallThreshold)

    # Generate HTML report and save it in the HUB Logs folder
    New-HTMLReport -DbPath $dbPath -OutputFile "C:\ProgramData\AirWatch\UnifiedAgent\Logs\DeviceHealthStatus.html"

    if ($ErrorThresholdReached -eq $True) {
        if (($Configuration.AutoReEnrollment) -eq "True") {
            if (($Configuration.EnrollmentDefinedDate) -eq "True") {
                
                # Create scheduled task to re-enroll the device

                # Variables
                $taskName = "WorkspaceONE Autorepair"
                $timeOfDay = "$($Configuration.EnrollmentTime)"
                $dayOfWeek = "$($Configuration.EnrollmentDay)"

                # Check for Existing Scheduled Task
                if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                    Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                }

                if (($Configuration.ReEnrollmentWithCurrentUserSession) -eq "False") {
                    $scriptPath = "$($DestinationPath)\recovery.ps1"

                    # Set the task to run as loggendin User
                    $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -LogonType Interactive
                }
                elseif (($Configuration.ReEnrollmentWithCurrentUserSession) -eq "True") {
                    $scriptPath = "$($DestinationPath)\UEM_automatic_reenrollment.ps1"

                    # Set the task to run as SYSTEM
                    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
                }
                    
                # Create an action to run the PowerShell script
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ExpectedHash $expectedHash"

                # Create a trigger to run the task weekly on the specified day and time
                $trigger = New-ScheduledTaskTrigger -Weekly -At $timeOfDay -DaysOfWeek $dayOfWeek


                # Register the task
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal

                Write-Output "Scheduled task '$taskName' created successfully to run every $dayOfWeek at $timeOfDay."

                
            }
            else {
                # Execute the reenrollment process
                $RecoveryScript = "-NoProfile -ExecutionPolicy Bypass -File `"$($PSScriptRoot)\recovery.ps1`""
        
                try {
                    Write-Log "Starting execution of recovery.ps1." "INFO"
                   
                    # Start the process and capture the process object.
                    $proc = Start-Process powershell.exe -ArgumentList $RecoveryScript -Wait -PassThru -ErrorAction Stop
                   
                    # Check the exit code.
                    if ($proc.ExitCode -eq 0) {
                        Write-Log "recovery.ps1 executed successfully. Exit code: $($proc.ExitCode)" "INFO"
                    }
                    else {
                        Write-Log "recovery.ps1 failed with exit code: $($proc.ExitCode)" "ERROR"
                        exit $proc.ExitCode
                    }
                }
                catch {
                    Write-Log "Error executing recovery.ps1: $_" "ERROR"
                    exit 1
                }
            }
        }
    }
}
else {
    if (($Configuration.EnrollIfNotEnrolled) -eq "True") {
        if (($Configuration.EnrollmentDefinedDate) -eq "True") {
                
            # Create scheduled task to re-enroll the device

            # Variables
            $taskName = "WorkspaceONE Autorepair"
            $timeOfDay = "$($Configuration.EnrollmentTime)"
            $dayOfWeek = "$($Configuration.EnrollmentDay)"

            # Check for Existing Scheduled Task
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }

            if (($Configuration.EnrollDuringCurrentUserSession) -eq "False") {
                $scriptPath = "$($DestinationPath)\recovery.ps1"

                # Set the task to run as loggendin User
                $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -LogonType Interactive
            }
            elseif (($Configuration.EnrollDuringCurrentUserSession) -eq "True") {
                $scriptPath = "$($DestinationPath)\UEM_automatic_reenrollment.ps1"

                # Set the task to run as SYSTEM
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
            }
                
            # Create an action to run the PowerShell script
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ExpectedHash $expectedHash"

            # Create a trigger to run the task weekly on the specified day and time
            $trigger = New-ScheduledTaskTrigger -Weekly -At $timeOfDay -DaysOfWeek $dayOfWeek


            # Register the task
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal

            Write-Output "Scheduled task '$taskName' created successfully to run every $dayOfWeek at $timeOfDay."

            
        }
        else {
            # Execute the reenrollment process
            $RecoveryScript = "-NoProfile -ExecutionPolicy Bypass -File `"$($PSScriptRoot)\recovery.ps1`""
    
            try {
                Write-Log "Starting execution of recovery.ps1." "INFO"
               
                # Start the process and capture the process object.
                $proc = Start-Process powershell.exe -ArgumentList $RecoveryScript -Wait -PassThru -ErrorAction Stop
               
                # Check the exit code.
                if ($proc.ExitCode -eq 0) {
                    Write-Log "recovery.ps1 executed successfully. Exit code: $($proc.ExitCode)" "INFO"
                }
                else {
                    Write-Log "recovery.ps1 failed with exit code: $($proc.ExitCode)" "ERROR"
                    exit $proc.ExitCode
                }
            }
            catch {
                Write-Log "Error executing recovery.ps1: $_" "ERROR"
                exit 1
            }
        }
    }
}

