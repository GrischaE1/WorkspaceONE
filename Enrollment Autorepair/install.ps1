param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")]
    [string]$DayOfWeek = "Thursday",

    [Parameter(Mandatory = $false)]
    [ValidatePattern("^(?:[01]?\d|2[0-3]):[0-5]\d:[0-5]\d$")]
    [string]$TimeOfDay = "8:00:00",

    [Parameter(Mandatory = $false)]
    [string]$DestinationPath = "C:\Windows\UEMRecovery",

    [Parameter(Mandatory = $true)]
    [string]$ExpectedHash

)

# Variables
$taskName = "WorkspaceONE Autorepair"
$scriptPath = "$($DestinationPath)\ws1_autorepair.ps1"
#$dayOfWeek = "Monday"  # Specify the day of the week (e.g., Monday)
#$timeOfDay = "14:00:00" # Set the time to run the task

# Create an action to run the PowerShell script
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ExpectedHash $expectedHash"

# Create a trigger to run the task weekly on the specified day and time
$trigger = New-ScheduledTaskTrigger -Weekly -At $timeOfDay -DaysOfWeek $dayOfWeek

# Set the task to run as SYSTEM
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

# Register the task
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal

Write-Output "Scheduled task '$taskName' created successfully to run every $dayOfWeek at $timeOfDay."


try {
    # Get the folder where the script is located
    $sourceFolder = Split-Path -Path $MyInvocation.MyCommand.Path

    # Ensure the destination folder exists
    if (-not (Test-Path -Path $DestinationPath)) {
        Write-Output "Destination folder does not exist. Creating it..."
        New-Item -ItemType Directory -Path $DestinationPath -Force
    }

    # Copy files from the script's folder to the destination folder
    Write-Output "Copying files from '$sourceFolder' to '$DestinationPath'..."
    Get-ChildItem -Path $sourceFolder -File | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $DestinationPath -Force
    }

    Write-Output "Files copied successfully to '$DestinationPath'."
} catch {
    Write-Error "An error occurred: $_"
}