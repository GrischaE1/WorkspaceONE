<#
===============================================================================
Script Name: Install.ps1
Description: Sets up the Workspace ONE Recovery Solution by copying files and 
creating a scheduled task for validation and recovery.

Author:      Grischa Ernst
Date:        2024-12-12
Version:     1.0
===============================================================================

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

USAGE:
.\Install.ps1 -ExpectedHash "<HashValue>" -DayOfWeek "Monday" -TimeOfDay "14:00:00" 
              -DestinationPath "C:\Windows\UEMRecovery"
===============================================================================

PARAMETERS:
- DayOfWeek: Specifies the day to run the scheduled task (default: Thursday).
- TimeOfDay: Specifies the time to run the scheduled task (default: 08:00:00).
- DestinationPath: Path where recovery scripts will be stored 
                   (default: C:\Windows\UEMRecovery).
- ExpectedHash: SHA-256 hash of the 'ws1_autorepair.ps1' script to validate its integrity.
===============================================================================

NOTES:
- Ensure administrative privileges before execution.
- Test thoroughly in a non-production environment.
===============================================================================
#>



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


# Check for Existing Scheduled Task
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

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