<#
===============================================================================
Script Name: Install.ps1
Description: Sets up the Workspace ONE Recovery Solution by copying files,
             creating a scheduled task for validation and recovery, and
             inserting credentials into a SQLite database.
Author:      Grischa Ernst
Date:        2024-12-12
Version:     1.1
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
.\Install.ps1 -ExpectedHash "<HashValue>" -DayOfWeek "Monday" -TimeOfDay "14:00:00" `
              -DestinationPath "C:\Windows\UEMRecovery" -IntervalHours 4 `
              -CredentialURL "https://example.com" -CredentialUsername "admin" `
              -CredentialPassword "Secret123" -CredentialOG "ExampleOG"
===============================================================================

PARAMETERS:
- DayOfWeek: Specifies the day to run the scheduled task (default: Thursday).
- TimeOfDay: Specifies the time to run the scheduled task (default: 08:00:00).
- IntervalHours: Specifies an interval (in hours) to run the task. If provided and > 0,
                 the task will run every x hours (ignoring DayOfWeek and TimeOfDay).
- DestinationPath: Path where recovery scripts will be stored 
                   (default: C:\Windows\UEMRecovery).
- ExpectedHash: SHA-256 hash of the 'ws1_autorepair.ps1' script to validate its integrity.
- CredentialURL, CredentialUsername, CredentialPassword, CredentialOG: Values that will be
                   inserted into the Credentials table in the SQLite database.
===============================================================================
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$DestinationPath = "C:\Windows\UEMRecovery",

    #Expected Hash of the HubHealthEvaluation.ps1 file
    [Parameter(Mandatory = $true)]
    [string]$ExpectedHash,

    [Parameter(Mandatory = $true)]
    [string]$CredentialURL,

    [Parameter(Mandatory = $true)]
    [string]$CredentialUsername,

    [Parameter(Mandatory = $true)]
    [string]$CredentialPassword,

    [Parameter(Mandatory = $true)]
    [string]$CredentialOG
)

# Load SQL Functions
. "$PSScriptRoot\SQL_Functions.ps1"
. "$PSScriptRoot\General_Functions.ps1"

# -------------------------------
# Copy Files
# -------------------------------

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
}
catch {
    Write-Error "An error occurred: $_"
}


# -------------------------------
# Create Scheduled Task
# -------------------------------

# Variables
$taskName = "WorkspaceONE Autorepair"
$scriptPath = "$($DestinationPath)\HubHealthEvaluation.ps1"

# Check for Existing Scheduled Task
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

try {
    # Create Trigger 1: A daily trigger that repeats every 4 hours.
    $dailyTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -hours 4) 

    # Create Trigger 2: A logon trigger that starts 10 minutes after user logon.
    $logonTrigger = New-ScheduledTaskTrigger -AtLogon -RandomDelay (New-TimeSpan -Minutes 15)

    # Create the action to run the specified PowerShell script.
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

    # Create task settings: run only if a user is logged on and start when available.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable

    # Create the principal. Running as SYSTEM is common when a task must run in system context.
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

    # Register the task with both triggers.
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($dailyTrigger, $logonTrigger) `
        -Settings $settings -Principal $principal

    Write-Host "Scheduled task '$taskName' created successfully." -ForegroundColor Green

}
catch {
    Write-Host "Scheduled task '$taskName' created successfully." -ForegroundColor Red
    Write-Error "An error occurred: $_"
    exit 1
}


# -------------------------------
# Create SQLite Database and Insert Credentials
# -------------------------------

# Define the path to the SQLLite Data
$SQLPath = "$($DestinationPath)\SQLite"

# Adjust the path to where your System.Data.SQLite.dll is located and unblock files
Get-ChildItem -Path $SQLPath | Unblock-File

# Add the .dll to work with SQLite
Add-Type -Path "$($SQLPath)\System.Data.SQLite.dll"



# Define the SQLite database file path
$dbPath = "$DestinationPath\HUBHealth.sqlite"

# Create or open the database
New-SQLiteDB -DbPath $dbPath

# Create the SQLite tables if it doesn't exist. 
# Before the Table gets created, the data gets deleted

# Define an array of table definitions as custom objects.
$tables = @(
    @{
        Name             = "Credentials"
        ColumnDefinition = "Name TEXT NOT NULL PRIMARY KEY, EncryptedUrl TEXT NOT NULL, EncryptedPassword TEXT NOT NULL, EncryptedUsername TEXT NOT NULL, encryptedOG TEXT NOT NULL"
    },
    @{
        Name             = "OMADM"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "HUB"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "SFD"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "WNS"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "Eventlog"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "TaskScheduler"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "Errors"
        ColumnDefinition = "OMADM_Errorcount INTEGER NOT NULL, HUB_Errorcount INTEGER NOT NULL, WNS_Errorcount INTEGER NOT NULL, ScheduledTask_Errorcount INTEGER NOT NULL, SFD_Errorcount INTEGER NOT NULL, AWCM_Errorcount INTEGER NOT NULL, LastUpdate DATETIME NOT NULL, Overall_Errorcount INTEGER NOT NULL"
    },
    @{
        Name             = "Configurations"
        ColumnDefinition = "OverallThreshold INTEGER, IndividualThreshold INTEGER, ResetAfter INTEGER, ThresholdReached TEXT, ThresholdTimestamp DATETIME DEFAULT NULL, AutoReEnrollment TEXT, EnrollmentDefinedDate TEXT, ReEnrollmentWithCurrentUserSession TEXT, EnrollmentDay TEXT, EnrollmentTime TEXT, EnrollDuringCurrentUserSession TEXT,EnrollIfNotEnrolled TEXT"
    },
    @{
        Name             = "General"
        ColumnDefinition = 'Name TEXT NOT NULL PRIMARY KEY, Value TEXT NOT NULL, "Group" TEXT'
    },
    @{
        Name             = "Encryption"
        ColumnDefinition = 'Name TEXT NOT NULL PRIMARY KEY, EncryptionKey TEXT NOT NULL'
    }
)

if (Wait-ForSQLiteUnlock -DbPath $dbPath -MaxAttempts 10 -DelaySeconds 1) {
    # Proceed with your database operations.
}
else {
    Write-Error "Cannot proceed because the database remains locked."
}

# Loop through each table definition.
foreach ($table in $tables) {
    Remove-SQLiteTable -DbPath $dbPath -TableName $table.Name
    New-SQLiteTable -DbPath $dbPath -TableName $table.Name -ColumnDefinition $table.ColumnDefinition
}

# Save the configuration from the Config File to the DB
Save-Configuration -DbPath $dbPath -ConfigJsonPath "$($DestinationPath)\config.json"


# Generate a new random string for encryption
$EncryptionKey = New-RandomKeyString

$connectionString = "Data Source=$DbPath;Version=3;"
$conn = $null

try {
    # Open the connection.
    $conn = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
    $conn.Open()

    # Use INSERT OR REPLACE to ensure a single row with the key "CurrentCredential" is maintained.
    $sql = "INSERT OR REPLACE INTO Encryption (Name, EncryptionKey)
                VALUES ('UniqueKey', @EncryptionKey);"
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = $sql

    # Bind parameters.
    $paramkey = $cmd.CreateParameter(); $paramkey.ParameterName = "@EncryptionKey"; $paramkey.Value = $EncryptionKey; $cmd.Parameters.Add($paramkey) | Out-Null
        
    $rowsAffected = $cmd.ExecuteNonQuery()
    Write-Host "Credentials updated successfully. Rows affected: $rowsAffected" -ForegroundColor Green
}
catch {
    Write-Error "Error in Updating the Encrpytion Key $_"
}
finally {
    if ($conn -and $conn.State -eq 'Open') {
        $conn.Close()
    }
}

# Insert the credentials record into the Credentials table.
Write-CredentialsRecord -DbPath $dbPath -URL $CredentialURL -Password $CredentialPassword -Username $CredentialUsername -OG $CredentialOG -EncryptionKey $EncryptionKey

Write-Output "Installation complete."