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
Script Name: SQL_Functions.ps1
Description: Provides SQL re-usable functions

Author:      Grischa Ernst
Date:        2025-01-01
Version:     1.0
===============================================================================

#>

function Write-CredentialsRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        [Parameter(Mandatory = $true)]
        [string]$Url,
        
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [string]$Password,
        
        [Parameter(Mandatory = $true)]
        [string]$OG,

        # Encryption key used for AES encryption.
        [Parameter(Mandatory = $true)]
        [string]$EncryptionKey
    )

    try {
        # Encrypt each credential value using the provided key.
        $encryptedUrl      = New-EncryptedString -PlainText $Url -KeyString $EncryptionKey
        $encryptedUsername = New-EncryptedString -PlainText $Username -KeyString $EncryptionKey
        $encryptedPassword = New-EncryptedString -PlainText $Password -KeyString $EncryptionKey
        $encryptedOG       = New-EncryptedString -PlainText $OG -KeyString $EncryptionKey
    }
    catch {
        Write-Error "Error encrypting credentials: $_"
        return
    }

    $connectionString = "Data Source=$DbPath;Version=3;"
    $conn = $null

    try {
        # Open the connection.
        $conn = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $conn.Open()

        # Use INSERT OR REPLACE to ensure a single row with the key "CurrentCredential" is maintained.
        $sql = "INSERT OR REPLACE INTO Credentials (Name, EncryptedUrl, EncryptedUsername, EncryptedPassword, encryptedOG)
                VALUES ('CurrentCredential', @EncryptedUrl, @EncryptedUsername, @EncryptedPassword, @encryptedOG);"
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $sql

        # Bind parameters.
        $paramUrl = $cmd.CreateParameter(); $paramUrl.ParameterName = "@EncryptedUrl"; $paramUrl.Value = $encryptedUrl; $cmd.Parameters.Add($paramUrl) | Out-Null
        $paramUsername = $cmd.CreateParameter(); $paramUsername.ParameterName = "@EncryptedUsername"; $paramUsername.Value = $encryptedUsername; $cmd.Parameters.Add($paramUsername) | Out-Null
        $paramPassword = $cmd.CreateParameter(); $paramPassword.ParameterName = "@EncryptedPassword"; $paramPassword.Value = $encryptedPassword; $cmd.Parameters.Add($paramPassword) | Out-Null
        $paramOG = $cmd.CreateParameter(); $paramOG.ParameterName = "@encryptedOG"; $paramOG.Value = $encryptedOG; $cmd.Parameters.Add($paramOG) | Out-Null

        $rowsAffected = $cmd.ExecuteNonQuery()
        Write-Host "Credentials updated successfully. Rows affected: $rowsAffected" -ForegroundColor Green
    }
    catch {
        Write-Error "Error in Write-CredentialsRecord: $_"
    }
    finally {
        if ($conn -and $conn.State -eq 'Open') {
            $conn.Close()
        }
    }
}

function Read-CredentialsRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        # Encryption key used for AES decryption.
        [Parameter(Mandatory = $true)]
        [string]$EncryptionKey
    )

    $connectionString = "Data Source=$DbPath;Version=3;"
    $conn = $null
    $results = @()

    try {
        $conn = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $conn.Open()

        # Query the Credentials table; note: we assume there's only one row.
        $sql = "SELECT EncryptedUrl, EncryptedUsername, EncryptedPassword, encryptedOG FROM Credentials"
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $sql

        $reader = $cmd.ExecuteReader()
        while ($reader.Read()) {
            $encryptedUrl = $reader["EncryptedUrl"]
            $encryptedUsername = $reader["EncryptedUsername"]
            $encryptedPassword = $reader["EncryptedPassword"]
            $encryptedOG = $reader["encryptedOG"]

            try {
                $urlPlain = Read-EncryptedString  -CipherText $encryptedUrl -KeyString $EncryptionKey
                $usernamePlain = Read-EncryptedString  -CipherText $encryptedUsername -KeyString $EncryptionKey
                $passwordPlain = Read-EncryptedString  -CipherText $encryptedPassword -KeyString $EncryptionKey
                $OGPlain = Read-EncryptedString  -CipherText $encryptedOG -KeyString $EncryptionKey
            }
            catch {
                Write-Error "Decryption error: $_"
                continue
            }

            $record = [PSCustomObject]@{
                Url      = $urlPlain
                Username = $usernamePlain
                Password = $passwordPlain
                OG       = $OGPlain
            }
            $results += $record
        }
        $reader.Close()
    }
    catch {
        Write-Error "Error in Read-CredentialsRecord: $_"
    }
    finally {
        if ($conn -and $conn.State -eq 'Open') {
            $conn.Close()
        }
    }
    return $results
}
function Write-StatusRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        
        [Parameter(Mandatory = $true)]
        [string]$TestName,
        
        [Parameter(Mandatory = $true)]
        [string]$Result,
        
        # Optional parameters; they are only included if provided
        [Parameter(Mandatory = $false)]
        [int]$ErrorCounter,
        
        [Parameter(Mandatory = $false)]
        [datetime]$LastRunTime = (Get-Date),
        
        [Parameter(Mandatory = $false)]
        [datetime]$LastErrorDetection
    )
    
    $connectionString = "Data Source=$DbPath;Version=3;"
    $connection = $null
    
    try {
        # Open the SQLite connection
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()
        
        # Start with the required columns and placeholders.
        $columns = "TestName, Result, LastRunTime"
        $placeholders = "@testName, @result, @lastRunTime"
        
        # Dynamically add optional columns if they were provided.
        if ($PSBoundParameters.ContainsKey('ErrorCounter') -and $ErrorCounter -ne $null) {
            $columns += ", ErrorCounter"
            $placeholders += ", @errorCounter"
        }
        if ($PSBoundParameters.ContainsKey('LastErrorDetection') -and $LastErrorDetection -ne $null) {
            $columns += ", LastErrorDetection"
            $placeholders += ", @lastErrorDetection"
        }
        
        # Build the SQL INSERT command dynamically.
        $sql = "INSERT INTO $TableName ($columns) VALUES ($placeholders)"
        
        # Create the command and set its text.
        $cmd = $connection.CreateCommand()
        $cmd.CommandText = $sql
        
        # Add required parameters.
        $pTestName = $cmd.CreateParameter()
        $pTestName.ParameterName = "@testName"
        $pTestName.Value = $TestName
        $cmd.Parameters.Add($pTestName) | Out-Null

        $pResult = $cmd.CreateParameter()
        $pResult.ParameterName = "@result"
        $pResult.Value = $Result
        $cmd.Parameters.Add($pResult) | Out-Null

        $pLastRunTime = $cmd.CreateParameter()
        $pLastRunTime.ParameterName = "@lastRunTime"
        $pLastRunTime.Value = $LastRunTime
        $cmd.Parameters.Add($pLastRunTime) | Out-Null

        # Add optional parameters if provided.
        if ($PSBoundParameters.ContainsKey('ErrorCounter') -and $ErrorCounter -ne $null) {
            $pErrorCounter = $cmd.CreateParameter()
            $pErrorCounter.ParameterName = "@errorCounter"
            $pErrorCounter.Value = $ErrorCounter
            $cmd.Parameters.Add($pErrorCounter) | Out-Null
        }
        if ($PSBoundParameters.ContainsKey('LastErrorDetection') -and $LastErrorDetection -ne $null) {
            $pLastErrorDetection = $cmd.CreateParameter()
            $pLastErrorDetection.ParameterName = "@lastErrorDetection"
            $pLastErrorDetection.Value = $LastErrorDetection
            $cmd.Parameters.Add($pLastErrorDetection) | Out-Null
        }
        
        # Execute the command.
        $cmd.ExecuteNonQuery() | Out-Null
        Write-Host "Status record inserted into table '$TableName'."
    }
    catch {
        Write-Error "Error in Write-StatusRecord: $_"
    }
    finally {
        if ($connection -and $connection.State -eq 'Open') {
            $connection.Close()
        }
    }
}

function Remove-SQLiteOldEntries {
    [CmdletBinding()]
    param(
        # Path to the SQLite database file.
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        # Name of the table to clean up.
        [Parameter(Mandatory = $true)]
        [string]$TableName,

        # Name of the column containing the timestamp (default is "Timestamp").
        [Parameter(Mandatory = $false)]
        [string]$TimestampColumn = "Timestamp",

        # Number of days; rows older than this number will be deleted (default is 14 days).
        [Parameter(Mandatory = $false)]
        [int]$Days = 14
    )

    # Calculate the threshold timestamp. Any record with a timestamp earlier than this value will be deleted.
    $threshold = (Get-Date).AddDays(-$Days).ToString("s")

    $connectionString = "Data Source=$DbPath;Version=3;"
    $connection = $null

    try {
        # Open the SQLite connection.
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Prepare the SQL DELETE command.
        $sql = "DELETE FROM $TableName WHERE $TimestampColumn < @threshold;"
        $cmd = $connection.CreateCommand()
        $cmd.CommandText = $sql

        # Create and add the threshold parameter.
        $param = $cmd.CreateParameter()
        $param.ParameterName = "@threshold"
        $param.Value = $threshold
        $cmd.Parameters.Add($param) | Out-Null

        # Execute the command and get the number of rows deleted.
        $rowsDeleted = $cmd.ExecuteNonQuery()
        Write-Host "Deleted $rowsDeleted row(s) from table '$TableName' older than $Days days (threshold: $threshold)."
    }
    catch {
        Write-Error "Error cleaning up old entries from table '$TableName': $_"
    }
    finally {
        # Ensure the connection is closed.
        if ($connection -and $connection.State -eq 'Open') {
            $connection.Close()
        }
    }
}


function Read-SQLiteTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DbPath,
        [Parameter(Mandatory=$true)]
        [string]$TableName
    )

    $connectionString = "Data Source=$DbPath;Version=3;"
    $connection = $null
    $results = @()

    try {
        # Open the SQLite connection.
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Build and set the SELECT query.
        $sql = "SELECT * FROM $TableName"
        $cmd = $connection.CreateCommand()
        $cmd.CommandText = $sql

        # Execute the query.
        $reader = $cmd.ExecuteReader()

        # Process each record in the result set.
        while ($reader.Read()) {
            $row = @{}
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                $colName = $reader.GetName($i)
                # Check for DB null; if so, assign $null; otherwise, get the raw value.
                if ($reader.IsDBNull($i)) {
                    $row[$colName] = $null
                }
                else {
                    $row[$colName] = $reader.GetValue($i)
                }
            }
            $results += [PSCustomObject]$row
        }
        $reader.Close()
    }
    catch {
        Write-Error "Error in Read-SQLiteTable: $_"
    }
    finally {
        if ($connection -and $connection.State -eq 'Open') {
            $connection.Close()
        }
    }
    return $results
}




function Insert-SQLiteRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Data,
        
        # If set, update an existing record instead of inserting a new one.
        [Parameter(Mandatory = $false)]
        [switch]$Overwrite,
        
        # A list of columns to update when overwriting.
        [Parameter(Mandatory = $false)]
        [string[]]$OverwriteColumns,
        
        # (Optional) A SQL condition (without the WHERE keyword) to uniquely identify a record.
        [Parameter(Mandatory = $false)]
        [string]$UniqueCondition = ""
    )

    $connectionString = "Data Source=$DbPath;Version=3;"
    $connection = $null

    try {
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        if ($Overwrite.IsPresent -and $OverwriteColumns -and $OverwriteColumns.Count -gt 0) {
            # Build UPDATE statement for specific columns.
            $setClauses = @()
            foreach ($col in $OverwriteColumns) {
                if (-not $Data.ContainsKey($col)) {
                    throw "Data must contain a key for '$col' when using -Overwrite with -OverwriteColumns."
                }
                # Wrap the column name in double quotes.
                $setClauses += "`"$col`" = @${col}"
            }
            $setClauseStr = $setClauses -join ", "
            if ($UniqueCondition -ne "") {
                $sql = "UPDATE $TableName SET $setClauseStr WHERE $UniqueCondition;"
            }
            else {
                $sql = "UPDATE $TableName SET $setClauseStr;"
            }
        }
        elseif ($Overwrite.IsPresent -and $UniqueCondition -ne "") {
            # Check if a matching record exists.
            $cmdCheck = $connection.CreateCommand()
            $cmdCheck.CommandText = "SELECT COUNT(*) FROM $TableName WHERE $UniqueCondition;"
            $existingCount = $cmdCheck.ExecuteScalar()

            if ([int]$existingCount -gt 0) {
                # Build UPDATE statement for all columns.
                $setClauses = @()
                foreach ($key in $Data.Keys) {
                    $setClauses += "`"$key`" = @${key}"
                }
                $setClauseStr = $setClauses -join ", "
                $sql = "UPDATE $TableName SET $setClauseStr WHERE $UniqueCondition;"
            }
            else {
                # Build INSERT statement.
                $columns = ($Data.Keys | ForEach-Object { "`"$_`"" }) -join ", "
                $placeholders = ($Data.Keys | ForEach-Object { "@$_" }) -join ", "
                $sql = "INSERT INTO $TableName ($columns) VALUES ($placeholders);"
            }
        }
        else {
            # Build INSERT statement for all columns.
            $columns = ($Data.Keys | ForEach-Object { "`"$_`"" }) -join ", "
            $placeholders = ($Data.Keys | ForEach-Object { "@$_" }) -join ", "
            $sql = "INSERT INTO $TableName ($columns) VALUES ($placeholders);"
        }

        $cmd = $connection.CreateCommand()
        $cmd.CommandText = $sql

        if ($Overwrite.IsPresent -and $OverwriteColumns -and $OverwriteColumns.Count -gt 0) {
            foreach ($col in $OverwriteColumns) {
                $param = $cmd.CreateParameter()
                $param.ParameterName = "@$col"
                $param.Value = $Data[$col]
                $cmd.Parameters.Add($param) | Out-Null
            }
        }
        else {
            foreach ($key in $Data.Keys) {
                $param = $cmd.CreateParameter()
                $param.ParameterName = "@$key"
                $param.Value = $Data[$key]
                $cmd.Parameters.Add($param) | Out-Null
            }
        }

        $cmd.ExecuteNonQuery() | Out-Null
        Write-Host "Record inserted/updated successfully in table '$TableName'." -ForegroundColor Green
    }
    catch {
        Write-Error "Error inserting/updating record in table '$TableName': $_"
    }
    finally {
        if ($connection -and $connection.State -eq 'Open') {
            $connection.Close()
        }
    }
}


function Test-ErrorsThreshold {
    [CmdletBinding()]
    param(
        # Path to the SQLite database file.
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        # Threshold value for each individual error column (e.g. OMADM_Errorcount, HUB_Errorcount, etc.).
        [Parameter(Mandatory = $true)]
        [int]$IndividualThreshold,
        
        # Threshold value for Overall_Errorcount.
        [Parameter(Mandatory = $true)]
        [int]$OverallThreshold
    )
    
    try {
        # Read all rows from the Errors table.
        $errorRows = Read-SQLiteTable -DbPath $DbPath -TableName "Errors"
        
        if (-not $errorRows -or $errorRows.Count -eq 0) {
            Write-Log "No error entries found in the Errors table." -Severity "INFO"
            return $false
        }
        
        foreach ($row in $errorRows) {
            # Convert LastUpdate to a DateTime.
            $lastUpdate = [datetime]$row.LastUpdate
            
            # Calculate the number of hours since LastUpdate.
            $hoursSinceUpdate = (Get-Date) - $lastUpdate | Select-Object -ExpandProperty TotalHours
            
            if ($hoursSinceUpdate -gt 24) {
                Write-Log "Skipping error entry: LastUpdate ($lastUpdate) is older than 24 hours (hours since update: $hoursSinceUpdate)." -Severity "DEBUG"
                continue
            }
            
            # Check each individual error count.
            $indivThresholdMet = (
                ([int]$row.OMADM_Errorcount -ge $IndividualThreshold) -or 
                ([int]$row.HUB_Errorcount -ge $IndividualThreshold) -or 
                ([int]$row.WNS_Errorcount -ge $IndividualThreshold) -or 
                ([int]$row.ScheduledTask_Errorcount -ge $IndividualThreshold) -or 
                ([int]$row.SFD_Errorcount -ge $IndividualThreshold)
            )
            
            # Check the overall error threshold.
            $overallThresholdMet = ([int]$row.Overall_Errorcount -ge $OverallThreshold)
            
            Write-Log "Evaluating Errors row: OMADM=$($row.OMADM_Errorcount), HUB=$($row.HUB_Errorcount), WNS=$($row.WNS_Errorcount), ScheduledTask=$($row.ScheduledTask_Errorcount), SFD=$($row.SFD_Errorcount), Overall=$($row.Overall_Errorcount), LastUpdate=$lastUpdate (hours since update: $hoursSinceUpdate)" -Severity "DEBUG"
            
            if ($indivThresholdMet -and $overallThresholdMet) {
                Write-Log "Threshold conditions met: All individual error counts are >= $IndividualThreshold and Overall_Errorcount is >= $OverallThreshold." -Severity "INFO"
                return $true
            }
        }
        
        Write-Log "No error entry meets the threshold conditions (individual threshold = $IndividualThreshold and overall threshold = $OverallThreshold) within the last 24 hours." -Severity "INFO"
        return $false
    }
    catch {
        Write-Error "Error checking error thresholds: $_"
        return $false
    }
}


function New-SQLiteDB {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath
    )
    
    $connectionString = "Data Source=$DbPath;Version=3;"
    $connection = $null

    if (Test-Path -Path $DbPath) {
        # The database file exists. Attempt to open it.
        try {
            $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
            $connection.Open()
            Write-Host "SQLite database '$DbPath' already exists and was opened successfully."
        }
        catch {
            Write-Error "The database file '$DbPath' exists but could not be opened: $_"
        }
        finally {
            if ($connection -and $connection.State -eq 'Open') {
                $connection.Close()
            }
        }
    }
    else {
        # The database file does not exist. Create it by opening a new connection.
        try {
            $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
            $connection.Open()
            Write-Host "SQLite database '$DbPath' did not exist and was created successfully."
        }
        catch {
            Write-Error "Error creating/opening SQLite DB at '$DbPath': $_"
        }
        finally {
            if ($connection -and $connection.State -eq 'Open') {
                $connection.Close()
            }
        }
    }
}

function New-SQLiteTable {
    #example
    <#
    $tableName = "OmaDmStatus"
    $columns = "Id INTEGER PRIMARY KEY AUTOINCREMENT, TestName TEXT NOT NULL, Result TEXT NOT NULL, ErrorCounter INTEGER DEFAULT 0, LastRunTime DATETIME, LastErrorDetection DATETIME"
    New-SQLiteTable -DbPath $dbPath -TableName $tableName -ColumnDefinition $columns
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$ColumnDefinition
    )

    # Build the CREATE TABLE SQL command
    $sql = "CREATE TABLE IF NOT EXISTS $TableName ($ColumnDefinition);"
    $connectionString = "Data Source=$DbPath;Version=3;"
    $connection = $null
    try {
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()
        $cmd = $connection.CreateCommand()
        $cmd.CommandText = $sql
        $cmd.ExecuteNonQuery() | Out-Null
        Write-Host "Table '$TableName' created (if not already existing) in the database at: $DbPath"
    }
    catch {
        Write-Error "Error creating table '$TableName': $_"
    }
    finally {
        if ($connection -and $connection.State -eq 'Open') {
            $connection.Close()
        }
    }
}


function Update-ErrorColumn {
    [CmdletBinding()]
    param(
        # Path to the SQLite database file.
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        # The name of the error column to update (e.g. "OMADM_Errorcount", "HUB_Errorcount", or "WNS_Errorcount").
        [Parameter(Mandatory = $true)]
        [string]$ErrorColumn,
        
        # Boolean flag indicating if an error was detected.
        # If $true, the error count is incremented; if $false and count > 0, it is decremented; if count is 0, only update the timestamp.
        [Parameter(Mandatory = $true)]
        [bool]$IsError
    )

    Write-Log "Updating Errors table for column '$ErrorColumn' with error flag: $IsError" -Severity "INFO"

    $currentValue = 0

    try {
        $connectionString = "Data Source=$DbPath;Version=3;"
        $conn = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $conn.Open()
        $cmd = $conn.CreateCommand()
        # Retrieve the current value from the specified column.
        $cmd.CommandText = "SELECT $ErrorColumn FROM Errors ORDER BY LastUpdate DESC LIMIT 1;"
        $result = $cmd.ExecuteScalar()
        if ($result -ne $null) {
            $currentValue = [int]$result
        }
        #If entries were not created before, create them
        else {
            $errorData = @{
                OMADM_Errorcount         = 0
                HUB_Errorcount           = 0
                WNS_Errorcount           = 0
                ScheduledTask_Errorcount = 0
                SFD_Errorcount           = 0
                AWCM_Errorcount          = 0
                LastUpdate               = (Get-Date).ToString("s")
                Overall_Errorcount       = 0
            }
            Insert-SQLiteRecord -DbPath $DbPath -TableName "Errors" -Data $errorData
        }

    }
    catch {
        Write-Log "Error reading current value for column '$ErrorColumn': $($_.Exception.Message)" -Severity "ERROR"
    }
    finally {
        if ($conn -and $conn.State -eq 'Open') {
            $conn.Close()
        }
    }

    # Determine the new value based on $IsError.
    if ($IsError) {
        $newValue = $currentValue + 1
        
    }
    else {
        if ($currentValue -gt 0) {
            $newValue = $currentValue - 1
            
        }
        else {
            $newValue = 0
            
        }
    }

    # Prepare the data hashtable to update the Errors table.
    $data = @{
        $ErrorColumn       = $newValue
        LastUpdate         = (Get-Date).ToString("s")
    }

    # Update the Errors table by overwriting only the specified error column and the LastUpdate column.
    Insert-SQLiteRecord -DbPath $DbPath -TableName "Errors" -Data $data -Overwrite -OverwriteColumns @($ErrorColumn, "LastUpdate")

    #Get the updated Error Counts
    # Read the current errors from the Errors table.
    $errorsRows = Read-SQLiteTable -DbPath $DbPath -TableName "Errors"
    if (-not $errorsRows -or $errorsRows.Count -eq 0) {
        Write-Error "No rows found in the Errors table. Cannot update Overall_Errorcount."
        return
    }

    # Assume a single row; if there are multiple rows, adjust the logic as needed.
    $row = $errorsRows[0]

    # Sum individual error counts.
    $overall = ([int]$row.OMADM_Errorcount) +
               ([int]$row.HUB_Errorcount) +
               ([int]$row.WNS_Errorcount) +
               ([int]$row.SFD_Errorcount) +
               ([int]$row.ScheduledTask_Errorcount) +
               ([int]$row.AWCM_Errorcount)

    Write-Host "Calculated Overall_Errorcount: $overall"

    # Build a hashtable to update the row.
    $data = @{
        Overall_Errorcount = $overall
        LastUpdate         = (Get-Date).ToString("s")
    }

    # Update the Errors table. Using "1=1" as a condition assumes only one row exists.
    Insert-SQLiteRecord -DbPath $DbPath -TableName "Errors" -Data $data -Overwrite -UniqueCondition "1=1"
    
    Write-Log "Updated '$ErrorColumn' to $newValue in Errors table." -Severity "INFO"
}

function New-HTMLReport {
    [CmdletBinding()]
    param(
        # Path to the SQLite database file.
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        # Path to the output HTML file.
        [Parameter(Mandatory = $true)]
        [string]$OutputFile,
        
        # Optional: List of tables (categories) to include in the report.
        [Parameter(Mandatory = $false)]
        [string[]]$TableList = @("Errors", "General", "OMADM", "HUB", "SFD", "WNS", "TaskScheduler", "Eventlog"),
        
        # For tables other than "Errors" and "General", only show rows generated within this time window (in minutes)
        # relative to the most recent entry.
        [Parameter(Mandatory = $false)]
        [int]$CurrentWindowMinutes = 2
    )

    Write-Host "Generating HTML report from DB: $DbPath" -ForegroundColor Cyan

    # Array to hold HTML content.
    $htmlSections = @()

    # HTML header with custom styles.
    $htmlHeader = @"
<html>
<head>
    <title>Hub Health Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        h1 { color: #007ACC; }
        h2 { background-color: #007ACC; color: white; padding: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; table-layout: fixed; }
        table, th, td { border: 1px solid #ddd; }
        th, td { padding: 8px; text-align: left; word-wrap: break-word; }
        th { background-color: #f2f2f2; }
        .errorRow { background-color: red; color: white; }
        .greenRow { background-color: green; color: white; }
    </style>
</head>
<body>
    <h1>Hub Health Report</h1>
    <p>Report generated on: $(Get-Date)</p>
"@
    $htmlSections += $htmlHeader

    foreach ($table in $TableList) {
        Write-Host "Processing table: $table" -ForegroundColor Green
        
        $sectionHeader = "<h2>$table</h2>"
        $htmlSections += $sectionHeader

        # Read all rows from the table.
        $rows = Read-SQLiteTable -DbPath $DbPath -TableName $table

        if ($table -eq "Errors") {
            # For Errors table: unpivot the latest row.
            if ($rows) {
                $latestRow = $rows | Sort-Object { [datetime]$_.LastUpdate } -Descending | Select-Object -First 1
                $errorColumns = @("OMADM_Errorcount", "HUB_Errorcount", "WNS_Errorcount", "ScheduledTask_Errorcount", "SFD_Errorcount", "Overall_Errorcount")
                $htmlTable = "<table><tr><th>Test</th><th>Result</th></tr>"
                foreach ($col in $errorColumns) {
                    if ($latestRow.PSObject.Properties.Name -contains $col) {
                        $resultValue = $latestRow.$col
                        $rowClass = ""
                        if ($col -eq "Overall_Errorcount") {
                            if ([int]$resultValue -eq 0) {
                                $rowClass = " class='greenRow'"
                            }
                            elseif ([int]$resultValue -ne 0) {
                                $rowClass = " class='errorRow'"
                            }
                        }
                        else {
                            if ([int]$resultValue -ne 0) {
                                $rowClass = " class='errorRow'"
                            }
                        }
                        $htmlTable += "<tr$rowClass><td>$col</td><td>$resultValue</td></tr>"
                    }
                }
                $htmlTable += "</table>"
                $htmlSections += $htmlTable
            }
            else {
                $htmlSections += "<p>No records found in Errors table.</p>"
            }
        }
        elseif ($table -eq "General") {
            # For General table, we assume columns: Name, Value, Group.
            if ($rows) {
                # Group rows by the 'Group' column; if empty, assign "Other".
                $groups = $rows | Group-Object -Property { if ([string]::IsNullOrEmpty($_.Group)) { "Other" } else { $_.Group } }
                foreach ($grp in $groups) {
                    $groupName = $grp.Name
                    $htmlSections += "<h3>$groupName</h3>"
                    # Build an HTML table with fixed column widths.
                    $htmlTable = "<table style='width:100%; table-layout: fixed;'><tr><th style='width:50%;'>Name</th><th style='width:50%;'>Value</th></tr>"
                    foreach ($row in $grp.Group) {
                        if ($row.Name -like "*Joined*" -and $row.Value -eq "0") { $keyvalue = "No" }
                        elseif ($row.Name -like "*Joined*" -and $row.Value -eq "1") { $keyvalue = "Yes" }
                        else { $keyvalue = $row.Value }
                        $htmlTable += "<tr><td>$($row.Name)</td><td>$($keyvalue)</td></tr>"
                    }
                    $htmlTable += "</table>"
                    $htmlSections += $htmlTable
                }
            }
            else {
                $htmlSections += "<p>No records found in General table.</p>"
            }
        }
        else {
            # For all other tables, filter rows relative to the most recent entry.
            if ($rows) {
                try {
                    $latestEntry = $rows | Sort-Object { [datetime]$_.Timestamp } -Descending | Select-Object -First 1
                    $maxTime = [datetime]$latestEntry.Timestamp
                }
                catch {
                    Write-Host "Unable to determine the latest timestamp for table $table" -ForegroundColor Yellow
                    $maxTime = $null
                }
                if ($maxTime) {
                    $displayRows = $rows | Where-Object { 
                        try { [datetime]$_.Timestamp -ge $maxTime.AddMinutes(-$CurrentWindowMinutes) }
                        catch { $false }
                    }
                }
                else {
                    $displayRows = $rows
                }
                
                $displayRows = $displayRows | Select-Object Timestamp, Test, Result

                if ($displayRows) {
                    # Manually build an HTML table so that we can conditionally style rows.
                    $htmlTable = "<table style='width:100%; table-layout: fixed;'><tr><th style='width:33%;'>Timestamp</th><th style='width:33%;'>Test</th><th style='width:34%;'>Result</th></tr>"
                    foreach ($row in $displayRows) {
                        $rowClass = ""
                        if ($row.Result -match "(?i)(Failure|Error|Error detected|Non-compliant)") {
                            $rowClass = " class='errorRow'"
                        }
                        $htmlTable += "<tr$rowClass><td>$($row.Timestamp)</td><td>$($row.Test)</td><td>$($row.Result)</td></tr>"
                    }
                    $htmlTable += "</table>"
                    $htmlSections += "<h3>Recent Results from $table</h3>"
                    $htmlSections += $htmlTable
                }
                else {
                    $htmlSections += "<p>No records found in $table for the current data set.</p>"
                }
            }
            else {
                $htmlSections += "<p>No records found in $table.</p>"
            }
        }
    }

    # Append closing HTML tags.
    $htmlFooter = @"
</body>
</html>
"@
    $htmlSections += $htmlFooter

    $fullHtml = $htmlSections -join "`n"
    $fullHtml | Out-File -FilePath $OutputFile -Encoding UTF8

    Write-Host "HTML report generated successfully at: $OutputFile" -ForegroundColor Cyan
}


function Remove-SQLiteTable {
    [CmdletBinding()]
    param(
        # Path to the SQLite database file.
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        # Name of the table to delete.
        [Parameter(Mandatory = $true)]
        [string]$TableName
    )

    $connectionString = "Data Source=$DbPath;Version=3;"
    $connection = $null

    try {
        # Create and open the SQLite connection.
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Create a command to drop the table.
        $cmd = $connection.CreateCommand()
        $cmd.CommandText = "DROP TABLE IF EXISTS $TableName;"
        $cmd.ExecuteNonQuery() | Out-Null

        Write-Host "Table '$TableName' deleted successfully from database '$DbPath'." -ForegroundColor Green
    }
    catch {
        Write-Error "Error deleting table '$TableName' from database '$DbPath': $_"
    }
    finally {
        # Ensure the connection is closed.
        if ($connection -and $connection.State -eq 'Open') {
            $connection.Close()
        }
    }
}

function Wait-ForSQLiteUnlock {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DbPath,
        
        # Number of attempts or timeout (in seconds)
        [int]$MaxAttempts = 10,
        [int]$DelaySeconds = 1
    )
    
    $attempts = 0
    $connectionString = "Data Source=$DbPath;Version=3;PRAGMA busy_timeout=30000;"
    
    while ($attempts -lt $MaxAttempts) {
        try {
            $conn = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
            $conn.Open()
            $conn.Close()
            Write-Host "Database unlocked after $attempts attempts." -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "Database is locked. Attempt $($attempts + 1) of $MaxAttempts. Waiting $DelaySeconds second(s)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $DelaySeconds
            $attempts++
        }
    }
    Write-Error "Database remains locked after $MaxAttempts attempts."
    return $false
}


function Insert-GeneralData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Data,
        
        [hashtable]$GroupMapping
    )

    Write-Host "Bulk inserting/updating general data into the 'General' table." -ForegroundColor Green

    foreach ($key in $Data.Keys) {
        $record = @{
            Name  = $key
            Value = $Data[$key]
        }
        if ($GroupMapping -and $GroupMapping.ContainsKey($key)) {
            $record["Group"] = $GroupMapping[$key]
        }
        Insert-SQLiteRecord -DbPath $DbPath -TableName "General" -Data $record -Overwrite -UniqueCondition "Name = '$key'"
        Write-Host "Inserted/updated: Name='$key', Value='$($Data[$key])'" -ForegroundColor Green
    }
}