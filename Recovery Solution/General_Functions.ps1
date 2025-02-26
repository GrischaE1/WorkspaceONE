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
Description: Provides general re-usable functions

Author:      Grischa Ernst
Date:        2025-01-01
Version:     1.0
===============================================================================

#>



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


function Set-RegistryValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        # Customize this to whatever main registry hive/path you prefer
        [string]$BasePath = "HKLM:\Software\WorkspaceONEStatus"
    )

    # Construct the full registry path: e.g. HKLM:\Software\MyCompany\Domain Status
    $fullKeyPath = Join-Path -Path $BasePath -ChildPath $Category

    # 1) Check if the registry subkey exists; if not, create it
    if (-not (Test-Path -Path $fullKeyPath)) {
        Write-Verbose "Creating registry key: $fullKeyPath"
        New-Item -Path $fullKeyPath -Force | Out-Null
    }

    # 2) Create or update the property (Name=Value). 
    #    -PropertyType String is common for text data; use other types if needed.
    Write-Verbose "Setting property '$Name' to '$Value' in $fullKeyPath"
    New-ItemProperty -Path $fullKeyPath -Name $Name -Value $Value -PropertyType String -Force | Out-Null

    Write-Host "Successfully set registry value: $($fullKeyPath)\$Name = $Value"
}


function Get-DomainStatus {
    [CmdletBinding()]
    param()

    #--- 1) Parse dsregcmd /status output
    try {
        $dsregLines = dsregcmd /status | ForEach-Object { $_.Trim() }
    }
    catch {
        Write-Error "Failed to run 'dsregcmd /status': $_"
        return
    }

    $dsregPairs = $dsregLines |
    Where-Object { $_ -match ' : ' } |
    ConvertFrom-String -PropertyNames 'Name', 'Value' -Delimiter ' : '

    $hash = @{}
    foreach ($item in $dsregPairs) {
        $hash[$item.Name] = $item.Value
    }

    # Booleans
    $AADJoined = ($hash["AzureAdJoined"] -eq 'YES')
    $ADJoined = ($hash["DomainJoined"] -eq 'YES')
    $HybridJoined = $AADJoined -and $ADJoined

    #--- 2) Determine domain type
    if ($HybridJoined) {
        $domainType = "Hybrid joined"
    }
    elseif ($ADJoined) {
        $domainType = "AD joined"
    }
    elseif ($AADJoined) {
        $domainType = "Azure AD joined"
    }
    else {
        $domainType = "Workgroup"
    }

    #--- 3) Retrieve domain name, tenant name, or workgroup name
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem

    if ($HybridJoined) {
        # For Hybrid: combine on-prem domain and tenant name
        $tenantName = if ($hash["TenantName"]) {
            $hash["TenantName"]
        }
        else {
            "UnknownTenant"
        }
        $domainOrTenantName = $computerSystem.Domain + " / " + $tenantName
    }
    elseif ($ADJoined) {
        # On-prem domain only
        $domainOrTenantName = $computerSystem.Domain
    }
    elseif ($AADJoined) {
        # AAD: tenant name from dsregcmd
        $domainOrTenantName = if ($hash["TenantName"]) {
            $hash["TenantName"]
        }
        else {
            "UnknownTenant"
        }
    }
    else {
        # Workgroup
        $domainOrTenantName = $computerSystem.Workgroup
    }

    #--- 4) (Optional) Store Domain Type or DomainOrTenantName in registry
    Set-RegistryValue -Category "Domain Status" -Name "Domain Type"         -Value $domainType
    Set-RegistryValue -Category "Domain Status" -Name "DomainOrTenantName" -Value $domainOrTenantName

    #--- 5) (Optional) Store General Information in SQLite DB
    $General = @{
        Computername       = $env:COMPUTERNAME
        Windows            = (Get-WmiObject -class Win32_OperatingSystem).Caption
        WindowsBuild       = (Get-WmiObject -class Win32_OperatingSystem).Version
        WindowsVersion     = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion
        Uptime             = (Get-CimInstance CIM_OperatingSystem).LastBootUpTime
        AADJoined          = $AADJoined
        ADJoined           = $ADJoined
        HybridJoined       = $HybridJoined
        DomainType         = $domainType
        DomainOrTenantName = $domainOrTenantName
    }

    $GroupMapping = @{
        Computername       = "Computer Information"
        Windows            = "Computer Information"
        WindowsBuild       = "Computer Information"
        WindowsVersion     = "Computer Information"
        Uptime             = "Computer Information"
        AADJoined          = "Domain Information"
        ADJoined           = "Domain Information"
        HybridJoined       = "Domain Information"
        DomainType         = "Domain Information"
        DomainOrTenantName = "Domain Information"
    }

    Insert-GeneralData -DbPath $DbPath -Data $General -GroupMapping $GroupMapping

    #--- 5) Return a structured object
    return [PSCustomObject]@{
        AADJoined          = $AADJoined
        ADJoined           = $ADJoined
        HybridJoined       = $HybridJoined
        DomainType         = $domainType
        DomainOrTenantName = $domainOrTenantName
    }
}

function Test-PendingReboot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to the SQLite database file")]
        [string]$DbPath
    )


    # Initialize the pending reboot flag.
    $PendingRestart = $false

    # Check various registry locations and COM object to determine if a reboot is pending.
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore) { 
        $PendingRestart = $true 
    }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore) { 
        $PendingRestart = $true 
    }
    if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired -eq $true) { 
        $PendingRestart = $true 
    }

    # Build a hashtable with the data to insert into the General table under the group "Computer Information".
    $GeneralData = @{
        "Test-PendingReboot Status" = if ($PendingRestart) { "Pending Reboot" } else { "No Pending Reboot" }
    }
  
    # Build a group mapping so that all keys are assigned to "Computer Information".
    $GroupMapping = @{}
    foreach ($key in $GeneralData.Keys) {
        $GroupMapping[$key] = "Computer Information"
    }

    # Insert or update the general data into the General table.
    Insert-GeneralData -DbPath $DbPath -Data $GeneralData -GroupMapping $GroupMapping

    # Return the pending reboot status.
    return $PendingRestart
}

#Get the WIndows Username from a SID
function Get-UserNameFromSid {
    param(
        [Parameter(Mandatory)]
        [string]$Sid
    )
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
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

function Set-FileExclusiveAcl {
    <#
    # ---------------------------------------------------
    # Example Usage:
    # ---------------------------------------------------
    $sqliteFilePath = "C:\Temp\MySQLiteDB.sqlite"
    $targetAccount = "MYDOMAIN\ServiceAccount"  # Change to your account
    Set-SQLiteFileExclusiveAcl -FilePath $sqliteFilePath -Account $targetAccount -Rights FullControl -ReplaceOwner
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$Account,
        [Parameter(Mandatory = $false)]
        [ValidateSet("FullControl", "Modify", "ReadAndExecute", "Read", "Write")]
        [string]$Rights = "FullControl",
        [Parameter(Mandatory = $false)]
        [switch]$ReplaceOwner
    )

    try {
        # Verify the file exists
        if (-not (Test-Path -Path $FilePath)) {
            throw "The file '$FilePath' does not exist."
        }

        # Retrieve the current ACL for the file
        $acl = Get-Acl -Path $FilePath

        # Disable inheritance and remove all inherited ACEs.
        # The second parameter 'false' means do NOT preserve inherited rules.
        $acl.SetAccessRuleProtection($true, $false)

        # Remove all existing explicit access rules.
        $existingRules = @($acl.Access)
        foreach ($rule in $existingRules) {
            $acl.RemoveAccessRuleAll($rule)
        }

        # Create a new access rule for the specified account.
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Account,
            $Rights,
            "ContainerInherit, ObjectInherit",
            "None",
            "Allow"
        )

        # Add the new rule.
        $acl.AddAccessRule($accessRule)

        # Apply the updated ACL to the file.
        Set-Acl -Path $FilePath -AclObject $acl

        Write-Host "Successfully updated ACL for '$FilePath'. Only '$Account' now has '$Rights' access."

        # If the ReplaceOwner switch is set, update the file owner.
        if ($ReplaceOwner) {
            Set-FileOwner -FilePath $FilePath -OwnerAccount $Account
        }
    }
    catch {
        Write-Error "Failed to update ACL for '$FilePath': $_"
    }
}
function Set-FileOwner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$OwnerAccount
    )
    try {
        # Verify the file exists
        if (-not (Test-Path -Path $FilePath)) {
            throw "The file '$FilePath' does not exist."
        }
        
        # Get the current ACL for the file
        $acl = Get-Acl -Path $FilePath
        
        # Create an NTAccount object for the new owner
        $newOwner = New-Object System.Security.Principal.NTAccount($OwnerAccount)
        
        # Replace the owner
        $acl.SetOwner($newOwner)
        
        # Apply the updated ACL (with the new owner) to the file
        Set-Acl -Path $FilePath -AclObject $acl
        
        Write-Host "Successfully replaced the owner of '$FilePath' with '$OwnerAccount'."
    }
    catch {
        Write-Error "Failed to set owner on '$FilePath': $_"
    }
}

function Test-EnrollmentStatus {
    [CmdletBinding()]
    param()

    # Initialize flags.
    $workspaceOneInstalled = $false
    $workspaceOneRegistryStatus = $false
    $isWorkspaceONEEnrolled = $false
    $isOMADMEnrolled = $false

    # --- Workspace ONE Enrollment Checks ---

    # 1. Check for "Workspace ONE Intelligent Hub Installer" via WMI.
    try {
        $wmiResult = Get-WmiObject -Class win32_Product -Filter "Name='Workspace ONE Intelligent Hub Installer'" -ErrorAction SilentlyContinue
        if ($wmiResult) {
            $workspaceOneInstalled = $true
        }
    }
    catch {
        # Optionally log or handle errors.
    }

    # 2. Check the registry key for Workspace ONE Enrollment Status.
    try {
        $regPath = "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
        if (Test-Path $regPath) {
            $statusValue = (Get-ItemProperty -Path $regPath -Name "Status" -ErrorAction SilentlyContinue).Status
            if ($statusValue -eq "Completed") {
                $workspaceOneRegistryStatus = $true
            }
        }
    }
    catch {
        # Optionally log or handle errors.
    }

    if ($workspaceOneInstalled -and $workspaceOneRegistryStatus) {
        $isWorkspaceONEEnrolled = $true
    }

    # --- OMA-DM Enrollment Check ---
    try {
        $omaDmAccountsPath = "HKLM:\Software\Microsoft\Provisioning\OMADM\Accounts"
        if (Test-Path $omaDmAccountsPath) {
            $subkeys = Get-ChildItem -Path $omaDmAccountsPath -ErrorAction SilentlyContinue
            if ($subkeys -and $subkeys.Count -gt 0) {
                $isOMADMEnrolled = $true
            }
        }
    }
    catch {
        # Optionally log or handle errors.
    }

    # Return a custom object with the results.
    $result = [PSCustomObject]@{
        IsWorkspaceONEEnrolled   = $isWorkspaceONEEnrolled
        IsOMADMEnrolled          = $isOMADMEnrolled
        WorkspaceONEInstalled    = $workspaceOneInstalled
        WorkspaceONERegistryStatus = $workspaceOneRegistryStatus
    }

    return $result
}

function Test-ProxyConfig {
    param (        
        # Database path for logging results to the HUB and Errors tables.
        [Parameter(Mandatory = $true)]
        [string]$DbPath
    )


    # Build a hashtable with the proxy test results.
    $ProxyData = @{}

    # INET Proxy result.
    if ($INETDetected -eq $true) {
        $ProxyData["INET Proxy Status"] = "Proxy enabled. Server: $INETServer"
    }
    else {
        $ProxyData["INET Proxy Status"] = "Proxy disabled"
    }

    # WINHTTP Proxy result.
    if ($WINHTTPDetected -eq $true) {
        $ProxyData["WINHTTP Proxy Status"] = "Proxy configured: $($WINHTTP[3])"
    }
    else {
        $ProxyData["WINHTTP Proxy Status"] = "No proxy configured"
    }

    # BITS Proxy result.
    if ($BITSDetected -eq $true) {
        $ProxyData["BITS Proxy Status"] = "Proxy configured. LocalSystem: $($BITSLOCALSYSTEM[5]) $($BITSLOCALSYSTEM[8]); " + `
            "NetworkService: $($BITSNETWORKSERVICE[5]) $($BITSNETWORKSERVICE[8]); " + `
            "LocalService: $($BITSLOCALSERVICE[5]) $($BITSLOCALSERVICE[8])"
    }
    else {
        $ProxyData["BITS Proxy Status"] = "No proxy configured"
    }

    # Overall Proxy Status.
    if ((-not $INETDetected) -and (-not $WINHTTPDetected) -and (-not $BITSDetected)) {
        $ProxyData["Overall Proxy Status"] = "No proxy detected"
    }
    else {
        $ProxyData["Overall Proxy Status"] = "Proxy detected"
    }

    # Build a group mapping so that all keys (except "Timestamp") are assigned to the "Proxy" group.
    $GroupMapping = @{}
    foreach ($key in $ProxyData.Keys) {
            $GroupMapping[$key] = "Proxy"
    }

    # Call the Insert-GeneralData function to update the General table.
    Insert-GeneralData -DbPath $dbPath -Data $ProxyData -GroupMapping $GroupMapping

    Write-Output "Proxy results have been inserted/updated into the General table under the group 'Proxy'."

}

function Save-Configuration {
    [CmdletBinding()]
    param(
        # Path to the SQLite database file.
        [Parameter(Mandatory = $true)]
        [string]$DbPath,
        
        # Path to the JSON configuration file.
        [Parameter(Mandatory = $true)]
        [string]$ConfigJsonPath
    )

    try {
        # Read the JSON file as a single string and convert it to a PowerShell object.
        $configData = Get-Content -Path $ConfigJsonPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to read or parse the JSON configuration file: $_"
        return
    }

    # Convert the configuration object to a hashtable.
    $configHash = @{}
    foreach ($prop in $configData.PSObject.Properties) {
        $configHash[$prop.Name] = $prop.Value
    }

    $connectionString = "Data Source=$DbPath;Version=3;"
    $conn = $null

    try {
        # Open a connection to the SQLite database.
        $conn = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $conn.Open()

        # Delete all existing rows from the Configurations table.
        $cmdDelete = $conn.CreateCommand()
        $cmdDelete.CommandText = "DELETE FROM Configurations;"
        $cmdDelete.ExecuteNonQuery() | Out-Null

        # Build the INSERT query.
        $columns = ($configHash.Keys | ForEach-Object { "`"$_`"" }) -join ", "
        $placeholders = ($configHash.Keys | ForEach-Object { "@$_" }) -join ", "
        $sql = "INSERT INTO Configurations ($columns) VALUES ($placeholders);"

        $cmdInsert = $conn.CreateCommand()
        $cmdInsert.CommandText = $sql

        # Bind parameters.
        foreach ($key in $configHash.Keys) {
            $param = $cmdInsert.CreateParameter()
            $param.ParameterName = "@$key"
            $param.Value = $configHash[$key]
            $cmdInsert.Parameters.Add($param) | Out-Null
        }

        $rowsAffected = $cmdInsert.ExecuteNonQuery()
        Write-Host "Configuration saved successfully to the Configurations table. Rows affected: $rowsAffected" -ForegroundColor Green

        #remove the file
        Remove-Item $ConfigJsonPath -Force
    }
    catch {
        Write-Error "Error saving configuration: $_"
    }
    finally {
        if ($conn -and $conn.State -eq 'Open') {
            $conn.Close()
        }
    }
}

function New-EncryptedString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PlainText,
        [Parameter(Mandatory = $true)]
        [string]$KeyString
    )

    try {
        # Derive a 256-bit key from the provided key string using SHA256.
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($KeyString))
        $sha256.Dispose()

        # Create an AES object.
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key
        $aes.GenerateIV()  # Generate a random IV.
        $iv = $aes.IV

        $encryptor = $aes.CreateEncryptor()
        $plainBytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
        $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        $aes.Dispose()

        # Prepend the IV to the encrypted bytes.
        $resultBytes = $iv + $encryptedBytes
        return [Convert]::ToBase64String($resultBytes)
    }
    catch {
        throw "Encryption failed: $_"
    }
}

function Read-EncryptedString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CipherText,
        [Parameter(Mandatory = $true)]
        [string]$KeyString
    )

    try {
        $allBytes = [Convert]::FromBase64String($CipherText)
        # The IV for AES is 16 bytes.
        $iv = $allBytes[0..15]
        $encryptedBytes = $allBytes[16..($allBytes.Length - 1)]

        # Derive the 256-bit key.
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($KeyString))
        $sha256.Dispose()

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key
        $aes.IV = $iv

        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        $aes.Dispose()

        return [Text.Encoding]::UTF8.GetString($decryptedBytes)
    }
    catch {
        throw "Decryption failed: $_"
    }
}

function New-RandomKeyString {
    [CmdletBinding()]
    param(
        # Length in bytes for the random key (default: 32 bytes for 256 bits)
        [Parameter(Mandatory = $false)]
        [int]$ByteLength = 32
    )
    
    # Create a byte array with the specified length.
    $byteArray = New-Object byte[] $ByteLength
    
    # Try to use the static Fill method if available.
    $rngType = [System.Security.Cryptography.RandomNumberGenerator]
    if ($rngType.GetMethod("Fill", [Reflection.BindingFlags] "Public, Static")) {
        # For .NET Core 3.0+ or .NET 5+, use the new Fill method.
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($byteArray)
    }
    else {
        # For older .NET Framework versions, use RNGCryptoServiceProvider.
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($byteArray)
        $rng.Dispose()
    }
    
    # Convert the byte array to a hexadecimal string (without dashes).
    $hexString = ([BitConverter]::ToString($byteArray)) -replace '-', ''
    return $hexString
}


function Invoke-RecoveryProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )
    $RecoveryScript = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    try {
        Write-Log "Starting execution of recovery process from $ScriptPath." "INFO"
        # Start the recovery process and wait for its completion
        $proc = Start-Process powershell.exe -ArgumentList $RecoveryScript -Wait -PassThru -ErrorAction Stop
        if ($proc.ExitCode -eq 0) {
            Write-Log "Recovery process executed successfully. Exit code: $($proc.ExitCode)" "INFO"
        }
        else {
            Write-Log "Recovery process failed with exit code: $($proc.ExitCode)" "ERROR"
            exit $proc.ExitCode
        }
    }
    catch {
        Write-Log "Error executing recovery process: $_" "ERROR"
        exit 1
    }
}

function New-EnrollmentScheduledTask {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Configuration,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash,
        [Parameter(Mandatory = $true)]
        [bool]$UseSystemAccount
    )

    $taskName = "WorkspaceONE Autorepair"
    $timeOfDay = "$($Configuration.EnrollmentTime)"
    $dayOfWeek = "$($Configuration.EnrollmentDay)"

    # Check if task already exists; if so, remove it for an update
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    if (-not $UseSystemAccount) {
        $scriptPath = "$DestinationPath\recovery.ps1"
        # Set the task to run as the currently logged-in user
        $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -LogonType Interactive
    }
    else {
        $scriptPath = "$DestinationPath\UEM_automatic_reenrollment.ps1"
        # Set the task to run as SYSTEM
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    }

    # Create an action to run the PowerShell script with the expected hash parameter
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ExpectedHash $ExpectedHash"
    # Create a trigger to run the task weekly on the specified day and time
    $trigger = New-ScheduledTaskTrigger -Weekly -At $timeOfDay -DaysOfWeek $dayOfWeek

    # Register the scheduled task
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal

    Write-Output "Scheduled task '$taskName' created successfully to run every $dayOfWeek at $timeOfDay."
}