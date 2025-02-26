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
.\ws1_autorepair.ps1 -providerID "AirwatchMDM" -logFilePath "C:\Logs\Log.txt" -ExpectedHash "<HashValue>" -EnableReEnrollment
===============================================================================

PARAMETERS:
- providerID: Specifies the MDM provider (default: AirwatchMDM).
- logFilePath: Path for saving logs (default: C:\Windows\UEMRecovery\Logs\MDM_Validation_Log.txt).
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
    [string]$logFilePath = "C:\Windows\UEMRecovery\Logs\MDM_Validation_Log.txt",

    #The Hash value for this script, to make sure the script was not modified
    [Parameter(Mandatory = $true)]
    [string]$ExpectedHash,

    #Switch parameter to enable the automatic re-enollment when an error was detected
    [Parameter(HelpMessage = "Switch parameter to enable the automatic re-enollment when an error was detected")]
    [switch]$EnableReEnrollment

)

#Import Functions
. "$PSScriptRoot\UEM_Status_Check_Functions.ps1"
. "$PSScriptRoot\OMA-DM_Status_Check_Functions.ps1"
. "$PSScriptRoot\General_Functions.ps1"
. "$PSScriptRoot\SQLFunctions.ps1"

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
# Start Script if no user is logged in

 #Get the MDM ernollment error status
 $MDMEnrollmentErrorStatus = Get-MDMEnrollmentDetails -ProviderID $providerID
 $ScheduledTaskErrorStatus = Test-ScheduledTasks -activeMDMID $MDMEnrollmentErrorStatus[0]
 $IntelligentHubErrorStatus = Get-WorkspaceONEHubStatus

if ($EnableReEnrollment -and (Get-UserLoggedIn) -eq $false) {

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

