
#Generate a random password
function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length,
        [int] $amountOfNonAlphanumeric = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length, $amountOfNonAlphanumeric)
}
$Password = Get-RandomPassword 10

#Create a temporary admin user with the random password
net user /add Installer $Password
net localgroup administrators installer /add

#Register the scheduled task to run the Workspace ONE enrollment after the device is rebooted and logged in as "Installer"
schtasks.exe /create  /tn "WorkspaceONE Enrollment" /RU installer /RP "$($Password)" /sc ONLOGON /tr "powershell -executionpolicy bypass -file C:\Recovery\OEM\Mover_Data\postmigration.ps1"

#Create a scheduled task to trigger the screen lock during the autologon 
$action = New-ScheduledTaskAction -Execute "%windir%\System32\rundll32.exe" -Argument "user32.dll,LockWorkStation"
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users"
$Task = New-ScheduledTask -Action $action -Principal $User 
Register-ScheduledTask "Screenlock" -InputObject $Task -Force

#Copy files to the destination folder
New-Item -Path "C:\Recovery\OEM\Mover_Data" -ItemType Directory -Force
New-Item -Path "C:\Recovery\OEM\Mover_Data" -Name "$($env:Computername).txt" -Force

Copy-Item "$PSScriptRoot\*" -Destination "C:\Recovery\OEM\Mover_Data" -Force 
#remove the .zip file to save storage
Get-ChildItem "C:\Recovery\OEM\Mover_Data" | Where-Object {$_.Name -like "*.zip"} | Remove-Item

#Confogure Autologon for the "installer" user
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "installer" -type String 
Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$($Password)" -type String
Set-ItemProperty $RegistryPath 'EnableFirstLogonAnimation' -Value "0" -Type String

#Skip user prompts after login
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "PrivacyConsentStatus" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "SkipUserOOBE" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "PrivacyConsentStatus" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "SkipUserOOBE" /t REG_DWORD /d 1 /f

#Start the start.ps1 script
$Arguments = "-file C:\Recovery\OEM\Mover_Data\start.ps1"
Start-Process powershell.exe -ArgumentList $Arguments -NoNewWindow -Wait