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