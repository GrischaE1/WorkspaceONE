$ErrorActionPreference = 'SilentlyContinue'

#Remove the Skip User OOBE disablement
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -name "PrivacyConsentStatus"  -Force
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -name "DisablePrivacyExperience" -Force
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -name "SkipUserOOBE" -Force
Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -name "PrivacyConsentStatus"  -Force
Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -name "DisablePrivacyExperience" -Force
Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -name "SkipUserOOBE" -Force
Remove-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Cleanup" -Force

#Delete the scheduled tasks
schtasks.exe /delete  /tn "WorkspaceONE Enrollment" /f
Disable-ScheduledTask -TaskName "Cleanup" 
Unregister-ScheduledTask -TaskName "Cleanup" 
Unregister-ScheduledTask -TaskName "Screenlock" 

#Delete the temporary admin user
net user /delete Installer

#Delete the user profile
Remove-Item C:\Users\Installer -Recurse -Force 