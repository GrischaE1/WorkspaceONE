<#
===============================================================================
Script Name: recovery.ps1
Description: Performs unenrollment of Workspace ONE, removes all associated 
artifacts (applications, registry keys, certificates, etc.), and re-enrolls 
the device into Workspace ONE.

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
.\recovery.ps1
===============================================================================

NOTES:
- Automatically downloads the Workspace ONE Agent and re-enrolls the device.
- Removes all previous MDM configurations, applications, and certificates.
- Includes hardcoded staging credentials for enrollment—replace with secure 
  alternatives for production use.
- Requires administrative privileges to execute.
===============================================================================
#>


$WSOStagingUser = "test"
$WSOStagingPW = 'test'
$WSOOGID = "WS1"
$WSOServer = "ds1831.awmdm.com"


    #Wait for explorer to be started
    do{
        $Process = Get-Process -Name explorer
        if($Process)
        {
            Start-Sleep 20 
            Start-ScheduledTask "Screenlock"
        }
    }while(!$Process)

    
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile("https://$($WSOServer)/agents/ProtectionAgent_autoseed/airwatchagent.msi", "C:\Windows\UEMRecovery\AirwatchAgent.msi")


    #Get Enrollment ID
    $AllItems = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments -Recurse
    $AirWatchMDMKey = $AllItems | Where-Object { $_.Name -like "*AirWatchMDM" }
    $pattern = "Enrollments(.*?)\DMClient"
    $EnrollmentKey = ([regex]::Match(($AirWatchMDMKey.PSPath), $pattern).Groups[1].Value).Replace("\", "")

    
    #Uninstall SFD to avoid application uninstallation
    $Registry = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object {$_.GetValue('DisplayName') -like "*SfdAgent*"})
    $SFDUninstall = "/x $($registry.PSChildName) /q"
    Start-Process MsiExec.exe -ArgumentList $SFDUninstall -Wait

    #Remove SFD and OMA-DM Registry keys to avoid application uninstallation
    Remove-Item HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement -Recurse -Force
    Remove-Item HKLM:\SOFTWARE\AirWatchMDM -Recurse -Force

    #Remove Intelligent Hub
    $HubData = Get-WmiObject Win32_Product | Where-Object {$_.Name -like "*Intelligent HUB Installer*"}
    $HubUninstall = "/x $($HubData.IdentifyingNumber) /q"
    Start-Process MsiExec.exe -ArgumentList $HubUninstall -Wait

    #Sleep for 60 seconds to make sure Hub is uninstalled
    Start-Sleep -Seconds 60

    #uninstall WS1 App
    Get-AppxPackage *AirWatchLLC* | Remove-AppxPackage 

    #Remove Enrollment registry keys
    Remove-Item -Path "HKLM:\SOFTWARE\AirWatch" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Enrollments" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\logger" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID" -Recurse -Force    
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($EnrollmentKey)" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxDefault\$($EnrollmentKey)" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($EnrollmentKey)" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\_ContainerAdmxDefault\*" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\device\ApplicationManagement\*" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($EnrollmentKey)" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Session\$($EnrollmentKey)" -Recurse -Force
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAnytimeUpgrade\Attempts\*" -Recurse -Force


    #Delete folders
    $path = "$env:ProgramData\AirWatch"
    Remove-Item $path -Recurse -Force

    #$path = "$env:ProgramData\AirWatchMDM"
    #Remove-Item $path -Recurse -Force

    $path = "$env:ProgramData\VMware\SfdAgent"
    Remove-Item $path -Recurse -Force


    #Clean Scheduled Tasks - SFD
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$($EnrollmentKey)\*" | Unregister-ScheduledTask  -Confirm:$false

    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
    $rootFolder.DeleteFolder("$($EnrollmentKey)", $null)

    #Clean Scheduled Tasks - SFD
    Get-ScheduledTask -TaskPath "\vmware\SfdAgent\*" | Unregister-ScheduledTask  -Confirm:$false

    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\vmware")
    $rootFolder.DeleteFolder("SfdAgent", $null)
    
    #Delete user certificates
    $UserCerts = Get-ChildItem cert:"CurrentUser" -Recurse
    $UserCerts | Where-Object { $_.Issuer -like "*AirWatch*" -or $_.Issuer -like "*AwDeviceRoot*" } | Remove-Item -Force

    #Delete device certificates
    $DeviceCerts = Get-ChildItem cert:"LocalMachine" -Recurse
    $DeviceCerts | Where-Object { $_.Issuer -like "*AirWatch*" -or $_.Issuer -like "*AwDeviceRoot*" } | Remove-Item -Force

    #Enroll the device to UEM
    $List =  "/q ENROLL=Y SERVER=https://$($WSOServer) LGName=$($WSOOGID) USERNAME=$($WSOStagingUser) PASSWORD=$($WSOStagingPW) ASSIGNTOLOGGEDINUSER=Y"
    Start-Process "C:\Windows\UEMRecovery\AirwatchAgent.msi" -ArgumentList $List -Wait



#Generate 10 minute timer
$timeout = new-timespan -Minutes 10
$sw = [diagnostics.stopwatch]::StartNew()
$enrollcheck = $false

do {
    Start-Sleep -Seconds 10
    #Check every 10 seconds if the device is enrolled
    $enrolltemp = Get-Item -Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
    If ($enrolltemp.GetValue("Status") -eq 'Completed') {
        $enrollcheck = $true
        
        #Remove autologon settings
        $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Remove-ItemProperty $RegistryPath -name "AutoAdminLogon"
        Remove-ItemProperty $RegistryPath -name "DefaultUsername" 
        Remove-ItemProperty $RegistryPath -name "DefaultPassword" 

        #Remove the "Installer" account information from the login screen
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "LastLoggedOnUser" -PropertyType String -Value "" -Force
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "LastLoggedOnUserSID" -PropertyType String -Value "" -Force
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "LastLoggedOnDisplayName" -PropertyType String -Value "" -Force
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "LastLoggedOnSamUser" -PropertyType String -Value "" -Force
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "SelectedUserSID" -PropertyType String -Value "" -Force

        #Restart the device
        $shutdown = "/r /t 20 /f"
        Start-Process shutdown.exe -ArgumentList $shutdown

        #Disable the Scheduled task
        Unregister-ScheduledTask -TaskName "WorkspaceONE Recovery" -Confirm:$false

    }
}while ($enrollcheck -eq $false -and $sw.elapsed -lt $timeout)