
##########################################################################################
# You running this script/function means you will not blame the author(s) if this breaks your stuff. 
# This script/function is provided AS IS without warranty of any kind. Author(s) disclaim all 
# implied warranties including, without limitation, any implied warranties of merchantability or of 
# fitness for a particular purpose. The entire risk arising out of the use or performance of the sample 
# scripts and documentation remains with you. In no event shall author(s) be held liable for any damages 
# whatsoever (including, without limitation, damages for loss of business profits, business interruption, 
# loss of business information, or other pecuniary loss) arising out of the use of or inability to use 
# the script or documentation. Neither this script/function, nor any part of it other than those parts 
# that are explicitly copied from others, may be republished without author(s) express written permission. 
# Author(s) retain the right to alter this disclaimer at any time.
##########################################################################################

#example: 
#reenroll.ps1 -KeepAppsInstalled True -Reenrolldevice True -DSServerURL "ds137.awmdm.com" -UserName "StagingUser" -UserPassword "StagingPassword" -OGID "TestOG" 

param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "If true - apps will stay on the device after un-enrollment")][String] $KeepAppsInstalled,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "If true - device gets re-enrolled")][String] $Reenrolldevice,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "URL of the DS Server - e.g. ds137.awmdm.com for CN137")][String] $DSServerURL,   
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Staginguser Username")][String] $UserName,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Staginguser Password")][String] $UserPassword,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Target OG ID")][String] $OGID
)


#Download the Intelligent HUB agent
if ($Reenrolldevice -eq "true") {
    if (!(Test-Path C:\Temp)) { New-Item C:\Temp -ItemType Directory -Force }
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile("https://$($DSServerURL)/agents/ProtectionAgent_autoseed/airwatchagent.msi", "C:\temp\AirwatchAgent.msi")
}



#Get Enrollment ID
$AllItems = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments -Recurse
$AirWatchMDMKey = $AllItems | Where-Object { $_.Name -like "*AirWatchMDM" }
$pattern = "Enrollments(.*?)\DMClient"
$EnrollmentKey = ([regex]::Match(($AirWatchMDMKey.PSPath), $pattern).Groups[1].Value).Replace("\", "")


#Uninstall SFD Agent
if ($KeepAppsInstalled -eq "true") {
    $SFDAgent = Get-WmiObject -Class win32_product -Filter "Name like '%SFD%'"
    $Arguments = "/x $($SFDAgent.IdentifyingNumber) /q /norestart"
    Start-Process msiexec -ArgumentList $Arguments -Wait 
}

#Uninstall Agent - requires manual delete of device object in console
$HUB = Get-WmiObject -Class win32_product -Filter "Name like '%Workspace ONE%'"
$Arguments = "/x $($HUB.IdentifyingNumber) /q /norestart"
Start-Process msiexec -ArgumentList $Arguments -Wait 

Start-Sleep -Seconds 120

#uninstall WS1 App
Get-AppxPackage *AirWatchLLC* | Remove-AppxPackage 
 
#Delete reg keys
Remove-Item -Path HKLM:\SOFTWARE\Airwatch -Recurse -Force
Remove-Item -Path HKLM:\SOFTWARE\AirwatchMDM -Recurse -Force



#Remove enrollment specific entries
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$($EnrollmentKey)" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($EnrollmentKey)" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxDefault\$($EnrollmentKey)" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($EnrollmentKey)" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\_ContainerAdmxDefault\*" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\device\ApplicationManagement\*" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($EnrollmentKey)" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Session\$($EnrollmentKey)" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAnytimeUpgrade\Attempts\*" -Recurse -Force



#Cleanup other registry
Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\omadm\Accounts\* -Recurse -Force
Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\* -Recurse -Force
Remove-Item -Path HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\*\MSI\* -Recurse -Force
 
#Delete folders
$path = "$env:ProgramData\AirWatch"
Remove-Item $path -Recurse -Force

$path = "$env:ProgramData\AirWatchMDM"
Remove-Item $path -Recurse -Force

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


#Install Workspace One Agent
if ($Reenrolldevice -eq $true) {
    $args = "/i C:\Temp\AirwatchAgent.msi /q ENROLL=Y SERVER=$($DSServerURL) LGName=$($OGID) USERNAME=$($UserName) PASSWORD=$($UserPassword) ASSIGNTOLOGGEDINUSER=Y DOWNLOADWSBUNDLE=FALSE IMAGE=N /LOG C:\Temp\WorkspaceONE.log"
    Start-Process C:\Windows\System32\msiexec.exe -ArgumentList $args -Wait
}
