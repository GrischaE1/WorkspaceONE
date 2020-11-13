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



##########################################################################################
# Name: CheckEnrollemnt.ps1
# Version: 0.7
# Date: 8.8.2020
# Created by: Grischa Ernst gernst@vmware.com
#
# Description
# - (Optional for Factory Provisioning and AD join scenraio) Lock the local admin account - user can't login since user don't know the local admin account password
# - check the enrollemnt status of the Workspace ONE agent via registry
# - check the enrollment status of the device via API against the Workspace One console
# - check installed apps and wait till all automatic assigend apps are installed
# - check if all profiles are installed
# - clean up registry and files
# - (Optional for Factory Provisioning and AD join scenraio) restart the device so the user is able to login
#
#
##########################################################################################
#                                    Changelog 
#
# 0.7 - Changed Application detection to registry to reduce API calls
# 0.6 - Added external Credential encryption
# 0.5 - Added application installation verification
# 0.4 - Added profile installation verification
# 0.3 - Added API enrollment check + User Account Picture
# 0.2 - Added lock screen + lock device function
# 0.1 - inital creation - check enrollment status against registry
##########################################################################################




##########################################################################################
#Declare varibales

#Set API variable
#API Server
$APIEndpoint = "as137.awmdm.com"
#Your OG ID (shortform of your OG)
$OG = "OGID"

#Download URLs
$CertURL = "https://winsettings.blob.core.windows.net/winsettings/APIEncryption.pfx?sv=201"

$CredFileURL = "https://winsettings.blob.core.windows.net/winsettings/encryptedpassword.txt?sv=201"

$AESKeyURL = "https://winsettings.blob.core.windows.net/winsettings/AESKey.key?sv=201"

$APIInfoFileURL = "https://winsettings.blob.core.windows.net/winsettings/APIInfo.txt?sv=201"

$Logpath = "C:\Temp\Enrollment.log"

##########################################################################################
#Start script


#inform the user
Write-Host ""
Write-Host "###################################################" -ForegroundColor red
Write-Host ""
Write-Host "Please wait till the system is installed"
Write-Host ""
Write-Host "Please do not turn off the PC"
Write-Host ""
Write-Host "You will be logged out soon - the system will restart when finished"
Write-Host ""
Write-Host "If the normal Login screen appears, please log in with your domain credentials"
Write-Host "" 
Write-Host "###################################################" -ForegroundColor red


#set prerequisites
#get current logged on user SID
$usersid = (whoami /user /FO csv | ConvertFrom-Csv).sid

#create Temp folder
if ((Test-Path -Path "C:\Temp") -eq $false) { New-Item -Path "C:\Temp" -ItemType Directory }

#start logging
Start-Transcript -Force -Path $Logpath


###########
#Wait till system is running
Write-Output "Check if System is fully loaded"
do {
    Start-Sleep -Seconds 10
    $explorer = Get-Process -name explorer -ErrorAction SilentlyContinue

    if ($explorer) {
        do {
            $AWAgent = Get-Process -Name AWWindowsLpc -ErrorAction SilentlyContinue
            if ($AWAgent) {
                $started = $true
            }
            else { start-sleep -Seconds 10 }
        }while ($started -eq $true)
    }
}while ($started -eq $true)




#Lock device - not needed if spashscreen is used
#rundll32.exe user32.dll, LockWorkStation


##############################
#Get API Credentials

Write-Output "Generating API credentials"

#Download Certificate
$output = "C:\Temp\APICert.pfx"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($CertURL, $output)

#Download Credential Files
$output = "C:\Temp\encryptedpassword.txt"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($CredFileURL, $output)

$output = "C:\Temp\AESKey.key"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($AESKeyURL, $output)


#Download API Information file
$output = "C:\Temp\APIInfo.txt"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($APIInfoFileURL, $output)

#create Password file
#$Key = New-Object Byte[] 32
#[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
#$Key | out-file C:\Temp\CertKey.key
#(get-credential).Password | ConvertFrom-SecureString -key (get-content C:\Temp\CertKey.key) | set-content "C:\Temp\encryptedpassword.txt"


$password = Get-Content "C:\Temp\encryptedpassword.txt" | ConvertTo-SecureString -Key (Get-Content C:\Temp\AESKey.key)

#Import Certificate
Import-PfxCertificate -filepath "C:\Temp\APICert.pfx" -Password $password -CertStoreLocation Cert:\CurrentUser\My

Clear-Variable password -Force

$EFSContent = Unprotect-CmsMessage -Path C:\Temp\APIInfo.txt 
$APICreds = $EFSContent -split "`n" | % { $_.trim() }

Foreach ($Creds in $APICreds) {
    if ($Creds -like "*APIUser*") {
        $APIUser = $Creds -replace "^.*?:"
    }
    if ($Creds -like "*APIPassword*") {
        $APIPassword = $Creds -replace "^.*?:"
    }
    if ($Creds -like "*APIKey*") {
        $APIKey = $Creds -replace "^.*?:" 
    }
}

#Delete certificate and source files
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*APIEncryption*" } | Remove-Item -Force
Remove-Item "C:\Temp\APICert.pfx" -Force
Remove-Item "C:\Temp\encryptedpassword.txt" -Force
Remove-Item "C:\Temp\AESKey.key" -Force
Remove-Item "C:\Temp\APIInfo.txt" -Force

#Check if credentials are loaded 
if ($APIUser -and $APIPassword -and $APIKey) {
    Write-Host "Credentials fully loaded" -ForegroundColor Green
}
else { 
    Write-Host "Credentials failed to load" -ForegroundColor Red
    break
}



#generate API Credentials
$UserNameWithPassword = $APIUser + “:” + $APIPassword
$Encoding = [System.Text.Encoding]::ASCII.GetBytes($UserNameWithPassword)
$EncodedString = [Convert]::ToBase64String($Encoding)
$Auth = "Basic " + $EncodedString

#generate header
$Headers = @{"Authorization" = $Auth; "aw-tenant-code" = $APIKey }
$ContentType = 'application/json'


Start-Sleep -Seconds 60

##############################
#Check enrollment
Write-Output "Check enrollment status"
do {
    #Wait for installation
    do {
        Start-Sleep -Seconds 10
        $AWinstalled = Test-Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
    }while ($AWinstalled -eq $false)

    <#
    #Check if AutoLogonCount REG Key is set to 0 (will be deleted as part of the unattend commands
    $logontemp = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    If ($logontemp.GetValue("AutoLogonCount") -eq '0') {
        $regcheck = $true
    }
#>


    #Check registry if device is enrolled
    $enrolltemp = Get-Item -Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
    If ($enrolltemp.GetValue("Status") -eq 'Completed') {
        $enrollcheck = $true
    }


    ##############################
    #API Call to get Enrollement stauts
    if ($enrollcheck -eq $true) {


        #get current computer object in WSO via serialnumber
        $computerserial = gwmi win32_bios | Select –ExpandProperty SerialNumber

        do {
            $Uri = "https://$($APIEndpoint)/API/mdm/devices?searchBy=Serialnumber&id=$($computerserial)"
            $WSODevice = Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType
            $DeviceID = $WSODevice.id.Value
            
            if ($DeviceID) {
                $DeviceFound = $true
            }
            else { Start-Sleep -Seconds 30 }
        }while ($DeviceFound -eq $false)


        #get enrollment Status
        $Uri = "https://$($APIEndpoint)/API/mdm/devices/udid/$($WSODevice.Udid)/deviceenrollmentstatus?organizationgroupid=$($OG)"
        $WSOEnrollmentStatus = Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType

        if ($WSOEnrollmentStatus.EnrollmentStatus -eq '4') {
            $WSOEnrolled = $true
        }
        else {
            Start-Sleep -Seconds 60
        }
    }

}while ($regcheck -eq $false -or $enrollcheck -eq $false -or $WSOEnrolled -eq $false)

Write-Output "Device enrolled with ID $($DeviceID)"




##############################
#Check installed profiles
#Status 1 = assigned - not installed
#Status 3 = installed
#Status 6 = failed


Write-Output "Check if all profiles are installed"

#Check Profile installation status
$Uri = "https://$($APIEndpoint)/API/mdm/devices/$($DeviceID)/profiles"
$Profiles = (Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType).DeviceProfiles

foreach ($Profile in $Profiles) {
    if ($Profile.Status -ne '3') {
        Clear-Variable ProfileSet -Force
        $retrycount = 0
                
        #three time retry to detect installation status of the profile
        do {
            $UpdatedStatus = (Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType).DeviceProfiles | Where-Object { $_.id.value -eq $Profile.Id.Value }
                        
            if ($UpdatedStatus.Status -ne '3') {
                $ProfileSet = $false
                Write-Host "The Profile $($Profile.Name) is not installed" -ForegroundColor Red
                $retrycount = $retrycount + 1 
                Start-Sleep -Seconds 60
            }
            else {
                $ProfileSet = $true
                Write-Host "Profile $($Profile.name) installed" -ForegroundColor Green
            }

        }while ($ProfileSet -eq $false -and $retrycount -lt 3)
    }
    else { Write-Host "Profile $($Profile.name) installed" -ForegroundColor Green }
}



##############################
#Check installed apps
#Status 2 = installed
#Status 5 = assigned

Write-Output "Get all assigned apps"

#Trigger device query to update latest information
$Uri = "https://$($APIEndpoint)/API/mdm/devices/$($DeviceID)/commands?command=DeviceQuery"
Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType -Method Post
Start-Sleep -Seconds 120


#Get all assigned smart groups of device        
$Uri = "https://$($APIEndpoint)/API/mdm/devices/$($DeviceID)/smartgroups"
$SmartGroups = Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType 
$smartgroupIDs = ($SmartGroups.SmartGroup  | Where-Object { $_.SmartGroupName -ne "All Devices" -and $_.SmartGroupName -ne "All Corporate Dedicated Devices" }).SmartGroupId

$AssignedApps = @()

#Get all assigned applictions - this is for get the information if app is assigned as Auto or ondemand
foreach ($ID in $smartgroupIDs) {
    #Get all assigned apps
    $Uri = "https://as137.awmdm.com/API/mdm/smartgroups/$($Id.Value)/apps"
    $result = Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType 
    if ($result) { $AssignedApps += $result }
    Clear-Variable result -Force
}


#Get all inventoried and assigned apps
$Uri = "https://$($APIEndpoint)/API/mdm/devices/$($DeviceID)/apps"
$Apps = Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType
$Apps = $Apps.DeviceApps | Where-Object { $_.IsManaged -eq $true -and $_.Type -eq "Internal" } #-and $_.ApplicationName -like "*notepad*"}


$AutoInstallApps = @()
$RequiredApps = @()

#Check if all AUTO assigned apps are installed or not
foreach ($app in $Apps) {
    #Get the Application infromation 
    $Uri = "https://$($APIEndpoint)/API/mam/apps/internal/$($app.Id.Value)"
    $AppUUID = (Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType).UUID
    
    #Get the Application deployment assignment to check if Auto or ondemand
    $Uri = "https://$($APIEndpoint)/API/mam/apps/$($AppUUID)/assignment-rule"
    $assignments = (Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType).assignments
   

    foreach ($deployment in $assignments.distribution) {
        foreach ($ID in $smartgroupIDs) {
            $Uri = "https://$($APIEndpoint)/API/mdm/smartgroups/$($ID.Value)"
            $RestError = $null
            Try {
                $SmartGroupInfo = Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType -ErrorAction SilentlyContinue
            }
            Catch {
                $RestError = $_
            }

            if ($SmartGroupInfo.SmartGroupUuid -eq $deployment.smart_groups) {
                Write-Host "Deployment" $deployment.name "on:" $SmartGroupInfo.Name
                if ($deployment.app_delivery_method -eq "AUTO") {
                    $AutoInstallApps += $app.id.Value
                    $RequiredApps += $app
                }
            }                    
                    
        }
    }

}


#Get the current installation status of all not installed AUTO assigned apps
#Will wait for 60 minutes for every app to install - otherwise the next app will be checked

Write-Output "Wait for installation of all Apps - check via registry"

foreach ($installcheck in $RequiredApps) {
    $installed = $false
    $starttime = Get-Date 
    do {
        
        #$installcheck.ApplicationIdentifier
        $AppIdentifyer = (Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests' -Recurse | Get-ItemProperty | where { $_ -match $($installcheck.ApplicationIdentifier.ToUpper()) }).PSChildName
        $InstallTest = Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\S*' -Recurse | Where-Object { $_.PSChildName -eq $AppIdentifyer }
    
        if (!$InstallTest) {
            $RegCheck = Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\S*' -Recurse | Where-Object { $_.PSChildName -eq $installcheck.ApplicationIdentifier.ToUpper() }
            if (!$RegCheck) {
                Write-Host "Warning! Application $($installcheck.ApplicationIdentifier.ToUpper()) is missing" -ForegroundColor Red
                Write-Host $installcheck.ApplicationName "was not detected" -ForegroundColor Red
            }
            else {
                $installed = Get-ItemPropertyValue -Path $($RegCheck.Name.Replace('HKEY_LOCAL_MACHINE', 'HKLM:')) -Name IsInstalled
                Write-Host $installcheck.ApplicationName "was successfully installed" -ForegroundColor Green
            }
        }
        else {
            $installed = Get-ItemPropertyValue -Path $($InstallTest.Name.Replace('HKEY_LOCAL_MACHINE', 'HKLM:')) -Name IsInstalled
            Write-Host $installcheck.ApplicationName "was successfully installed" -ForegroundColor Green
        }
   

    }while ($Installed -ne $true -and $starttime.AddMinutes(60))

}


#Trigger app samples via API
$Uri = "https://$($APIEndpoint)//API/mdm/devices/$($DeviceID)/commands?command=applistsample"
Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType -Method Post
Start-Sleep -Seconds 30


$Uri = "https://$($APIEndpoint)/API/mdm/devices/$($DeviceID)/apps"
$AssignedApps = Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType
        
#Get the current installation status of all not installed AUTO assigned apps
#Will wait for 60 minutes for every app to install - otherwise the next app will checked

Write-Output "Wait for installation of all Apps - check via API"

if ($AutoInstallApps) {
    $Appsinstalled = $false
    
    Write-Output "Checking if following apps are detected in Console"
    $RequiredApps.ApplicationName

    #get latest application status via API
    $Uri = "https://$($APIEndpoint)/API/mdm/devices/$($DeviceID)/apps"
    $AssignedApps = Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType

            
    foreach ($verify in $RequiredApps) {
        
        #Write-Output "Current app is $($Verify.ApplicationName)"

        $ApplicationID = $verify.ID.Value
       
        $Missingapp = $AssignedApps.DeviceApps | Where-Object { $_.id.value -eq $ApplicationID }
        if ($Missingapp.status -ne 2) {
            Write-Host "App $($Missingapp.ApplicationName) not installed" -ForegroundColor Red

        }
        else {
            Write-Host "App $($Missingapp.ApplicationName) is now installed" -ForegroundColor Green
        }    
    }
}



<#
#Restart device
if ($regcheck -eq $true -and $enrollcheck -eq $true -and $WSOEnrolled -eq $true) {
    #Trigger device query to update latest information
    $Uri = "https://$($APIEndpoint)/API/mdm/devices/$($DeviceID)/commands?command=DeviceQuery"
    Invoke-RestMethod -Uri $uri -Headers $Headers -ContentType $ContentType -Method Post
    Start-Sleep -Seconds 120

    Write-Output "Enrollment complete - Restart triggered"

    Stop-Transcript
    Restart-Computer -Force
}
else{

    Write-Output "Enrollment failed - please check logs"
}
#>