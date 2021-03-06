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
# Name: MEM_to_WSO_Migration.ps1
# Version: 0.1
# Date: 1.11.2020
# Created by: Grischa Ernst gernst@vmware.com
#
# Description
# - Remove the Intune management via API
# - Install the lates HUB version
# - Uninstall the SCCM agent (if not needed remove the function)
#
#
##########################################################################################
#                                    Changelog 
#
# 0.1 - inital creation
##########################################################################################



##########################################################################################
#Define varibales
#Intune API Admin User
$username= "Username@Domain.com"
$password =ConvertTo-SecureString "Password IN Plaintext" -AsPlainText -Force

#Client ID see Azure Portal -> Azure Active Directory -> Enterprise Apps -> Microsoft Intune Powershell -> Application ID
#or create an own application see https://docs.microsoft.com/en-us/mem/intune/developer/intune-graph-apis
$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

#Workspace ONE settings
#your device server 
$WSOServer = "ds137.awmdm.com"
#Your OG ID (shortform of your OG)
$WSOOGID = "OGID"
#Staging user - just the username (not the mail)
$WSOStagingUser = "stagingUSER"
#Staging Password
$WSOStagingPW = "StagingPassword"

##########################################################################################
#                                       Functions

#Generate Auth Token for Azure Graph API
function Get-AuthToken {
    <#
        .SYNOPSIS
        This function is used to authenticate with the Graph API REST interface
        .DESCRIPTION
        The function authenticate with the Graph API Interface with the tenant name
        .EXAMPLE
        Get-AuthToken
        Authenticates you with the Graph API interface
        .NOTES
        NAME: Get-AuthToken
    #>

    [cmdletbinding()]
    $user =$username
    $userUpn =New-Object "System.Net.Mail.MailAddress"-ArgumentList $User
    $tenant =$userUpn.Host
    $clientId = $AzureclientId
    $redirectUri ="urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI ="https://graph.microsoft.com"
    $authority ="https://login.microsoftonline.com/$Tenant"

    try {
            $authContext =New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext"-ArgumentList $authority
            # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
            $platformParameters =New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters"-ArgumentList "Auto"
            $userId =New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier"-ArgumentList ($User,"OptionalDisplayableId")
            $authResult =$authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId,"prompt=admin_consent").Result

            if($authResult.AccessToken){
                # Creating header for Authorization token
                $authHeader = @{
                    'Content-Type'='application/json'
                    'Authorization'="Bearer " + $authResult.AccessToken
                    'ExpiresOn'=$authResult.ExpiresOn
            }
            return $authHeader
            }
            else {break}
    }

    catch {
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    }
}


#Uninstall SCCM Agent 
function  Uninstall-SCCMAgent
{
<#
    .SYNOPSIS
    This function is used to uninstall the SCCM agent
    .DESCRIPTION
    The function will remove the SCCM agent and all stored SCCM data
    .EXAMPLE
    uninstall-SCCMAgent
    .NOTES
    NAME: uninstall-SCCMAgent
#>
$ErrorActionPreference = "SilentlyContinue"

# Uninstall SCCM Agent with smssetup.exe
$MyPath = $env:WinDir
& "$MyPath\ccmsetup\ccmsetup.exe" /uninstall | Out-Null

# Stop Services
Stop-Service -Name 'ccmsetup' -Force 
Stop-Service -Name 'CcmExec' -Force 
Stop-Service -Name 'smstsmgr' -Force 
Stop-Service -Name 'CmRcService' -Force 

# Remove Services
sc delete ccmsetup
sc delete CcmExec
sc delete smstsmgr
sc delete CmRcService

# Remove WMI Namespaces
Get-WmiObject -query "SELECT * FROM __Namespace WHERE Name='CCM'" -Namespace "root" | Remove-WmiObject 
Get-WmiObject -query "SELECT * FROM __Namespace WHERE Name='SMS'" -Namespace "root\cimv2"  | Remove-WmiObject 

# Remove Services from Registry
$MyPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
Remove-Item -Path "$MyPath\CCMSetup" -Force -Recurse 
Remove-Item -Path "$MyPath\CcmExec" -Force -Recurse 
Remove-Item -Path "$MyPath\smstsmgr" -Force -Recurse
Remove-Item -Path "$MyPath\CmRcService" -Force -Recurse 

# Remove SCCM Client from Registry
$MyPath = "HKLM:\SOFTWARE\Microsoft"
Remove-Item -Path "$MyPath\CCM" -Force -Recurse 
Remove-Item -Path "$MyPath\CCMSetup" -Force -Recurse 
Remove-Item -Path "$MyPath\SMS" -Force -Recurse

# Remove SCCM Client from 64 Bit Registry
$MyPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft"
Remove-Item -Path "$MyPath\SMS" -Force -Recurse 
Remove-Item -Path "$MyPath\CCM" -Force -Recurse 

# Remove Folders and Files
$MyPath = $env:WinDir
Remove-Item -Path "$MyPath\CCM" -Force -Recurse
Remove-Item -Path "$MyPath\ccmsetup" -Force -Recurse
Remove-Item -Path "$MyPath\ccmcache" -Force -Recurse
Remove-Item -Path "$MyPath\SMSCFG.ini" -Force
Remove-Item -Path "$MyPath\SMS*.mif" -Force

# Remove Scheduled Task
Unregister-ScheduledTask -TaskName "Configuration Manager Health Evaluation" -Confirm:$False -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Configuration Manager Idle Detection" -Confirm:$False -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Configuration Manager Passport for Work Certificate Enrollment Task" -Confirm:$False -ErrorAction SilentlyContinue

# Remove Scheduled Task Folder
$scheduleObject = New-Object -ComObject schedule.service
$scheduleObject.connect()
$rootFolder = $scheduleObject.GetFolder("\Microsoft")
$rootFolder.DeleteFolder("Configuration Manager",$unll)

# Remove Certificates
Get-ChildItem -Path cert:\LocalMachine\SMS | Remove-Item 

}

##########################################################################################
#                                    Start Script 

#Install required PowerShell modules
Install-PackageProvider -Name Nuget -Force
Install-Module AzureAD -force
Install-Module WindowsAutoPilotIntune -Force 

#Create Temp path if not exists
$Test = Test-Path -Path "C:\Temp"
if($Test -eq $false)
{
    New-Item -Path "C:\Temp" -ItemType Directory
}

#Download the Workspace One Agent from www.getws1.com
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://packages.vmware.com/wsone/AirwatchAgent.msi","C:\temp\AirwatchAgent.msi")

#Generate Azure Graph API credentials
$creds =New-Object System.Management.Automation.PSCredential-ArgumentList ($username,$password)

#Import Windows Auto Pilot Module
Import-Module WindowsAutoPilotIntune -Scope Global
Connect-MSGraph -Credential $creds | Out-Null


# Getting the authorization token
$global:authToken = Get-AuthToken
$graphApiVersion ="beta"

#Get the Devices that are MDM managed
$Resource ="deviceManagement/managedDevices"
$uri = ("https://graph.microsoft.com/{0}/{1}?filter=managementAgent eq 'mdm' or managementAgent eq 'easMDM'"-f $graphApiVersion,$Resource)
$devices = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

   
#Get the current device
$currentdevice =  $devices |Where-Object{$_.devicename -eq $env:COMPUTERNAME}

write-output "Enrolled Username: $($currentdevice.userPrincipalName)"
write-output "Enrolled User ID:  $($currentdevice.userid)"

#get enrollmet information
$EnrollmentID = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status").PSChildName

ForEach($UUID in $EnrollmentID)
{
    $MDMAuthority = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Enrollments\$($UUID)").ProviderID
    if($MDMAuthority -eq "MS DM Server"){
        $Intuneenrolled = $true
        break
    }
}

#retire the device if Intune enrolled
if($Intuneenrolled -eq $true)
{
    $retire = ("https://graph.microsoft.com/{0}/{1}/{2}/retire" -f $graphApiVersion,$Resource,$currentdevice.id)
    Invoke-RestMethod -Uri $retire -Headers $authToken -Method Post

    do{
        Remove-Variable MDMAuthority -Force
        $MDMAuthority = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Enrollments\$($EnrollmentID)").ProviderID
        if($MDMAuthority)
        {
            if($MDMAuthority -eq "MS DM Server"){$Intuneenrolled = $true}
        }
        else{$Intuneenrolled = $false}

        Start-Sleep -Seconds 5
    }while($Intuneenrolled -eq $true)
}

#Install Workspace One Agent
$args = "/i C:\Temp\AirwatchAgent.msi /q ENROLL=Y SERVER=$($WSOServer) LGName=$($WSOOGID) USERNAME=$($WSOStagingUser) PASSWORD=$($WSOStagingPW) ASSIGNTOLOGGEDINUSER=Y DOWNLOADWSBUNDLE=FALSE IMAGE=N /LOG C:\Temp\WorkspaceONE.log"
Start-Process C:\Windows\System32\msiexec.exe -ArgumentList $args -Wait

#Check enrollment
do {
    #Wait for installation
    do {
        Start-Sleep -Seconds 10
        $AWinstalled = Test-Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
    }while ($AWinstalled -eq $false)

    #Check registry if device is enrolled
    $enrolltemp = Get-Item -Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
    If ($enrolltemp.GetValue("Status") -eq 'Completed') {
        $enrollcheck = $true
    }
}while($AWinstalled -eq $false -and $enrollcheck -eq $true)


#Start the SCCM uninstallation after the device is enrolled in VMware Workspace ONE
#If you don't want to to remove the SCCM agent, just remove the line below
Uninstall-SCCMAgent

#exit the script
exit 0
