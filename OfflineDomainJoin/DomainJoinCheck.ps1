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
# Name: DomainJoinTest.ps1
# Version: 0.4
# Date: 20.06.2021
# Created by: Grischa Ernst gernst@vmware.com
# Contributor: Leo Prince leo@mobinergy.com
#
# Description
# - This script waits for the Workspace ONE enrollment + domain join to complete + application installation
#
# How To
# - Run the script - if you need to change the sourcepath or the logpath, provide the parameter
#
# Example:
# DomainJoinTest.ps1 -SourcePath "C:\Source" -LogPath "C:\logs" -ComputerNamePrefix "Test"
#
##########################################################################################
#                                    Changelog 
#
# 0.4 - bugfixing the Domain Join Check part ( initial value 1 - now 10 minutes)
# 0.3 - added the computername prefix support
# 0.2 - changed SFD detection to WMI
# 0.1 - Inital creation
##########################################################################################

##########################################################################################
#                                    Param 
#

param(
		[string]$SourcePath = "C:\Temp\ODJSource",
        [string]$ComputerNamePrefix = "ODJ",
        [string]$LogPath = "C:\Temp"
	)


##########################################################################################
#                                    Start Script 


#Disable Network Discovery popup
New-Item HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff -Force


#Install config registry keys
$Param = '/s "$($SourcePath)\keylock.reg"'
Start-Process  regedit.exe -ArgumentList $Param -Wait

#block keyboard
Start-Process "$($SourcePath)\kidkeylock.exe" -WindowStyle Hidden

#Start Splashscreen
$Param = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $($SourcePath)\Show-OSUpgradeBackground.ps1"
Start-Process "$env:SystemRoot\System32\WindowsPowershell\v1.0\powershell.exe" -ArgumentList $Param

Start-Transcript -Path "$($LogPath)\Provisioning.log" -Force
#Check if HUB is installed and enrolled
do {
    #Wait for installation
    do {
        Start-Sleep -Seconds 10
        $AWinstalled = Test-Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
    }while ($AWinstalled -eq $false)

    
    #Check if AutoLogonCount REG Key is set to 0 (will be deleted as part of the unattend commands
    $logontemp = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    If ($logontemp.GetValue("AutoLogonCount") -eq '0') {
        $regcheck = $true
    }



    #Check registry if device is enrolled
    $enrolltemp = Get-Item -Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus"
    If ($enrolltemp.GetValue("Status") -eq 'Completed') {
        $enrollcheck = $true
    }

}while ($regcheck -eq $false -or $enrollcheck -eq $false -or $regcheck -eq $false)
 Write-Host "Enrollment completed" -ForegroundColor Green

 Write-Host "Waiting for ODJ"
 #Wait for the ODJ blob gets applied

 $ODJCheckstarttime = Get-Date 
 do
{   
       $DomainJoined = $false
       Start-Sleep -Seconds 10
 
       If ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\JoinDomain") -eq $true -and ( (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName").computername ) -like "*$($ComputerNamePrefix)*")
       {
            $DomainJoined = $true
            Write-Host "Domain Join config applied" -ForegroundColor Green
       }   
  
}while($DomainJoined -eq $false -and ((Get-Date) -le $ODJCheckstarttime.AddMinutes(10)))

if($DomainJoined -eq $false)
{
    Write-Host "Domain Join error - please check Domain Join configuration" -ForegroundColor Red
    break
}



Start-Sleep -Seconds 60
 Write-Host "Checking queue"
#Check if the Queue is filled
do
{
     $QueueTest =  Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\Queue' -Recurse
     if($QueueTest)
     {
        Write-Host "Queue detected" -ForegroundColor Red

        $Queue = $true
        Start-Sleep -Seconds 10
     }
     else
     {
        Write-Host "Queue emtpy" -ForegroundColor Green
        $Queue = $false
     }
}while($Queue -eq $true)


#Check if SFD getting installed
Write-Host "Checking SFD installation"
$SFDInstallCheckstarttime = Get-Date 
do
{
   $count = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI').Count
   Start-Sleep 10
}while($count -lt 1 -and ((Get-Date) -le $SFDInstallCheckstarttime.AddMinutes(10)))


$SFDInstallCheckstarttime = Get-Date 
do{
    Clear-Variable -name "sfdinstalled"
    $SFDInstalled = Get-wmiobject win32_product | Where-Object {$_.name -like "*SFDAgent*"} | select-object -property name,version,identifyingnumber
    Start-Sleep 10

}while(!$SFDInstalled -and ((Get-Date) -le $SFDInstallCheckstarttime.AddMinutes(10)))

if($SFDInstalled)
{
    Write-Host "SFD installed" -ForegroundColor Green
}
else
{
    Write-Host "SFD installation error - please check SFD installation" -ForegroundColor Red
    break
}


#Only for for DSM enabled clients
<#
$AllSFDIDs =  (Get-ItemProperty "HKLM:\SOFTWARE\AIRWATCH\DSM\SeededResources").SeededResources.Replace('{"APPS":[{"identifier":"',"").Replace('{"identifier":"',"").Replace('"}',"").Replace(']}',"").Split(",") | where{$_ -ne ""}

$SFDCheckstarttime = Get-Date 
#Check if SFD is installed
do
{
    $SFDInstalled = @()
    $EnterpriseAppManagement = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI'
   

    foreach($managementapp in $EnterpriseAppManagement)
    {
       
           $starttime = Get-Date 
           do
           {
            $currentStatus = (Get-ItemProperty -Path $($managementapp.Name.Replace('HKEY_LOCAL_MACHINE', 'HKLM:')) -Name Status).status
            if($currentStatus -ne 70)
            {
                Start-Sleep -Seconds 10
            }
            
           }while(((Get-Date) -le $starttime.AddMinutes(5)) -and $currentStatus -ne 70)

           $currentStatus = (Get-ItemProperty -Path $($managementapp.Name.Replace('HKEY_LOCAL_MACHINE', 'HKLM:')) -Name Status).status
           if($currentStatus -eq 70)
           {
                $WMIInstalledProducts = Get-wmiobject win32_product | Where-Object {$_.name -like "*SFDAgent*"} | select-object -property name,version,identifyingnumber
                
                $SFDInstalled += $true
                Write-Host "MSI $($managementapp.PSChildName) installed" -ForegroundColor Green
           }
           else
           {
                $SFDInstalled += $false
                Write-Host "MSI $($managementapp.PSChildName) Nnot installed" -ForegroundColor Green
           }
    }

}while($SFDInstalled -contains $false -and ((Get-Date) -le $SFDCheckstarttime.AddMinutes(10)))
#>

#Check if all apps are installed

Write-Host "Start app detection"

$RequiredApps = (Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests' -Recurse).PSChildName
foreach ($App in $RequiredApps) 
{
    $installed = $false
    $starttime = Get-Date 
   
    do 
    {
        $Appinformation = Get-ItemProperty "HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests\$($App)"
        $InstallTest = Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\S*' -Recurse | Where-Object { $_.PSChildName -eq $App }

        if (!$InstallTest) 
        {
            $RegCheck = Get-ChildItem 'HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\S*' -Recurse | Where-Object { $_.PSChildName -eq $App}
            if (!$RegCheck) {
                Write-Host "Warning! Application $($AppInformation.Name) is missing" -ForegroundColor Red
                Write-Host $Appinformation.Name "was not detected" -ForegroundColor Red
                $installed = $false
            }
            else {
                $installed = Get-ItemPropertyValue -Path $($RegCheck.Name.Replace('HKEY_LOCAL_MACHINE', 'HKLM:')) -Name IsInstalled
            }
        }
        else {
            $installed = Get-ItemPropertyValue -Path $($InstallTest.Name.Replace('HKEY_LOCAL_MACHINE', 'HKLM:')) -Name IsInstalled
        }

        if($installed -eq $true)
        {
                Write-Host $Appinformation.Name "was successfully installed" -ForegroundColor Green
                $installed = $true
        }
        else{
                Write-Host "Warning! Application $($AppInformation.Name) is missing" -ForegroundColor Red
                Write-Host $Appinformation.Name "was not detected" -ForegroundColor Red
                start-sleep -Seconds 20
        }

    }while ($Installed -ne $true -and $starttime.AddMinutes(60))
}

#remove last logged on user
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnUser -Value ""
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnSAMUser -Value ""

#remove the autologon count
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon  -Value "0"

#Disable Network Discovery popup
Remove-Item HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff -Force -ErrorAction SilentlyContinue

Restart-Computer
