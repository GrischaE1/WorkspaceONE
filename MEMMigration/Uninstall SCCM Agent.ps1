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

<#
    .NOTES
    ==========================================================================
    
    Created on:   	23/06/2017 12:02 AM
    Created by:   	Grischa Ernst
    Filename:     	Uninstall SCCM Agent.ps1
     Version:       0.1
     Changelog:
     0.1 22.06.2017 Initial script
    ==========================================================================
    .DESCRIPTION
    Uninstall of the current SCCM Agent 

    .Requirements
       Must be run as local system or local admin account
#>



Try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop } Catch {}
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

#Start the SCCM uninstallation 
Uninstall-SCCMAgent

#exit the script
exit 0