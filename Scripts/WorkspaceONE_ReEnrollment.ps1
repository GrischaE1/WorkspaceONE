
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
#reenroll.ps1 -KeepAppsInstalled "True" -Reenrolldevice "True" -DSServerURL "ds137.awmdm.com" -UserName "StagingUser" -UserPassword "StagingPassword" -OGID "TestOG" 

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

# Get Enrollment ID
    try {
        # Retrieve all items under the Enrollment registry key
        $AllItems = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments -Recurse -ErrorAction Stop
        $AirWatchMDMKey = $AllItems | Where-Object { $_.Name -like "*AirWatchMDM" }

        # Ensure the AirWatchMDMKey exists
        if (-not $AirWatchMDMKey) {
            throw "No AirWatchMDM key found in the registry."
        }

        # Extract the Enrollment Key using regex
        $pattern = "Enrollments\\(.*?)\\DMClient"
        $EnrollmentKey = ([regex]::Match(($AirWatchMDMKey.PSPath), $pattern).Groups[1].Value).Replace("\\", "")

        if (-not $EnrollmentKey) {
            throw "Failed to extract Enrollment Key using the specified regex pattern."
        }

    }
    catch {
    }

    
    # Uninstall SFD to avoid application uninstallation
    try {
        # Retrieve the SFD Agent registry entry
        $Registry = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction Stop | Where-Object { $_.GetValue('DisplayName') -like "*SfdAgent*" }

        # Ensure the registry entry exists
        if (-not $Registry) {
            throw "SFD Agent registry entry not found."
        }

        # Construct the uninstall command
        $SFDUninstall = "/x $($Registry.PSChildName) /q"

        # Execute the uninstall process
        Start-Process MsiExec.exe -ArgumentList $SFDUninstall -Wait -ErrorAction Stop
    }
    catch {
    }


    # Remove SFD and OMA-DM Registry keys
    try {
        # Remove Registry Keys
        $registryKeys = @(
            "HKLM:\\SOFTWARE\\Microsoft\\EnterpriseDesktopAppManagement",
            "HKLM:\\SOFTWARE\\AirWatchMDM"
        )

        foreach ($key in $registryKeys) {
            try {
                if (Test-Path $key) {
                    Remove-Item $key -Recurse -Force -ErrorAction Stop
                }
            }
            catch {
            }
        }
    }
    catch {
    }

    # Uninstall Intelligent Hub
    if ($enrollmentStatus.WorkspaceONEInstalled -eq $True) {
        try {
            # Retrieve Intelligent Hub installation data
            $HubData = Get-WmiObject Win32_Product -ErrorAction Stop | Where-Object { $_.Name -like "*Intelligent HUB Installer*" }

            # Validate if Intelligent Hub is found
            if ($HubData) {
                # Construct the uninstall command
                $HubUninstall = "/x $($HubData.IdentifyingNumber) /q"

                # Execute the uninstall process
                Start-Process MsiExec.exe -ArgumentList $HubUninstall -Wait -ErrorAction Stop
            }
        }
        catch {
        }


        #Sleep for 60 seconds to make sure Hub is uninstalled
        Start-Sleep -Seconds 60

        # Uninstall WS1 App
        try {
            # Retrieve the WS1 app package
            $WS1App = Get-AppxPackage *AirWatchLLC* -ErrorAction SilentlyContinue

            # Validate if the app package exists
            if ($WS1App) {
                # Attempt to remove the app package
                $WS1App | Remove-AppxPackage -ErrorAction SilentlyContinue
            }
        }
        catch {    
        }
    }

    # Remove Enrollment Registry Keys
    $registryKeys = @(
        "HKLM:\SOFTWARE\AirWatch",
        "HKLM:\SOFTWARE\Microsoft\Enrollments",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\logger",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxDefault\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\_ContainerAdmxDefault\*",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\device\ApplicationManagement\*",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Session\$($EnrollmentKey)",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAnytimeUpgrade\Attempts\*"
        "HKLM:\SOFTWARE\WorkspaceONE"
        "HKLM:\SOFTWARE\AirWatchMDMBackup"
        "HKLM:\SOFTWARE\VMware, Inc.\VMware EUC"
        "HKLM:\SOFTWARE\VMware, Inc.\VMware Endpoint Telemetry"

    )

    foreach ($key in $registryKeys) {
        try {
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
        }
    }



    #Delete folders
    $directorypaths = @(
        "$env:ProgramData\AirWatch",
        "$env:ProgramData\VMware\SfdAgent",
        "$env:ProgramFiles\WorkspaceONE",
        "$env:ProgramData\VMware\vmwetlm",
        "$env:ProgramData\VMware\EUC",
        "$env:ProgramData\WorkspaceONE"
    )

    foreach ($directory in $directorypaths) {
        try {
            if (Test-Path $directory) {
                Remove-Item $directory -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        catch {           
        }
    }

    #Clean Scheduled Tasks - SFD
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$($EnrollmentKey)\*" | Unregister-ScheduledTask  -Confirm:$false

    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
    $rootFolder.DeleteFolder("$($EnrollmentKey)", $null)

    #Clean Scheduled Tasks - SFD - before 24.10
    Get-ScheduledTask -TaskPath "\vmware\SfdAgent\*" | Unregister-ScheduledTask  -Confirm:$false

    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\vmware")
    $rootFolder.DeleteFolder("SfdAgent", $null)

    #Clean Scheduled Tasks - SFD - after 24.10
    Get-ScheduledTask -TaskPath "\Workspace ONE\SfdAgent\*" | Unregister-ScheduledTask  -Confirm:$false

    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\Workspace ONE")
    $rootFolder.DeleteFolder("SfdAgent", $null)
    

    #Delete user certificates
    $UserCerts = Get-ChildItem cert:"CurrentUser" -Recurse
    $UserCerts | Where-Object { $_.Issuer -like "*AirWatch*" -or $_.Issuer -like "*AwDeviceRoot*" } | Remove-Item -Force

    #Delete device certificates
    $DeviceCerts = Get-ChildItem cert:"LocalMachine" -Recurse
    $DeviceCerts | Where-Object { $_.Issuer -like "*AirWatch*" -or $_.Issuer -like "*AwDeviceRoot*" } | Remove-Item -Force

#Install Workspace One Agent
if ($Reenrolldevice -eq "true") {
    $args = "/i C:\Temp\AirwatchAgent.msi /q ENROLL=Y SERVER=$($DSServerURL) LGName=$($OGID) USERNAME=$($UserName) PASSWORD=$($UserPassword) ASSIGNTOLOGGEDINUSER=Y DOWNLOADWSBUNDLE=FALSE IMAGE=N /LOG C:\Temp\WorkspaceONE.log"
    Start-Process C:\Windows\System32\msiexec.exe -ArgumentList $args -Wait
}
