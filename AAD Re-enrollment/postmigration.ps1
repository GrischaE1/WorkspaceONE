$WSOStagingUser = "stagingWS1"
$WSOStagingPW = "VMware1!"
$WSOOGID = "WS1"
$WSOServer = "https://ds1831.awmdm.com"

#Wait for explorer to be started
do{
    $Process = Get-Process -Name explorer
    if($Process)
    {
        Start-Sleep 20 
        Start-ScheduledTask "Screenlock"
    }
}while(!$Process)

#Rename the device after PPKG changed it 
$OldDeviceName = (Get-ChildItem 'C:\Recovery\OEM\Mover_Data' -Filter "*.txt").Name.Replace(".txt","")
Rename-Computer -Newname $OldDeviceName

#Enroll the device to UEM
$List =  "/q ENROLL=Y SERVER=$($WSOServer) LGName=$($WSOOGID) USERNAME=$($WSOStagingUser) PASSWORD=$($WSOStagingPW) ASSIGNTOLOGGEDINUSER=Y"
Start-Process "C:\Recovery\OEM\Mover_Data\AirwatchAgent.msi" -ArgumentList $List -Wait

#Create Cleanup Task
schtasks.exe /create  /tn "Cleanup" /ru "System" /sc ONSTART /tr "powershell -executionpolicy bypass -file C:\Recovery\OEM\Mover_Data\cleanup.ps1"

Start-Sleep -Seconds 60

#Generate 5 minute timer
$timeout = new-timespan -Minutes 5
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

        #Disable the Scheduled task
        Disable-ScheduledTask -TaskName "WorkspaceONE Enrollment" 

        #Remove the "Installer" account information from the login screen
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "LastLoggedOnUser" -PropertyType String -Value "" -Force
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "LastLoggedOnUserSID" -PropertyType String -Value "" -Force
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "LastLoggedOnDisplayName" -PropertyType String -Value "" -Force
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "LastLoggedOnSamUser" -PropertyType String -Value "" -Force
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -name "SelectedUserSID" -PropertyType String -Value "" -Force

        #Disable the user "Installer"
        net user /active:no Installer

        #Restart the device
        $shutdown = "/r /t 20 /f"
        Start-Process shutdown.exe -ArgumentList $shutdown

    }
}while ($enrollcheck -eq $false -and $sw.elapsed -lt $timeout)

