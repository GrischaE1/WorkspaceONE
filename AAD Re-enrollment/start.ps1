
#Get the Bearer token for authentication

$apikey = "+dGRoYLrPMAmBZtA6xPFo4V0RB3lYmgpzFuYi4hG5VQ="
$APIEndpoint = "as1831.awmdm.com"


function Get-UEMOauthToken
{
   param(

    [string]$APIClientID,     #UEM client app ID
    [string]$APIClientSecret, #UEM client app secret
    [string]$Tenant           #UEM client authentication URL - see https://docs.omnissa.com/bundle/WorkspaceONE-UEM-Console-BasicsVSaaS/page/UsingUEMFunctionalityWithRESTAPI.html for the right URL
    )

    #Create Header for getting BEARER Token
        $headers = @{
       'Content-Type' = 'application/x-www-form-urlencoded'
    }

    #Add the API information to the body
    $body = @{
	    'client_id' = $APIClientID
	    'client_secret' = $APIClientSecret
	    'grant_type' = "client_credentials"
    }

    #run the query against the UEM authentication URL
    $response = Invoke-RestMethod $Tenant -Method 'POST' -Headers $headers -Body $body

    #extract the bearer token
    $token = $response.access_token
    $authorizationHeader = "Bearer ${token}"

    return $authorizationHeader

}

# Get the Tenant URL from https://docs.omnissa.com/bundle/WorkspaceONE-UEM-Console-BasicsVSaaS/page/UsingUEMFunctionalityWithRESTAPI.html
$authorizationHeader = Get-UEMOauthToken -APIClientID "c9bfca1c91794ce4a31a7e52907ec236" -APIClientSecret "DBFDE8E7D1FDEBD32C912A5B7A576F85" -Tenant "https://uat.uemauth.vmwservices.com/connect/token"



function Create-UEMAPIHeader
{
    param(
        [string] $authorizationHeader, 
        [string] $APIKey,
        [string] $ContentType = "json",
        [string] $Accept = "json",
        [int] $APIVersion = 1
    )

        #generate Header
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("aw-tenant-code", $APIKey)
        $headers.Add("Authorization", $authorizationHeader)
        $headers.Add("Accept", "application/$($Accept);version=$($APIVersion)")
        $headers.Add("Content-Type", "application/$($ContentType)")
        return $headers

}

######################################################################################################
# Script start

#Generate the Header
$headers = Create-UEMAPIHeader -authorizationHeader $authorizationHeader -APIKey $apiKey

#Check AAD
$status = dsregcmd /status
$AADStatus = $status[5].Trim()

#get current computer object in WSO via serialnumber
$computerserial = gwmi win32_bios | Select -ExpandProperty SerialNumber


if($AADStatus -like "*YES")
{
    #Uninstall SFD to avoid application uninstallation
    $Registry = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object {$_.GetValue('DisplayName') -eq "VMware SfdAgent"})
    MsiExec.exe /x "$($registry.PSChildName)" /q

    #Remove SFD and OMA-DM Registry keys to avoid application uninstallation
    Remove-Item HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement -Recurse -Force
    Remove-Item HKLM:\SOFTWARE\AirWatchMDM -Recurse -Force
    
    #unjoin AAD
    dsregcmd /leave

    Start-Sleep -Seconds 60

    #Delete the device from UEM
    $Uri = "https://$($APIEndpoint)/API/mdm/devices?searchBy=Serialnumber&id=$($computerserial)"
    Invoke-RestMethod -Method DELETE -Uri $uri -Headers $Headers 
      

    #Join AAD
    #Install the PPKG to rejoin the Domain
    Install-ProvisioningPackage -PackagePath "$PSScriptRoot\AADJoin.ppkg" -ForceInstall -QuietInstall -LogsDirectoryPath "C:\Recovery\OEM\Mover_Data" | out-null
    shutdown.exe -a 
    Start-Sleep -Seconds 30
}

#Trigger restart to restart into the autologon 
$shutdown = "/r /t 20 /f"
Start-Process shutdown.exe -ArgumentList $shutdown