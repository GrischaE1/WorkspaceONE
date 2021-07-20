function Get-UEMOauthToken
{
   param(

    [string]$APIClientID,     #UEM client app ID
    [string]$APIClientSecret, #UEM client app secret
    [string]$Tenant           #UEM client authentication URL - see https://docs.vmware.com/en/VMware-Workspace-ONE-UEM/services/UEM_ConsoleBasics/GUID-BF20C949-5065-4DCF-889D-1E0151016B5A.html for the right URL
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

#Get the Bearer token for authentication
$authorizationHeader = Get-UEMOauthToken -APIClientID "123123" -APIClientSecret "123123" -Tenant "https://uat.uemauth.vmwservices.com/connect/token"


######################################
#optional

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


######################################
#example

#Generate the Header
$apikey = "123123123"
$headers = Create-UEMAPIHeader -authorizationHeader $authorizationHeader -APIKey $apiKey


$response = Invoke-RestMethod 'https://as137.awmdm.com/API/mdm/devices/search' -Method 'GET' -Headers $headers
$response | ConvertTo-Json
