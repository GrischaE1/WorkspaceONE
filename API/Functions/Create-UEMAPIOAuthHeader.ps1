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
