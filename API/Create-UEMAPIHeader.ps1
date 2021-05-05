function Create-UEMAPIHeader
{
    param(
        [string] $APIUser, 
        [string] $APIPassword,
        [string] $APIKey,
        [string] $ContentType = "json",
        [int] $APIVersion = 1
    )

        #generate API Credentials
        $UserNameWithPassword =  $APIUser + “:” + $APIPassword
        $Encoding = [System.Text.Encoding]::ASCII.GetBytes($UserNameWithPassword)
        $EncodedString = [Convert]::ToBase64String($Encoding)
        $Auth = "Basic " + $EncodedString
        $AWTenantCode = $APIKey

        #generate Header
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("aw-tenant-code", $APIKey)
        $headers.Add("Authorization", $auth)
        $headers.Add("Accept", "application/$($ContentType);version=$($APIVersion)")

        return $headers

}

#Example
$header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey -ContentType "XML" 
