function Get-IntelligenceReport
{
param(
        [string] $INTELRegion, 
        [string] $ReportID, 
        [string] $APIClientID,
        [string] $APIClientSecret, 
        [string] $ReportDestination
    )

    #encode the CLient Secret and the Client ID with Base64 - make sure to use ASCII   
    $CombinedAuthentication = "$($APIClientID):$($APIClientSecret)"
    $EncodedClientSecret =  [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($CombinedAuthentication))


    #Get Bearer Token
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($EncodedClientSecret)")

    $response = Invoke-RestMethod "https://auth.$($INTELRegion).data.vmwservices.com/oauth/token?grant_type=client_credentials" -Method 'POST' -Headers $headers -SessionVariable CurrentSession

    #Set Bearer Token
    $AccessToken = $response.access_token

    <# Cookie seems not to be needed anymore
    #create new Header
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "bearer $($AccessToken)")
    $headers.Add("Accept", "application/json")

    #Dummy URL for getting Cookie information
    $RequestURL = "https://api.$($INTELRegion).data.vmwservices.com/v1/meta/integration/airwatch/entity/device/attributes"

    #Requesting Cookie
    $response = Invoke-WebRequest $RequestURL -Method 'Get' -Headers $headers -SessionVariable CookieSession
    
    #Get CSRF Cookie token
    $cookies = $CookieSession.Cookies.GetCookies($RequestURL)
    $CSRFToken = $Cookies[0].value
    #>

    #Generate new Header with Cookie information
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("content-type", "application/json")
    $headers.Add("Authorization", "Bearer $($AccessToken)")
    #$headers.Add("Cookie", "XSRF-TOKEN=$($CSRFToken)")

    #For POST commands there is a requirement for a body
    $body = "{`"offset`": 0, `"page_size`": 100}"

    #Get all available downloads for the report 
    $RequestURL = "https://api.$($INTELRegion).data.vmwservices.com/v1/reports/$($ReportID)/downloads/search"
    $response = Invoke-RestMethod $RequestURL -Method 'POST' -Headers $headers -Body $body

    #filter out not completed reports
    $CompletedReports = $response.data.results | Where-Object {$_.status -eq "COMPLETED"} 

    #select latest report
    $LatestReport = $CompletedReports[0]

    #Download URL
    $RequestURL = "https://api.$($INTELRegion).data.vmwservices.com/v1/reports/tracking/$($LatestReport.ID)/download"

    #Download the report to destination
    Invoke-RestMethod $RequestURL -Method 'GET' -Headers $headers -OutFile $ReportDestination
}

$INTELRegion = "sandbox"
$ReportID = "e38fa255-1234-1234-1234-4415c020e25e"
$APIClientID = "intelligence_api@a9f1a6c3-ced3-4792-a65a.data.vmwservices.com"
$APIClientSecret = "YXBpQDk54YWE0MjIwLTJjYTctNG12341td3NlcnZpY2VzLmNv3To5OTk4RERFOTZGQkExND12Q1Mz1234FEMzhFMDQwQUY0MUU1MEVEMURFQzYxM1zE3RkZBQTQ4RTU4OEMwQjc0RUFDMEZB"
$DestinationPath = "C:\Temp\Report.csv" 

Get-IntelligenceReport -INTELRegion $INTELRegion -ReportID $ReportID -APIClientID $APIClientID -APIClientSecret $APIClientSecret -ReportDestination $DestinationPath
