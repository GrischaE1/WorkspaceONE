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
# Name: AddDevicesToSmartGroup.ps1
# Version: 0.1
# Date: 29.04.2021
# Created by: Grischa Ernst gernst@vmware.com
#
# Description
# - This Script will add all devices from a .csv file to a defiend smart group
#
##########################################################################################
#                                    Changelog 
#
# 0.1 - inital creation
##########################################################################################


##########################################################################################
#                                   Define varibales

#API Endpoint
$APIEndpoint = "as137.awmdm.com"

#API Credentials
$APIUser = "mmworksapi"
$APIPassword = "Password"
$APIKey = "F5yX1iaEoIZtLOybEU123EegBwurJxjWMSvnjes8="

#Intelligence information - for more information see 
# https://techzone.vmware.com/getting-started-workspace-one-intelligence-apis-workspace-one-operational-tutorial#_1078003
$INTELRegion = "sandbox"
$ReportID = "e38fa255-1234-1234-1234-4415c020e25e"
$APIClientSecret = "YXBpQDk4YWE0MjIwLTJjEMzhFMDQwQUY30MUU1MEVEMURFQ2zYxMzE3RkZBQTQ4RTU4OEMwQjc0R1UFDMEZB"

#SmartGroup ID which should be edited
$TargetSmartGroup = "290633"


#Files 
$DestinationPath = "C:\Temp\DeviceReport.csv" # Exported Intelligence Report csv location
$XMLTempFile = "C:\Temp\Body.xml" # created XML file for sending the XML as body to the API

#Smart Group Type - "All" for the normal filters, "UserDevice" for adding devices and users to the SmartGroup
$SmartGroupType = "UserDevice" #Set to "All" if you want to use other filters 


#Pagesize count - do not set to over 1000 since this will cause issues on the API servers
#Default size is 500
$Pagesize = 1000


##########################################################################################
#                                   Functions

function Get-IntelligenceReport
{
param(
        [string] $INTELRegion, 
        [string] $ReportID, 
        [string] $APISecret, 
        [string] $ReportDestination
    )


    #Get Bearer Token
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($APISecret)")

    $response = Invoke-RestMethod "https://auth.$($INTELRegion).data.vmwservices.com/oauth/token?grant_type=client_credentials" -Method 'POST' -Headers $headers -SessionVariable CurrentSession

    #Set Bearer Token
    $AccessToken = $response.access_token

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

    #Generate new Header with Cookie information
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("content-type", "application/json")
    $headers.Add("Authorization", "Bearer $($AccessToken)")
    $headers.Add("Cookie", "XSRF-TOKEN=$($CSRFToken)")

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

function Create-XMLBodyFile
{
param(
        $DeviceInformation, 
        [string] $TempFile,
        [string] $SmartGroupName,
        [string] $SmartGroupID,
        [string] $SmartGroupUuid,
        [string] $CriteriaType,
        [string] $ManagedByOrganizationGroupId,
        [string] $ManagedByOrganizationGroupUUID,
        [string] $ManagedByOrganizationGroupName
    )

#XML setting definition  
$xmlWriter = new-object system.xml.xmltextwriter($TempFile,[System.Text.Encoding]::UTF8)
$xmlWriter.Formatting = 'Indented'
$xmlWriter.Indentation = 1
$xmlWriter.Formatting = "utf-8"
$XmlWriter.IndentChar = "`t"

#Start root XML hive
$xmlWriter.WriteStartDocument()
$xmlWriter.WriteStartElement('SmartGroup')
$xmlWriter.WriteAttributeString('xmlns:xsd','http://www.w3.org/2001/XMLSchema')
$xmlWriter.WriteAttributeString('xmlns:xsi','http://www.w3.org/2001/XMLSchema-instance')
$xmlWriter.WriteAttributeString('xmlns','http://www.air-watch.com/servicemodel/resources')

#Add SmartGroup settings
$xmlWriter.WriteElementString('Name',$SmartGroupName)
$xmlWriter.WriteElementString('SmartGroupID',$SmartGroupID)
$xmlWriter.WriteElementString('SmartGroupUuid',$SmartGroupUuid)
$xmlWriter.WriteElementString('CriteriaType',$CriteriaType)
$xmlWriter.WriteElementString('ManagedByOrganizationGroupId',$ManagedByOrganizationGroupId)
$xmlWriter.WriteElementString('ManagedByOrganizationGroupUuid',$ManagedByOrganizationGroupUuid)
$xmlWriter.WriteElementString('ManagedByOrganizationGroupName',$ManagedByOrganizationGroupName)

#Add devices to Smartgroup rule
$xmlWriter.WriteStartElement('DeviceAdditions')

foreach($device in $DeviceInformation.GetEnumerator())
{
$xmlWriter.WriteStartElement('Device')
$xmlWriter.WriteElementString('Id',$device.Name)

$xmlWriter.WriteElementString('Name',$device.Value)
$xmlWriter.WriteEndElement()
}

#Close the XML and save it to the file
$xmlWriter.WriteEndElement()
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()

}

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

##########################################################################################
#                                    Start Script 

$Date = Get-Date -Format HHmm
#start logging
Start-Transcript -Path "C:\Temp\SmartGroupChange_$($TargetSmartGroup)_$($Date).log" -Force


Get-IntelligenceReport -INTELRegion $INTELRegion -ReportID $ReportID -APISecret $APIClientSecret -ReportDestination $DestinationPath

#Get Source CSV file - check if you have a header or not - if yes, remove the part after the pipe
$ImportDevices = Import-Csv C:\Temp\Grid_Report_export_WS_61f7388a-fdd3-4b81-9eff-d8dbb1cb5220.csv | Select-Object "Friendly Name" -ExpandProperty "Friendly Name"

#Get the Intelligence report
$ReportImport = Import-Csv C:\Temp\DeviceReport.csv | Select-Object "device_id", "device_friendly_name"

#Create Device ID Table
$DeviceIDsTable = @{}

#Get the device ID's
foreach ($device in $ReportImport)
{
    foreach($Name in $ImportDevices)
    {
        if($Name -eq $($device.device_friendly_name))
        {
           $DeviceIDsTable.Add($device.device_id, $device.device_friendly_name)
        }
    }

}



#Generate UEM API Header
$header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey


#Get SmartGroup information
$url = "https://$($APIEndpoint)/API/mdm/smartgroups/$($TargetSmartGroup)"
$response = Invoke-RestMethod $url -Method 'GET' -Headers $header 


Foreach ($device in $response.DeviceAdditions)
{
   #Set erroraction to silent - devices that are already in the hashtable will be generate an error
   $ErrorActionPreference = "SilentlyContinue"  

   $ID = $device.id
   $Name = $device.name
   $DeviceIDsTable.add($ID, $Name) 
  
   #Change Error Action back to default
   $ErrorActionPreference = "Silent" 
}

Write-Output "This devices will be added to SmartGroup" -Verbose
Write-Output $DeviceIDsTable -Verbose

#Create the XML Body file with the updated Smart Group information - including the device list
Create-XMLBodyFile -DeviceInformation $DeviceIDsTable -TempFile $XMLTempFile -SmartGroupName $response.Name -SmartGroupID $response.SmartGroupID -SmartGroupUuid $response.SmartGroupUuid -CriteriaType $SmartGroupType -ManagedByOrganizationGroupId $response.ManagedByOrganizationGroupId -ManagedByOrganizationGroupUUID $response.ManagedByOrganizationGroupUuid -ManagedByOrganizationGroupName $response.ManagedByOrganizationGroupName
$Body = Get-Content $XMLTempFile

Remove-Item $XMLTempFile -Force

#Change the Header to XML 
$header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey -ContentType "XML" 
$url = "https://$($APIEndpoint)/API/mdm/smartgroups/$($TargetSmartGroup)"

#Send the information to Workspace ONE UEM
$check = Invoke-RestMethod $url -Method 'PUT' -Headers $header -Body $Body -Verbose

#Check if the command was successful 
if($check)
{ Write-Output "No Update was made - XML error"}
else { Write-Output "Smart Group updated"}


Stop-Transcript 
