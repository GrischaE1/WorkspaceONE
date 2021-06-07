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
# - This will use an Intelligence Report for getting device data - for mapping Device Name to Device ID
#
##########################################################################################
#                                    Changelog 
#
# 0.1 - inital creation
##########################################################################################


##########################################################################################
#                                   Define varibales

#UEM API Endpoint
$APIEndpoint = "as137.awmdm.com"

#UEM API Credentials
$APIUser = "UEMAPI"
$APIPassword = "}[!6"
$APIKey = "zdCk9ONdW/F3Emu/="

#Intelligence information - for more information see 
# https://techzone.vmware.com/getting-started-workspace-one-intelligence-apis-workspace-one-operational-tutorial#_1078003
$INTELRegion = "eu1"
$ReportID = "caa85eab-1234-1234-1234-92a4c6d9a405"
$APIClientID = "intelligence_api@a9f1a6c3-1234-1234-1234-6d9624a63219.data.vmwservices.com"
$APIClientSecret = "EB9FE20DC2CF95029C42F4EA461993190A4B1F84B797E9FA29EBC57B482B2D0D"

#SmartGroup ID which should be edited
#Comment out the variable you don't want to use
$TargetSmartGroupName = "SSmartGroupName"
#If both variables are set - ID will be used
#$TargetSmartGroupID = "491"


#Files 
$LogFolder = "C:\Temp"
$ImportDeviceNames = "C:\Temp\DeviceNames.csv" # CSV of the devices that should be added 
$DestinationPath = "C:\Temp\MahleDeviceReport.csv" # Exported Intelligence Report csv location
$XMLTempFile = "C:\Temp\MahleBody.xml" # created XML file for sending the XML as body to the API

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
      #  $headers.Add("Connection","keep-alive")
        $headers.Add("Accept-Encoding","gzip, deflate, br")

        return $headers

}

##########################################################################################
#                                    Start Script 

$Date = Get-Date -Format HHmm
#start logging
Start-Transcript -Path "$($LogFolder)\SmartGroupChange_$($TargetSmartGroup)_$($Date).log" -Force

Get-IntelligenceReport -INTELRegion $INTELRegion -ReportID $ReportID -APIClientID $APIClientID -APIClientSecret $APIClientSecret -ReportDestination $DestinationPath

#Get Source CSV file - check if you have a header or not - if yes, remove the part after the pipe
$ImportDevices = Import-Csv $ImportDeviceNames | Select-Object "Friendly Name" -ExpandProperty "Friendly Name"

#Get the Intelligence report
$ReportImport = Import-Csv $DestinationPath | Where-Object {$_.device_enrollment_status -notlike "*Unenrolled*"}  | Select-Object "device_id", "device_friendly_name" 

#Create Device ID Table
$DeviceIDsTable = @{}

#Get the device ID's
foreach ($device in $ReportImport)
{
    foreach($name in $ImportDevices)
    {
        if($device.device_friendly_name -like "*$Name*" )
        {
           Write-Output "Match"
           $DeviceIDsTable.Add($device.device_id, $device.device_friendly_name)
        }
    }
}

if(!$DeviceIDsTable)
{
    Write-Verbose "Error during Device ID Match"
    Write-Verbose "Please check the report and the source file"
    break
}


#Generate UEM API Header
$header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey


#Get SmartGroup information
if($TargetSmartGroupName -and !$TargetSmartGroupID)
{
    $url = "https://$($APIEndpoint)/API/system/groups/search?name=$($TargetSmartGroupName)"
    $response = Invoke-RestMethod $url -Method 'GET' -Headers $header 
}
if($TargetSmartGroupID)
{
    $url = "https://$($APIEndpoint)/API/mdm/smartgroups/$($TargetSmartGroupID)"
    $response = Invoke-RestMethod $url -Method 'GET' -Headers $header 
}

if(!$response)
{
    Write-Verbose "Error during Smart Group response"
    Write-Verbose "Please check the Smart Group config"
    break
}

$TargetSmartGroupID = $response.SmartGroupID

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

#Only for logging
Write-Output "This devices will be added to SmartGroup" -Verbose
Write-Output $DeviceIDsTable -Verbose


#Create the XML Body file with the updated Smart Group information - including the device list
Create-XMLBodyFile -DeviceInformation $DeviceIDsTable -TempFile $XMLTempFile -SmartGroupName $response.Name -SmartGroupID $response.SmartGroupID -SmartGroupUuid $response.SmartGroupUuid -CriteriaType $SmartGroupType -ManagedByOrganizationGroupId $response.ManagedByOrganizationGroupId -ManagedByOrganizationGroupUUID $response.ManagedByOrganizationGroupUuid -ManagedByOrganizationGroupName $response.ManagedByOrganizationGroupName
[XML]$Body = Get-Content $XMLTempFile 
#Remove the XML file
Remove-Item $XMLTempFile -Force

#Change the Header to XML 
$header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey -ContentType "XML" 
$url = "https://$($APIEndpoint)/API/mdm/smartgroups/$($TargetSmartGroupID)"

#Send the information to Workspace ONE UEM
Invoke-RestMethod $url -Method 'PUT' -Headers $header -Body $Body -Verbose -OutVariable output 4>&1 | Out-Null

#Check if the command was successful 
if($OutPut -like "VERBOSE: received*")
{ Write-Output "No Update was made - XML error" -verbose}
else { Write-Output "Smart Group updated" -verbose}


Stop-Transcript 
