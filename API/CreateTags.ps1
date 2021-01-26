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
# Name: CreateTags.ps1
# Version: 0.1
# Date: 26.01.2021
# Created by: Grischa Ernst gernst@vmware.com
#
# Description
# - This script will create tags from a TXT or CSV file
# - Create a TXT file with all tags you want to create in Workspace ONE
# - Define a OG
# - enter the Credentials
#
##########################################################################################
#                                    Changelog 
#
# 0.1 - inital creation
##########################################################################################


##########################################################################################
#                                   Define varibales

#Workspace ONE settings
#Your OG ID (ID of your OG)
$LocationGroupId = "500"

$APIUser = "APIAdmin"
$APIPassword = "APIPassword"
$APIKey = "zdCk9ONdW/zDqHEIi5V9C"
$APIEndpoint = "as1104.awmdm.com"

$Content = Get-Content C:\temp\TAGS.txt


##########################################################################################
#                                    Start Script 

##########################################################################################
#                                    Create API settings

#generate API Credentials
$UserNameWithPassword =  $APIUser + “:” + $APIPassword
$Encoding = [System.Text.Encoding]::ASCII.GetBytes($UserNameWithPassword)
$EncodedString = [Convert]::ToBase64String($Encoding)
$Auth = "Basic " + $EncodedString
$AWTenantCode = $APIKey

#generate header
$Headers     = @{"Authorization" = $Auth; "aw-tenant-code" = $APIKey}
$ContentType = 'application/json'

##########################################################################################
#                                    Create Tags

foreach($TagName in $Content)
{
        Write-Host "Tag is : "$TagName
        $NewTag = @{}
        $NewTag = @{"TagName" = $($TagName)
         "LocationGroupId" = $($LocationGroupId) }

        $Uri = "https://$($APIEndpoint)/API/mdm/tags/addtag"
        Invoke-RestMethod -Uri $uri -Headers $Headers -Body $NewTag -Method Post -ErrorAction Continue

        Start-Sleep -Seconds 1

}
