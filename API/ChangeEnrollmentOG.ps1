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
# Name: ChangeEnrollmentOG.ps1
# Version: 0.1
# Date: 26.01.2021
# Created by: Grischa Ernst gernst@vmware.com
#
# Description
# - This Script will change the Enrollment OG of all users to a specified OG
# - Some customer have some lagacy users that might have not the Top Level OG as enrollment OG
# - With the varity of devices the enrollment OG should be the Top Level OG to provide the most flexibility 
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
$APIUser = "APIUSERNAME"
$APIPassword = "APIPASSWORD"
$APIKey = "APIKEY"


#Target OG UUID's - if this OG is not set as enrollment OG, it get changed
$TOPOGID = "UUID"


#Pagesize count - do not set to over 1000 since this will cause issues on the API servers
#Default size is 500
$Pagesize = 1000


##########################################################################################
#                                    Start Script 
$Date = Get-Date -Format HHmm
#start logging
Start-Transcript -Path "C:\Temp\EnrollmentOGChange_$($Date).log" -Force

#Create API Settings
$UserNameWithPassword =  $APIUser + “:” + $APIPassword
$Encoding = [System.Text.Encoding]::ASCII.GetBytes($UserNameWithPassword)
$EncodedString = [Convert]::ToBase64String($Encoding)
$Auth = "Basic " + $EncodedString


#Create headers
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("aw-tenant-code", $APIKey)
$headers.Add("Authorization", $auth)
$headers.Add("Accept", "application/json")




#Get the total amount of users
$response = Invoke-RestMethod https://$($APIEndpoint)/API/system/users/search?PageSize=1 -Method 'GET' -Headers $headers 
$TotalUsers = $response.Total

#check how many pages are needed to get all users
[int]$TotalPages = [math]::Ceiling(($TotalUsers / $Pagesize)+1)

#define all users array
$AllUsers = @()

for($i = 0; $i -lt $TotalPages; $i++)
{
 $response = Invoke-RestMethod "https://$($APIEndpoint)/API/system/users/search?page=$($i)&PageSize=1000" -Method GET -Headers $headers 
 $AllUsers +=  $response.Users
 Start-Sleep -Seconds 2
}


        #check every user if the enrollment OG is the same as the TOP OG - if not change it
        foreach($user in $($AllUsers))
        {
            #exclude staging users
            if($user.UserName -notlike "*Staging*")
            {

                #Switch to V2 System Managmeent REST API because enrollment OG is not availible in V1
                $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $headers.Add("aw-tenant-code", $APIKey)
                $headers.Add("Accept", "application/json;version=2")
                $headers.Add("Authorization", $auth)
                $headers.Add("Content-Type", "application/json")

                $Uri = "https://$($APIEndpoint)/API/system/users/$($user.Uuid)"
                $UserV2 = Invoke-RestMethod -Uri $uri -Headers $Headers -Method 'GET'
                
                #Change the enrollment OG to the TOP OG if its not already set
                if($userV2.enrollmentOrganizationGroupUuid -ne $TOPOGID)
                {
                    #for logging purpose 
                    write-output "Current User: $($UserV2.UserName) `t Current OG: $($userV2.enrollmentOrganizationGroupUuid )"
                       
                    #create body
                    $body = "{`"enrollmentOrganizationGroupUuid`":`"$($TOPOGID)`"}"

                    $Uri = "https://$($APIEndpoint)/API/system/Users/$($userV2.Uuid)"
                   # Invoke-RestMethod -Uri $uri -Method 'PUT' -Headers $headers -Body $body
                                       
                }
            }
            Start-Sleep -Seconds 1
        }

Stop-Transcript 
