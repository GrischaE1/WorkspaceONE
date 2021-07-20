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
# Name: AppUpload.ps1
# Version: 0.1
# Date: 20.06.2021
# Created by: Grischa Ernst gernst@vmware.com
#
# Description
# - This script will upload all MSI files that are in the source folder ($sourcepath)
# - MSI information will be queried and the product name will be the UEM application name
# - more MSI information are available in the Get-MSIInformation function
#
# How To
# - Run the script with the parameter
#
# appupload.ps1 -SourcePath "C:\Temp" -APIEndpoint "as137.awmdm.com" -APIUser "APIAdmin"-APIPassword "Password" -APIKey "123412341234" -orgID "1234"
#
##########################################################################################
#                                    Changelog 
#
# 0.1 - Inital creation
##########################################################################################

##########################################################################################
#                                    Param 
#

param(
		[string]$SourcePath,
        [string]$APIEndpoint,
        [string]$APIUser,
        [string]$APIPassword,
        [string]$APIKey,
        [string]$orgID

	)

##########################################################################################
#                                    Functions


function Get-MSIInformation 
{

 param(
        [System.IO.FileInfo]$MsiFile)
 

    $com_object = New-Object -com WindowsInstaller.Installer 
            
    $database = $com_object.GetType().InvokeMember("OpenDatabase","InvokeMethod",$Null,$com_object,@($MsiFile.FullName, 0)) 
 
    $query = "SELECT * FROM Property" 
    $View = $database.GetType().InvokeMember("OpenView","InvokeMethod",$Null,$database,($query)) 
 
    $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null) 
 
    $record = $View.GetType().InvokeMember("Fetch","InvokeMethod",$Null,$View,$Null) 

 
 
    $msi_props = @{} 
    while ($record -ne $null) { 
        $prop_name = $record.GetType().InvokeMember("StringData", "GetProperty", $Null, $record, 1) 
        $prop_value = $record.GetType().InvokeMember("StringData", "GetProperty", $Null, $record, 2) 
        $msi_props[$prop_name] = $prop_value 
        $record = $View.GetType().InvokeMember("Fetch","InvokeMethod",$Null,$View,$Null)
    }

    $MSIInformation = @{
    "ProductName"=$msi_props.Item("ProductName");
    "Manufacturer"=$msi_props.Item("Manufacturer");
    "ProductVersion"=$msi_props.Item("ProductVersion");
    "ProductCode"=$msi_props.Item("ProductCode");
    "ProductLanguage"=$msi_props.Item("ProductLanguage")}

    $view.Close()
    
    $database.Commit()
    $database = $null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($com_object) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($view) | Out-Null

    rv com_object,database,view,record,MsiFile
    [system.gc]::Collect()
    [System.gc]::waitforpendingfinalizers()

    
    return $MSIInformation
}


function Create-APIApplicationBody 
{
    param(
         $MSIDetails,
         $orgID) 
    
    $APIbody = @{    
        ApplicationName = "$($MSIDetails.ProductName)"
        DeviceType = "12"
        Platform = "WinRT"
        BlobId = "$($upload.Value)"
        PushMode = 0
        EnableProvisioning = "true"
        IsDependencyFile = "false"
        LocationGroupId = "$($OrgID)"
        SupportedProcessorArchitecture = "x86"
        SupportedModels = @{
                Model = @(@{
                    ModelId = "83"
                    ModelName = "Desktop"
                })
            }
        
            DeploymentOptions = @{
                WhenToInstall = @{
                    DataContingencies = ""
                    DiskSpaceRequiredInKb = "0"
                    DevicePowerRequired = "0"
                    RamRequiredInMb = "0"
                }

                HowToInstall = @{
                    InstallContext = "Device"
                    InstallCommand = "msiexec /i putty-64bit-0.75-installer.msi /q"
                    AdminPrivileges = "true"
                    DeviceRestart = "DoNotRestart"
                    RetryCount = "3"
                    RetryIntervalInMinutes = "5"
                    InstallTimeoutInMinutes = "60"
                    InstallerRebootExitCode = "1641"
                    InstallerSuccessExitCode = "0"
                }
                WhenToCallInstallComplete = @{
                    UseAdditionalCriteria = "false"
                }
        }

    }

        $json = $APIbody | ConvertTo-Json -Depth 10
        return $json
}


function Create-UEMAPIHeader
{
    param(
        [string] $APIUser, 
        [string] $APIPassword,
        [string] $APIKey,
        [string] $ContentType = "json",
        [string] $Accept = "json",
        [int] $APIVersion = 1
    )

        #generate API Credentials
        $UserNameWithPassword =  $APIUser + “:” + $APIPassword
        $Encoding = [System.Text.Encoding]::ASCII.GetBytes($UserNameWithPassword)
        $EncodedString = [Convert]::ToBase64String($Encoding)
        $Auth = "Basic " + $EncodedString

        #generate Header
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("aw-tenant-code", $APIKey)
        $headers.Add("Authorization", $auth)
        $headers.Add("Accept", "application/$($Accept);version=$($APIVersion)")
        $headers.Add("Content-Type", "application/$($ContentType)")
        return $headers

}



##########################################################################################
#                                   Start Script


#Get all MSI's
$MSIFiles = Get-ChildItem $SourcePath -Filter *.msi

foreach($file in $MSIFiles)
{

    #Get MSI information
    $MSIInfo = Get-MSIInformation -MsiFile "$($SourcePath)\$($file.name)"
     $MSIInfo
    #create header
    $header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey -ContentType "octet-stream"


    $url = "https://$($APIEndpoint)/api/mam/blobs/uploadblob?filename=$($file.name)&organizationgroupid=$($orgID)&moduleType=Application"
    $upload = Invoke-RestMethod $url -Method 'POST' -Headers $header  -InFile $file.FullName

    
    $appProperties = Create-APIApplicationBody -MSIDetails $MSIInfo -OrgID $orgID

    #Generate Header
    $header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey 



    $url = "https://$($APIEndpoint)/api/mam/apps/internal/begininstall"
    Invoke-RestMethod $url -Method 'POST' -Headers $header -Body $appProperties -Verbose

}