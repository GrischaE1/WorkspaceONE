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
# Name: CertBasedAPIAuthentication.ps1
# Version: 0.1
# Date: 05.05.2021
# Created by: Grischa Ernst gernst@vmware.com
#
# Description
# - This Script will use a Certificate to authenticate against the UEM API
#
# More information: 
# https://digitalworkspace.one/2021/04/19/certificate-authentication-for-workspace-one-api-with-powershell-scripts/
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
$APIKey = "F5yXiaEoIZtLOybEU12egBwurJxjWMSvnjes8="
$CertificateName = "72548:CertTest"


##########################################################################################
#                                   Functions

function Get-CMSURLAuthorizationHeader
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Input the URL to be
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [uri]$URL,

        # Specify the Certificate to be used
        [Parameter(Mandatory=$true,
                    ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    Begin
    {
        Write-Verbose -Message '[Get-CMSURLAuthorizationHeader] - Starting Function'
  
    }
    Process
    {
       TRY
       {
            #Get the Absolute Path of the URL encoded in UTF8
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($Url.AbsolutePath))

            #Open Memory Stream passing the encoded bytes
            $MemStream = New-Object -TypeName System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$bytes) -ErrorAction Stop

            #Create the Signed CMS Object providing the ContentInfo (from Above) and True specifying that this is for a detached signature
            $SignedCMS = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $MemStream,$true -ErrorAction Stop

            #Create an instance of the CMSigner class - this class object provide signing functionality
            $CMSigner = New-Object -TypeName System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $Certificate -Property @{IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly} -ErrorAction Stop

            #Add the current time as one of the signing attribute
            $null = $CMSigner.SignedAttributes.Add((New-Object -TypeName System.Security.Cryptography.Pkcs.Pkcs9SigningTime))

            #Compute the Signatur
            $SignedCMS.ComputeSignature($CMSigner)

            #As per the documentation the authorization header needs to be in the format 'CMSURL `1 <Signed Content>'
            #One can change this value as per the format the Vendor's REST API documentation wants.
            $CMSHeader = '{0}{1}{2}' -f 'CMSURL','`1 ',$([System.Convert]::ToBase64String(($SignedCMS.Encode())))
            Write-Output -InputObject $CMSHeader
        }
        Catch
        {
            Write-Error -Exception $_.exception -ErrorAction stop
        }
    }
    End
    {
        Write-Verbose -Message '[Get-CMSURLAuthorizationHeader] - Ending Function'
    }
}


Add-Type -AssemblyName System.Security



#Paste the REST API URL below For Ex: https://host/API/v1/system/admins/search?firstname=Test
$Url = "https://$($APIEndpoint)/API/mdm/devices/12772"

#This is the Client Certificate issued to me and has been imported to the Certificate store on my Machine under Current User store
$Certificate = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object Subject -eq "CN=$($CertificateName)"


#generate API Credentials
$Auth = "$(Get-CMSURLAuthorizationHeader -URL $Url -Certificate $Certificate)"

#generate header
$Headers     = @{"Authorization" = $Auth; "aw-tenant-code" = $APIKey}
$ContentType = 'application/json'

#Run the test API REST Method
Invoke-RestMethod -Uri $Url -Headers $Headers -ContentType $ContentType 
