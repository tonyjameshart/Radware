<#
//-----------------------------------------------------------------------
// Radware Cloud WAF.ps1
//
// Copyright (c) 2021 Caterpillar, Inc.  All rights reserved.
//
// This script is specIFic for CAT use and under development. 
//-----------------------------------------------------------------------
<field name>|<label text>|<flags>

Bit 1 = Enabled
Bit 2 = Policyable
Bit 3 = Mandatory

-----BEGIN FIELD DEFINITIONS-----
Text1|Text1|000
Text2|Text2|000
Text3|Application Name|110
Text4|Main Domain|110
Text5|IP|110
Text6|Region|110
Option1|Self Signed|110
Option2|Create Application|100
Passwd|Password Field|000
-----END FIELD DEFINITIONS-----
#>

<######################################################################################################################
.NAME
    Prepare-KeyStore
.DESCRIPTION
    Remotely create and/or verIFy keystore on the hosting platform.  Remote generation is considered UNSUPPORTED IF this
    function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions
        HostAddress : a string containing the hostname or IP address specIFied by the device object
        TcpPort : an integer value containing the TCP port specIFied by the application object
        UserName : a string containing the username portion of the credential assigned to the device or application object
        UserPass : a string containing the password portion of the credential assigned to the device or application object
        UserPrivKey : the non-encrypted PEM of the private key credential assigned to the device or application object
        AppObjectDN : a string containing the TPP distiguished name of the calling application object
        AssetName : a string containing a Venafi standard auto-generated name that can be used for provisioning
                    (<Common Name>-<ValidTo as YYMMDD>-<Last 4 of SerialNum>)
        VarText1 : a string value for the text custom field defined by the header at the top of this script
        VarText2 : a string value for the text custom field defined by the header at the top of this script
        VarText3 : a string value for the text custom field defined by the header at the top of this script
        VarText4 : a string value for the text custom field defined by the header at the top of this script
        VarText5 : a string value for the text custom field defined by the header at the top of this script
        VarBool1 : a boolean value for the yes/no custom field defined by the header at the top of this script (true|false)
        VarBool2 : a boolean value for the yes/no custom field defined by the header at the top of this script (true|false)
        VarPass : a string value for the password custom field defined by the header at the top of this script
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Prepare-KeyStore
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}


<######################################################################################################################
.NAME
    Generate-KeyPair
.DESCRIPTION
    Remotely generates a public-private key pair on the hosting platform.  Remote generation is
    considered UNSUPPORTED IF this function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER SpecIFic
    A hashtable containing the specIFic set of variables needed by this function
        KeySize : the integer key size to be used when creating a key pair
        EncryptPass : the password string to use IF encrypting the remotely generated private key
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        AssetName : (optional) the base name used to reference the certIFicate as it was installed on the device;
                    IF not supplied the auto-generated name is assumed
######################################################################################################################>
function Generate-KeyPair
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function SpecIFic Parameters")]
        [System.Collections.Hashtable]$SpecIFic
    )

    return @{ Result="NotUsed"; }
}


<######################################################################################################################
.NAME
    Generate-CSR
.DESCRIPTION
    Remotely generates a CSR on the hosting platform.  Remote generation is considered UNSUPPORTED
    IF this function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER SpecIFic
    A hashtable containing the specIFic set of variables needed by this function
        SubjectDN : the requested subject distiguished name as a hashtable; OU is a string array; all others are strings
        SubjAltNames : hashtable keyed by SAN type; values are string arrays of the individual SANs
        KeySize : the integer key size to be used when creating a key pair
        EncryptPass : the password string to use IF encrypting the remotely generated private key
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        Pkcs10 : a string representation of the CSR in PKCS#10 format
        AssetName : (optional) the base name used to reference the certIFicate as it was installed on the device;
                    IF not supplied the auto-generated name is assumed
######################################################################################################################>
function Generate-CSR
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function SpecIFic Parameters")]
        [System.Collections.Hashtable]$SpecIFic
    )

    return @{ Result="Success"}
}


<######################################################################################################################
.NAME
    Install-Chain
.DESCRIPTION
    Installs the certIFicate chain on the hosting platform.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER SpecIFic
    A hashtable containing the specIFic set of variables needed by this function
        ChainPem : all chain certIFicates concatentated together one after the other
        ChainPkcs7 : byte array PKCS#7 collection that includes all chain certIFicates
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Install-Chain
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function SpecIFic Parameters")]
        [System.Collections.Hashtable]$SpecIFic
    )
 
    return @{ Result="NotUsed"; }
}


<######################################################################################################################
.NAME
    Install-PrivateKey
.DESCRIPTION
    Installs the private key on the hosting platform.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER SpecIFic
    A hashtable containing the specIFic set of variables needed by this function
        PrivKeyPem : the non-encrypted private key in RSA Base64 PEM format
        PrivKeyPemEncrypted : the password encrypted private key in RSA Base64 PEM format
        EncryptPass : the string password that was used to encrypt the private key and PKCS#12 keystore
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
        AssetName : (optional) the base name used to reference the private key as it was installed on the device;
                    IF not supplied the auto-generated name is assumed
######################################################################################################################>
function Install-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function SpecIFic Parameters")]
        [System.Collections.Hashtable]$SpecIFic
    )

    return @{ Result="Success"; }
}


<######################################################################################################################
.NAME
    Install-CertIFicate
.DESCRIPTION
    Installs the certIFicate on the hosting platform.  May optionally be used to also install the private key and chain.
    Implementing logic for this function is REQUIRED.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER SpecIFic
    A hashtable containing the specIFic set of variables needed by this function
        CertPem : the X509 certIFicate to be provisioned in Base64 PEM format
        PrivKeyPem : the non-encrypted private key in RSA Base64 PEM format
        PrivKeyPemEncrypted : the password encrypted private key in RSA Base64 PEM format
        ChainPem : all chain certIFicates concatentated together one after the other
        ChainPkcs7 : byte array PKCS#7 collection that includes all chain certIFicates
        Pkcs12 : byte array PKCS#12 collection that includes certIFicate, private key, and chain
        EncryptPass : the string password that was used to encrypt the private key and PKCS#12 keystore
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
                 (may only be 'NotUsed' IF Install-PrivateKey did not return 'NotUsed')
        AssetName : (optional) the base name used to reference the certIFicate as it was installed on the device;
                    IF not supplied the auto-generated name is assumed
######################################################################################################################>
function Install-CertIFicate
{
Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function SpecIFic Parameters")]
        [System.Collections.Hashtable]$SpecIFic
    )
try
    {

 Get-Date | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue 
################################################## Auth ##############################################################

         $api_user = $General.UserName
         $api_pass = $General.UserPass
         $global:tenantID = $general.HostAddress
         #$certCN = $SpecIFic.SubjectDN.CN
         $url = 'https://radware-public.okta.com/api/v1/authn'

#Set up API credentials"
$api_user = $General.UserName
$api_pass = $General.UserPass
$body = @"
{"username":"$api_user",
"password":"$api_pass",
"options": 
        {
        "multiOptionalFactorEnroll": true,
        "warnBeforePasswordExpired": true
        }
    }
"@


<##########################
  Authentication request 
##########################>

$API_result = Invoke-RestMethod -Uri $url -Method POST -Body $body -ContentType "application/json"
IF ($API_result.status -eq 'SUCCESS') {
    $SessionToken = $API_result.sessionToken #Required to get client authorization token
    $session_id = $API_result._embedded.user.id
    "Session Token" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    <###########################
      Get Authorization Token 
    ###########################>
    $url = (
        "https://radware-public.okta.com/oauth2/aus2m0h583tl6JWsL1t7/v1/authorize?client_id=M1Bx6MXpRXqsv3M1JKa6" +
        "&nonce=n-0S6_WzA2M&" +
        "prompt=none&" +
        "redirect_uri=https%3A%2F%2Fportal.radwarecloud.com%2F&" + 
        "response_mode=okta_post_message&" +
        "response_type=token&" +
        "scope=openid%20email%20roles%20tenant&" +
        "sessionToken=$SessionToken&" +
        "state=af0IFjsldkj"
    )
    "URL $url" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $API_result = Invoke-RestMethod -Uri $url -Method GET -ContentType "application/json" -UseBasicParsing
    "API_result $API_result" | out-file -Append  $DEBUG_FILE -ErrorAction SilentlyContinue
    $authorization_token = $null
    $authorization_token0 = $null
    IF ($API_result.html.head.script.'#text' -match "data.access_token = '(?<ACCESS_TOKEN>.*)'") {
        $authorization_token0 = $matches["ACCESS_TOKEN"]
        $authorization_token = $authorization_token0.replace("\x2D","-")
    } 
    else 
    {
        return @{ Result= "API Token failure:  $($API_result.status)"}
    }
}
"End of Auth"  | out-file -Append  $DEBUG_FILE -ErrorAction SilentlyContinue
<##########################
Get all certs loaded in tenant
##########################>
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer $authorization_token")
$headers.Add("requestEntityIds", "$TenantID`n")
$headers.Add("applicationID", "")
$Tenantcerts = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/sslcertificates/' -Method 'GET' -Headers $headers
"All Certs in Tenant" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
$Tenantcerts | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

# Gets common name from Venafi
################################ Thumbprint from CertIFicate in Venafi ################################################
    $file = (Get-ItemProperty "HKLM:\SOFTWARE\Venafi\Platform")."Base Path" + "Logs\cert.txt"
    $SpecIFic.CertPem > $file
    $vcert = New-Object System.Security.Cryptography.X509CertIFicates.X509CertIFicate2 $file
    $thumbprint = $vcert.thumbprint

    "Veanfi Cert fingerprint: $thumbprint" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $certs = @()
    $vsub = $vcert.Subject
   "vsub: $vsub" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

    $v = $vsub.Substring(0, $vsub.IndexOf(','))
    $vcn = $v.Trim("CN=")
    "VCN $vcn" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
# Gets common name from Radware
    foreach ($Tcert in $Tenantcerts){
             $PD = $Tcert.protectedDomains 
             
        IF ($PD -ne '*.generic.com' -and $PD -ne ""){

        $Tcert.certificateChain | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
            $rsub = $Tcert.protectedDomains
            "rsub    $rsub" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

            $Tcert.protectedDomains | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
            $PD | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
            $r = $rsub.Substring(0, $rsub.IndexOf(';'))
            $cn = $r.Trim("CN=")
 
            $certs += $cn #creates array of all certificate common names in Tenant
         IF ($vcn -eq $cn) { # Gets Cert data from Radware (IF common name from Venafi matches the common name in Radware tenant)
             $global:rcert = $Tcert
             $rcn = $cn}
             $global:thumb = $rcert.fingerprint
             "RCert $rcert" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        } 

        IF ($PD -eq '*.generic.com'){ # Gets Generic cert data
        $Gcert = $Tcert
        $fingerprint = $Gcert.fingerprint
        }

    } 
"Certs: $certs"  | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
"radware cert Thumb : $thumb" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
"Venafi cert thumbprint : $thumbprint" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
"Place holder cert fingerprint : $fingerprint" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
"VCN $vcn"  | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
"RCN $rcn" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
<######################################################################################################################
 ######################################################################################################################
                                                New Certificate
###################################################################################################################### 
$rcn is common name from Radware
$vcn is common name from Venafi
######################################################################################################################>
IF ($vcn -notin $certs){
"If $vcn not in $certs" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
<###############################
       Install New Cert
###############################>
$selfsigned = $General.VarBool1.ToString() -eq "True"
$selfsigned| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
If ($selfsigned) { #Checks if Private or Public CA
#Install Cert 
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $authorization_token")
    $headers.Add("requestEntityIds", "$TenantID`n")
    $headers.Add("selfSigned", "true") 
    $headers.Add("Content-Type", "application/json")
    $body = "{`"certificate`":`"$($Specific.CertPem)`",`"chain`":`"$($Specific.ChainPem)`",`"key`":`"$($Specific.PrivKeyPem)`",`"passphrase`":`"$($Specific.EncryptPass)`"}"
    $response = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/sslcertificates/secret' -Method 'POST' -Headers $headers -Body $body -TimeoutSec 30
    $response | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    }
else {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $authorization_token")
    $headers.Add("requestEntityIds", "$TenantID`n")
    $headers.Add("selfSigned", "false") 
    $headers.Add("Content-Type", "application/json")
    $body = "{`"certificate`":`"$($Specific.CertPem)`",`"chain`":`"$($Specific.ChainPem)`",`"key`":`"$($Specific.PrivKeyPem)`",`"passphrase`":`"$($Specific.EncryptPass)`"}"
    $response = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/sslcertificates/secret' -Method 'POST' -Headers $headers -Body $body -TimeoutSec 30
    $response | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    }

<###############################
      Create Application
###############################

    $newapp = $General.VarBool2.ToString() -eq "True"
    IF ($newapp){$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
         "Create Application" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        $headers.Add("Authorization", "Bearer $authorization_token")
        $headers.Add("requestEntityIds", "$TenantID`n")
        $headers.Add("Content-Type", "text/plain")

        $body = "{
        `n	`"applicationName`": `"$Text3`",
        `n    `"mainDomain`": `"$Text4`",
        `n    `"fingerprint`": `"$thumb`",
        `n    `"originServers`": [
        `n      {
        `n        `"address`": `"$Text5`",
        `n        `"addressType`": `"IP`"
        `n      }
        `n    ],
        `n    `"protocol`": `"BOTH`",
        `n    `"region`": `"$Text6`",
        `n    `"securityPolicy`": {
        `n      `"protectionMode`": `"IMMEDIATE`",
        `n      `"technology`": `"ASP_NET`"
        `n    }
        `n  }"

        #$response = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/applications/' -Method 'POST' -Headers $headers -Body $body} 
        $response | out-file -Append $global:log
        #>
         } #end IF new cert
 "End New Cert" |  out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue       
<######################################################################################################################
Renewed Certificate
######################################################################################################################
                                                Unbound Certificate 
######################################################################################################################
$fingerprint is the app Place holder certificate (*.generic.com) fingerprint
$thumb is the fingerprint of the current certificate in radware
$thumbprint is the fingerprint of the renewed certificate from Venafi 
######################################################################################################################>
IF ($vcn -in $certs) { # re-check IF cert exists
"Common name exists" |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

 IF ($rcert.applications.count -eq 0) { # Check IF not bound to any apps
 "Unbound Certifgicate" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
 $rcert.applications.count | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
<###############################
      Delete Certificate
###############################>
    
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("requestEntityIds", "$TenantID`n")
    $headers.Add("Authorization","Bearer $authorization_token")
        $body = "[{
    `n
    `n}]"

    "Delete Unbound Cert"|out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    "headers" |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $headers | fl >> $DEBUG_FILE -ErrorAction SilentlyContinue 

    "Body $body" |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    "$thumb :: $rcert"  |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

    $response = Invoke-RestMethod "https://portal.radwarecloud.com/v1/configuration/sslcertificates/$thumb" -Method 'DELETE' -Headers $headers -Body $body
    $response | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds (5000 * $global:latency_factor)

<###############################
      Upload Certificate
###############################>
"Upload Unbound Cert"|out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
$selfsigned = $General.VarBool1.ToString() -eq "True"
If ($selfsigned) { #Checks if Private or Public CA
#Install Cert 
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $authorization_token")
    $headers.Add("requestEntityIds", "$TenantID`n")
    $headers.Add("selfSigned", "true") 
    $headers.Add("Content-Type", "application/json")
    $body = "{`"certificate`":`"$($Specific.CertPem)`",`"chain`":`"$($Specific.ChainPem)`",`"key`":`"$($Specific.PrivKeyPem)`",`"passphrase`":`"$($Specific.EncryptPass)`"}"
    $response = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/sslcertificates/secret' -Method 'POST' -Headers $headers -Body $body -TimeoutSec 30
    $response | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    }
else {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $authorization_token")
    $headers.Add("requestEntityIds", "$TenantID`n")
    $headers.Add("selfSigned", "false") 
    $headers.Add("Content-Type", "application/json")
    $body = "{`"certificate`":`"$($Specific.CertPem)`",`"chain`":`"$($Specific.ChainPem)`",`"key`":`"$($Specific.PrivKeyPem)`",`"passphrase`":`"$($Specific.EncryptPass)`"}"
    $response = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/sslcertificates/secret' -Method 'POST' -Headers $headers -Body $body -TimeoutSec 30
    $response | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    }
       } #end IF Unbound Cert


<####################################################################################################################
                                                Bound Certificate 
######################################################################################################################
$apps isall the applications bound to the certificate
$app is the application being unbound/rebound 
######################################################################################################################>
$rcert | out-file -Append  $DEBUG_FILE -ErrorAction SilentlyContinue
"App Count $($rcert.applications.count)" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
IF ($rcert.applications.count -ne 0 ) {
"Bound Certificate" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $apps = $rcert.applications |FL
"Apps $apps" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
$rcert.applications | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

    foreach ($appID in $rcert.applications.applicationUUID) { 
<###############################
      Get Application Data
###############################> 
###############################> 
$headers3 = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers3.Add("Authorization", "Bearer $authorization_token")
    $headers3.Add("requestEntityIds", "$TenantID`n")
    $headers3.Add("applicationID", "$appID")
    $App = Invoke-RestMethod "https://portal.radwarecloud.com/v1/gms/applications/$appID" -Method 'GET' -Headers $headers3
    "APP $app" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $appname = $app.name
    $servicesID =($app.applicationServices[0]).id
    $healthID =($app.healthChecks[0]).id 
 

  
<###############################
      Unbind Application
###############################>
"Unbind App"  | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
 set app variables
    $GcertID =$Gcert.id
    "GcertID $GcertID" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
   # UNbind Applications

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("requestEntityIds", "$TenantID`n")
            $headers.Add("Authorization","Bearer $authorization_token")
            $headers.Add("Content-Type", "application/json")
            $headers | FL >>  $DEBUG_FILE -ErrorAction SilentlyContinue
            $body = "{`"applicationServices`":[{`"id`":`"$servicesID`",`"frontPort`":443,`"backPort`":443,`"type`":`"HTTPS`",`"description`":null,`"enabled`":true}],`"certificateId`":`"$Gcertid`",`"redirect`":null,`"healthChecks`":[{`"id`":`"$healthID`",`"type`":`"TCP`",`"port`":443,`"hostname`":null,`"url`":null,`"responseCode`":null}]}"
            $body | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
            $response = Invoke-RestMethod "https://portal.radwarecloud.com/v1/configuration/applications/$appID/networkConfiguration" -Method 'PUT' -Headers $headers -Body $body          
            $response | out-file -Append  $DEBUG_FILE -ErrorAction SilentlyContinue
 }
<###############################
      Delete Certificate
###############################>
"5 min wait to delete cert"| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
Start-Sleep -Seconds (300 * $global:latency_factor) # 5min

    " Delete previously bound cert"  |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("requestEntityIds", "$TenantID`n")
    $headers.Add("Authorization","Bearer $authorization_token")
        $body = "[{
    `n
    `n}]"


    "headers" |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $headers | fl >> $DEBUG_FILE -ErrorAction SilentlyContinue 

    "Body $body" |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    "$thumb :: $rcert"  |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

    $response = Invoke-RestMethod "https://portal.radwarecloud.com/v1/configuration/sslcertificates/$thumb" -Method 'DELETE' -Headers $headers -Body $body
    $response | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

Start-Sleep -Milliseconds (6000 * $global:latency_factor)
    
"Uploading Cert"| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
<###############################
      Upload Certificate
###############################>
$selfsigned = $General.VarBool1.ToString() -eq "True"
$selfsigned| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
If ($selfsigned) { #Checks if Private or Public CA
#Install Cert 
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $authorization_token")
    $headers.Add("requestEntityIds", "$TenantID`n")
    $headers.Add("selfSigned", "true") 
    $headers.Add("Content-Type", "application/json")
    $body = "{`"certificate`":`"$($Specific.CertPem)`",`"chain`":`"$($Specific.ChainPem)`",`"key`":`"$($Specific.PrivKeyPem)`",`"passphrase`":`"$($Specific.EncryptPass)`"}"
    $response = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/sslcertificates/secret' -Method 'POST' -Headers $headers -Body $body -TimeoutSec 30
    $response | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    }
else {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $authorization_token")
    $headers.Add("requestEntityIds", "$TenantID`n")
    $headers.Add("selfSigned", "false") 
    $headers.Add("Content-Type", "application/json")
    $body = "{`"certificate`":`"$($Specific.CertPem)`",`"chain`":`"$($Specific.ChainPem)`",`"key`":`"$($Specific.PrivKeyPem)`",`"passphrase`":`"$($Specific.EncryptPass)`"}"
    $response = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/sslcertificates/secret' -Method 'POST' -Headers $headers -Body $body -TimeoutSec 30
    $response | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    }
    
Start-Sleep -Seconds (20 * $global:latency_factor)
"re-binding $($rcert.applications)"| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
<###############################
      Re-Bind Application
###############################>
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer $authorization_token")
$headers.Add("requestEntityIds", "$TenantID`n")
$headers.Add("applicationID", "")
$Tenantcerts = Invoke-RestMethod 'https://portal.radwarecloud.com/v1/configuration/sslcertificates/' -Method 'GET' -Headers $headers
"All Certs in Tenant" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
$Tenantcerts | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
Foreach ($cert in $Tenantcerts){
if ($cert.fingerprint -eq $thumbprint){
$certID = $cert.id }}

foreach ($appID in $rcert.applications.applicationUUID) {
"Rebind $apps" |out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    
 # Get each app details 
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $authorization_token")
    $headers.Add("requestEntityIds", "$tenantID")
    $certapp = Invoke-RestMethod "https://portal.radwarecloud.com/v1/gms/applications/$appID" -Method 'GET' -Headers $headers

    #set app variables
    $applicationId = $app.Id
    $servicesID =($certapp.applicationServices[0]).id
    $healthID =($certapp.healthChecks[0]).id 
    # Rebind Applications

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("requestEntityIds", "$TenantID`n")
            $headers.Add("Authorization","Bearer $authorization_token")
            $headers.Add("Content-Type", "application/json")
            $headers | FL >>  $DEBUG_FILE -ErrorAction SilentlyContinue
            $body = "{`"applicationServices`":[{`"id`":`"$servicesID`",`"frontPort`":443,`"backPort`":443,`"type`":`"HTTPS`",`"description`":null,`"enabled`":true}],`"certificateId`":`"$certid`",`"redirect`":null,`"healthChecks`":[{`"id`":`"$healthID`",`"type`":`"TCP`",`"port`":443,`"hostname`":null,`"url`":null,`"responseCode`":null}]}"
            $body | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
            $response = Invoke-RestMethod "https://portal.radwarecloud.com/v1/configuration/applications/$appID/networkConfiguration" -Method 'PUT' -Headers $headers -Body $body          
            $response | out-file -Append  $DEBUG_FILE -ErrorAction SilentlyContinue
    
       } # Rebind Each previously bound App
 
     } #end If cert is Bound
   } # end Renewed Cert
 
################################################ End of Try #######################################################################      

} #end TRY
catch
    {

        throw $_.Exception.message
    }

    "Install CertIFicate Finished Successfully"
    clear-variable * -Scope Script -ErrorAction SilentlyContinue
    return @{ Result="Success"}

}



<######################################################################################################################
.NAME
    Update-Binding
.DESCRIPTION
    Binds the installed certIFicate with the consuming application or service on the hosting platform
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Update-Binding
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

        return @{ Result="Success"}
}


<######################################################################################################################
.NAME
    Activate-CertIFicate
.DESCRIPTION
    Performs any post-installation operations necessary to make the certIFicate active (such as restarting a service)
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Activate-CertIFicate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}


<######################################################################################################################
.NAME
    Extract-CertIFicate
.DESCRIPTION
    Extracts the active certIFicate from the hosting platform.  IF the platform does not provide a method for exporting the
    raw certIFicate then it is sufficient to return only the Serial and Thumprint.  This function is REQUIRED.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        CertPem : the extracted X509 certIFicate referenced by AssetName in Base64 PEM format
        Serial : the serial number of the X509 certIFicate refernced by AssetName
        Thumbprint : the SHA1 thumprint of the X509 certIFicate referenced by AssetName
######################################################################################################################>
function Extract-CertIFicate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="Success"; CertPem="-----BEGIN CERTIFICATE-----..."; Serial="ABC123"; Thumprint="DEF456" }
}


<######################################################################################################################
.NAME
    Extract-PrivateKey
.DESCRIPTION
    Extracts the private key associated with the certIFicate from the hosting platform
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER SpecIFic
    A hashtable containing the specIFic set of variables needed by this function
        EncryptPass : the string password to use when encrypting the private key
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        PrivKeyPem : the extracted private key in RSA Base64 PEM format (encrypted or not)
######################################################################################################################>
function Extract-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function SpecIFic Parameters")]
        [System.Collections.Hashtable]$SpecIFic
    )

    return @{ Result="NotUsed"; }
}


<######################################################################################################################
.NAME
    Remove-CertIFicate
.DESCRIPTION
    Removes an existing certIFicate (or private key) from the device.  Only implement the body of
    this function IF TPP can/should remove old generations of the same asset.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER SpecIFic
    A hashtable containing the specIFic set of variables needed by this function
        AssetNameOld : the name of a asset that was previously replaced and should be deleted
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Remove-CertIFicate
{
#
Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function SpecIFic Parameters")]
        [System.Collections.Hashtable]$SpecIFic
    )
    
    return @{ Result="Success"; }
}

<###################### THE FUNCTIONS AND CODE BELOW THIS LINE ARE NOT CALLED DIRECTLY BY VENAFI ######################>

$global:latency_factor = 1.0
$global:error_log = (Get-ItemProperty "HKLM:\SOFTWARE\Venafi\Platform")."Base Path" + "Logs\radware-error.log"
