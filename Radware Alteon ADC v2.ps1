<#//-----------------------------------------------------------------------// Radware Alteon ADC.ps1//// Copyright (c) 2016 Venafi, Inc.  All rights reserved.//// This sample script and its contents are provided by Venafi to customers// and authorized technology partners for the purposes of integrating with// services and platforms that are not owned or supported by Venafi.  Any// sharing of this script or its contents without consent from Venafi is// prohibited.//// This sample is provided "as is" without warranty of any kind.// Requires Posh-SSH : Install-Module -Name Posh-SSH//// Added Push to management servers and Debug functionality - Caterpillar, Inc 3/17/2022//-----------------------------------------------------------------------<#
Adaptable Application Driver Behavior Customization Script

<field name>|<label text>|<flags>

Bit 1 = Enabled
Bit 2 = Policyable
Bit 3 = Mandatory

-----BEGIN FIELD DEFINITIONS-----
Text1|Virtual Server|111
Text2|Service Port|111
Text3|SSL Policy|110
Text4|Certificate Group|110
Text5|Not Used|000
Option1|Save to Startup Config|111
Option2|Push to Management (not VIP)|110
Passwd|Not Used|000
-----END FIELD DEFINITIONS-----
#> 
$global:latency_factor = 1.0
$global:error_log = (Get-ItemProperty "HKLM:\SOFTWARE\Venafi\Platform")."Base Path" + "Logs\radwareADC-error.log"

Import-Module -Name Posh-SSH

if ((Get-Module -Name "Posh-SSH") -eq $null)
{
    throw "Posh-SSH failed to import"
}

<##################################################################################################
.NAME
    Prepare-KeyStore
.DESCRIPTION
    Remotely create and/or verify keystore on the hosting platform.  Remote generation is considered UNSUPPORTED if this
    function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions
        HostAddress : a string containing the hostname or IP address specified by the device object
        TcpPort : an integer value containing the TCP port specified by the application object
        UserName : a string containing the username portion of the credential assigned to the device or application object
        UserPass : a string containing the password portion of the credential assigned to the device or application object
        AppObjectDN : a string containing the TPP distiguished name of the calling application object
        AssetName : a string containing a Venafi standard automatically generated name that can be used for provisioning (<Common Name>-<ValidTo as YYMMDD>-<Last 4 of SerialNum>)
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
##################################################################################################>
function Prepare-KeyStore
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )
    return @{ Result="NotUsed"; }
}


<##################################################################################################
.NAME
    Generate-KeyPair
.DESCRIPTION
    Remotely generates a public-private key pair on the hosting platform.  Remote generation is 
    considered UNSUPPORTED if this function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        KeySize : the integer key size to be used when creating a key pair
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
################################################################################################## >
function Generate-KeyPair
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )
    return @{ Result="NotUsed"; }
}


<##################################################################################################
.NAME
    Generate-CSR
.DESCRIPTION
    Remotely generates a CSR on the hosting platform.  Remote generation is considered UNSUPPORTED
    if this function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        SubjectDN : the requested subject distiguished name as a hashtable; OU is a string array; all others are strings
        SubjAltNames : hashtable keyed by SAN type; values are string arrays
        KeySize : the integer key size to be used when creating a key pair
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        Pkcs10 : a string representation of the CSR in PKCS#10 format
################################################################################################## >
function Generate-CSR
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )
    return @{ Result="NotUsed"; }
}


<##################################################################################################
.NAME
    Install-Chain
.DESCRIPTION
    Installs the certificate chain on the hosting platform.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        ChainPem : all chain certificates concatentated together one after the other
        ChainPkcs7 : byte array PKCS#7 collection that includes all chain certificates
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Install-Chain
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )
    "Install Chain" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $chain | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ( $Specific.ChainPkcs7 )
    {
        $chain.Import( $Specific.ChainPkcs7 )
    }
    else # there is no chain for the certificate being provisioned
    {
        return @{ Result="Success"; }
    }

    $passwd = ConvertTo-SecureString -String $General.UserPass -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential($General.UserName, $passwd)

    $session = New-SSHSession -ComputerName $General.HostAddress -Port $General.TcpPort -AcceptKey -Credential $creds
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*Confirm seeing above note `[y`]:*')
    {
        # acknowledge that there are pending changes
        $stream.Write("y`n")
        $stream | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    }

    foreach ( $cert in $chain )
    {
        $b64 = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
        $b64 = "-----BEGIN CERTIFICATE-----`n" + $b64 + "`n-----END CERTIFICATE-----"

        $stream.Write("/cfg/slb/ssl/certs/import intermca $($cert.SerialNumber) text`n")
        $stream.Write("$b64`n`n")
        Start-Sleep -Milliseconds (5000 * $global:latency_factor)
        $output = $stream.Read()
        $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        if ( $output -like '*intermca added.*' )
        {
            if ( $General.VarText4 ) # there is a certificate group to create/update
            {
                $stream.Write("/cfg/slb/ssl/certs/group $($General.VarText4)`n")
                $stream.Write("add`n")
                $stream.Write("$($cert.SerialNumber)`n")
                $stream | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds (3000 * $global:latency_factor)
            }
            $stream.Write("apply`n")
            Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        }
    }
    if ( $General.VarText3 ) # there is an ssl policy to create/update
    {
        $stream.Write("/cfg/slb/ssl/sslpol $($General.VarText3)`n")
        $stream.Write("intermca`n")
        $stream.Write("group`n")
        $stream.Write("$($General.VarText4)`n")
        $stream.Write("ena`n")
        $stream | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    }
    $stream.Write("apply`n")
    $stream | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)

    $stream.Write("exit`n")
    $stream | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    $stream.Read() | Out-Null
    $stream.Close()
    Remove-SSHSession -SSHSession $session | Out-Null
    "Removed  install chain Session" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    return @{ Result="Success"; }
}


<##################################################################################################
.NAME
    Install-PrivateKey
.DESCRIPTION
    Installs the private key on the hosting platform.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        PrivKeyPem : the non-encrypted private key in RSA Base64 PEM format
        PrivKeyPemEncrypted : the password encrypted private key in RSA Base64 PEM format
        EncryptPass : the string password that was used to encrypt the private key and PKCS#12 keystore
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
        AssetName : (optional) the name used to reference the private key as it was installed on the device; if not supplied the automatically generated name is assumed
##################################################################################################>
function Install-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    $result = $null

    Assert-NotNullOrEmpty "Private Key Name" $General.AssetName
    Assert-NotNullOrEmpty "Private Key PEM" $Specific.PrivKeyPem

    $passwd = ConvertTo-SecureString -String $General.UserPass -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential($General.UserName, $passwd)

    $session = New-SSHSession -ComputerName $General.HostAddress -Port $General.TcpPort -AcceptKey -Credential $creds
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    "Install Private Key" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    
   Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*Confirm seeing above note `[y`]:*')
    {
        # acknowledge that there are pending changes
        $stream.Write("y`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    }

    $name = Fix-CertKeyName $General.AssetName
    $name | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $stream.Write("/cfg/slb/ssl/certs/import key $name text`n")
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*already exists in the repository*')
    {
        # private key already exists so we're done
        $stream.Write("n`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        $result = "AlreadyInstalled"
    }
    else
    {
        $stream.Write("$($Specific.PrivKeyPem)`n`n")
        Start-Sleep -Milliseconds (4000 * $global:latency_factor)
        $output = $stream.Read()
        $soutput | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        if ( $output -like '*key added.*' )
        {
            $stream.Write("apply`n")
            $result = "Success"
        }
    }

    $stream.Write("exit`n")
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    $stream.Read() | Out-Null
    $stream.Close()
    Remove-SSHSession -SSHSession $session | Out-Null
    "Removed install priveate key session"  | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ( $result )
    {
        # this function sets the asset name that all subsequent function calls will need
		return @{ Result=$result; AssetName=$name }
    }
    else
    {
        $output | Out-File -Append $global:error_log
        $soutput | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        throw "Private Key installation failed. " + $($output.Split("`n") | Select-String "Error" | Select -First 1 | % {$_.Line} )
    }
}


<##################################################################################################
.NAME
    Install-Certificate
.DESCRIPTION
    Installs the certificate on the hosting platform.  May optionally be used to also install the private key and chain.
    Implementing logic for this function is REQUIRED.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        CertPem : the X509 certificate to be provisioned in Base64 PEM format
        PrivKeyPem : the non-encrypted private key in RSA Base64 PEM format
        PrivKeyPemEncrypted : the password encrypted private key in RSA Base64 PEM format
        ChainPem : all chain certificates concatentated together one after the other
        ChainPkcs7 : byte array PKCS#7 collection that includes all chain certificates
        Pkcs12 : byte array PKCS#12 collection that includes certificate, private key, and chain
        EncryptPass : the string password that was used to encrypt the private key and PKCS#12 keystore
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state (may only be 'NotUsed' if Install-PrivateKey did not return 'NotUsed')
        AssetName : (optional) the name used to reference the certificate as it was installed on the device; if not supplied the automatically generated name is assumed
##################################################################################################>
function Install-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    $result = $null

    Assert-NotNullOrEmpty "Certificate Name" $General.AssetName
    Assert-NotNullOrEmpty "Certificate PEM" $Specific.CertPem

    $passwd = ConvertTo-SecureString -String $General.UserPass -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential($General.UserName, $passwd)

    $session = New-SSHSession -ComputerName $General.HostAddress -Port $General.TcpPort -AcceptKey -Credential $creds
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    $output = $stream.Read()
    "Install Certificate"  | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $soutput | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*Confirm seeing above note `[y`]:*')
    {
        # acknowledge that there are pending changes
        $stream.Write("y`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    }

    $stream.Write("/cfg/slb/ssl/certs/import certificate $($General.AssetName) text`n") # srvcrt changed to certificate as per 30.2 and above ---RAJ
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    $output = $stream.Read()
    $soutput | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*already exists in the repository*')
    {
        # private key already exists so we're done
        $stream.Write("n`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        $result = "AlreadyInstalled"
    }
    else
    {
        $stream.Write("$($Specific.CertPem)`n")
        Start-Sleep -Milliseconds (5000 * $global:latency_factor)
        $output = $stream.Read()
        $soutput | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        if ( $output -like '*certificate added.*' )# modified '*srvrcrt added* to * added * as the string changed from srvrcrt to certificate ---RAJ
        {
            $stream.Write("apply`n")
            $result = "Success"
        }
    }

    $stream.Write("exit`n")
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    $stream.Read() | Out-Null
    $stream.Close()
    Remove-SSHSession -SSHSession $session | Out-Null
    "Removed install certificate session"  | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ( $result )
    {
        return @{ Result=$result; }
    }
    else
    {
        $output | Out-File -Append $global:error_log
        $soutput | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        throw "Certificate installation failed. " + $($output.Split("`n") | Select-String "Error" | Select -First 1 | % {$_.Line})
    }
}


<##################################################################################################
.NAME
    Update-Binding
.DESCRIPTION
    Binds the installed certificate with the consuming application or service on the hosting platform
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Update-Binding
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )
    "Update Binding" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
     if ( $General.VarBool2 )
        {
        "Update Management $General.HostAddress" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
           Update-Management
        }
        else{
        "Update $General.VarText1" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    Assert-NotNullOrEmpty "Certificate Name" $General.AssetName
    Assert-NotNullOrEmpty "Virtual Server" $General.VarText1
    Assert-NotNullOrEmpty "Service Port" $General.VarText2

    $passwd = ConvertTo-SecureString -String $General.UserPass -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential($General.UserName, $passwd)

    $session = New-SSHSession -ComputerName $General.HostAddress -Port $General.TcpPort -AcceptKey -Credential $creds
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    $output = $stream.Read()
    if ($output -like '*Confirm seeing above note `[y`]:*')
    {
        # acknowledge that there are pending changes
        $stream.Write("y`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    }

    $stream.Write("/cfg/slb/virt $($General.VarText1)`n")
    $stream.Write("service $($General.VarText2) https`n`n")
    Start-Sleep -Milliseconds (2000 * $global:latency_factor)

    if ( $General.VarText3 ) # there is an ssl policy
    {
    "SSL Policy: $($General.VarText3)"| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        $stream.Write("ssl/sslpol`n")
        $stream.Write("$($General.VarText3)`n")
        Start-Sleep -Milliseconds (2000 * $global:latency_factor)
        $stream.Write("/cfg/slb/virt $($General.VarText1)`n")
        $stream.Write("service $($General.VarText2) https`n`n")
        Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    }

    $stream.Write("ssl/srvrcert cert $($General.AssetName)`n")
    Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ( $output -like '*For certificate*' ) 
    {
        $stream.Write("apply`n")

        if ( $General.VarBool1 )
        {
        "Save to Startup"| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds (9000 * $global:latency_factor) 
            $stream.Write("save`n")
            $stream.Write("y`n")
        }

        $stream.Write("exit`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        $stream.Read() | Out-Null
        $stream.Close()
        Remove-SSHSession -SSHSession $session | Out-Null
        "End Update $($General.VarText3) Binding session"| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        return @{ Result="Success"; }
    }
    else
    {
        $output | Out-File -Append $global:error_log
        $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        throw "Bind certificate to consumer failed. " + $($output.Split("`n") | Select-String "Error" | Select -First 1 | % {$_.Line})
            $stream.Write("exit`n")
            Start-Sleep -Milliseconds (1000 * $global:latency_factor)
            $stream.Read() | Out-Null
            $stream.Close()
            Remove-SSHSession -SSHSession $session | Out-Null
    }
    }
}

<##################################################################################################
.NAME
    Update-Management
.DESCRIPTION
    Binds the installed certificate with the consuming application or service on the hosting platform 
    Management Devices
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Update-Management
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )
    "Update Binding on Management" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    Assert-NotNullOrEmpty "Certificate Name" $General.AssetName

    $passwd = ConvertTo-SecureString -String $General.UserPass -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential($General.UserName, $passwd)

    $session = New-SSHSession -ComputerName $General.HostAddress -Port $General.TcpPort -AcceptKey -Credential $creds
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*Confirm seeing above note `[y`]:*')
    {
        # acknowledge that there are pending changes
        $stream.Write("y`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    }



    $stream.Write("/cfg/sys/access/https/ cert $($General.AssetName)`n")
    Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $output + "`n" | Out-File -FilePath C:\Users\Administrator\Desktop\script_debug.txt -Append
    if ( $output -like '*For certificate*' ) #Removed "Server" and truncated the string, as there is no "Server" ---RAJ
    {
        $stream.Write("apply`n")

        if ( $General.VarBool1 )
        {"Save to Startup" | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds (10000 * $global:latency_factor) #Added sleep ---RAJ
            $stream.Write("save`n")
            $stream.Write("y`n")
        }

        $stream.Write("exit`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        $stream.Read() | Out-Null
        $stream.Close()
        Remove-SSHSession -SSHSession $session | Out-Null

        return @{ Result="Success"; }
    }
    else
    {
        $output | Out-File -Append $global:error_log
        $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        throw "Bind certificate to consumer failed. " + $($output.Split("`n") | Select-String "Error" | Select -First 1 | % {$_.Line})
            $stream.Write("exit`n")
            Start-Sleep -Milliseconds (1000 * $global:latency_factor)
            $stream.Read() | Out-Null
            $stream.Close()
            Remove-SSHSession -SSHSession $session | Out-Null
    }
}


<##################################################################################################
.NAME
    Activate-Certificate
.DESCRIPTION
    Performs any post-installation operations necessary to make the certificate active (such as restarting a service)
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Activate-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )
    return @{ Result="NotUsed"; }
}


<##################################################################################################
.NAME
    Extract-Certificate
.DESCRIPTION
    Extracts the active certificate from the hosting platform.  If the platform does not provide a method for exporting the
    raw certificate then it is sufficient to return only the Serial and Thumprint.  This function is REQUIRED.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        CertPem : the extracted X509 certificate referenced by AssetName in Base64 PEM format
        Serial : the serial number of the X509 certificate refernced by AssetName
        Thumbprint : the SHA1 thumprint of the X509 certificate referenced by AssetName
##################################################################################################>
function Extract-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )
    "Extract Certificate"| out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    Assert-NotNullOrEmpty "Certificate Key Name" $General.AssetName

    $passwd = ConvertTo-SecureString -String $General.UserPass -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential($General.UserName, $passwd)

    $session = New-SSHSession -ComputerName $General.HostAddress -Port $General.TcpPort -AcceptKey -Credential $creds
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*Confirm seeing above note `[y`]:*')
    {
        # acknowledge that there are pending changes
        $stream.Write("y`n")
    }

    $stream.Write("/cfg/slb/ssl/certs/export srvrcert $($General.AssetName) text`n`n")
    Start-Sleep -Milliseconds (5000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

    $header = "-----BEGIN CERTIFICATE-----"
    $footer = "-----END CERTIFICATE-----"

    if ( $output -like "*$header*" )
    {
        $CertPem = ($output -split $header,2)[1]
        $CertPem = ($CertPem -split $footer,2)[0]

        $CertPem = $header + "`n" + $CertPem.Trim() + "`n" + $footer

        $stream.Write("exit`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        $stream.Read() | Out-Null
        $stream.Close()
        Remove-SSHSession -SSHSession $session | Out-Null

        return @{ Result="Success"; CertPem=$CertPem }
    }
    else
    {
        $output | Out-File -Append $global:error_log
        $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        throw "Certificate extraction failed. " + $($output.Split("`n") | Select-String "Error" | Select -First 1 | % {$_.Line} )
    }
}


<##################################################################################################
.NAME
    Extract-PrivateKey
.DESCRIPTION
    Extracts the private key associated with the certificate from the hosting platform
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        EncryptPass : the string password to use when encrypting the private key
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        PrivKeyPem : the extracted private key in RSA Base64 PEM format (encrypted or not)
##################################################################################################>
function Extract-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )
    "Extract Private Key"  | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    Assert-NotNullOrEmpty "Private Key Name" $General.AssetName
    Assert-NotNullOrEmpty "Private Key Password" $Specific.EncryptPass

    $passwd = ConvertTo-SecureString -String $General.UserPass -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential($General.UserName, $passwd)

    $session = New-SSHSession -ComputerName $General.HostAddress -Port $General.TcpPort -AcceptKey -Credential $creds
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*Confirm seeing above note `[y`]:*')
    {
        # acknowledge that there are pending changes
        $stream.Write("y`n")
    }

    $stream.Write("/cfg/slb/ssl/certs/export key $($General.AssetName) `"$($Specific.EncryptPass)`" text`n`n")
    Start-Sleep -Milliseconds (5000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    $header = "-----BEGIN RSA PRIVATE KEY-----"
    $footer = "-----END RSA PRIVATE KEY-----"

    if ( $output -like "*$header*" )
    {
        $KeyPem = ($output -split $header,2)[1]
        $KeyPem = ($KeyPem -split $footer,2)[0]

        $KeyPem = $header + "`n" + $KeyPem.Trim() + "`n" + $footer

        $stream.Write("exit`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        $stream.Read() | Out-Null
        $stream.Close()
        Remove-SSHSession -SSHSession $session | Out-Null

        return @{ Result="Success"; PrivKeyPem=$KeyPem }
    }
    else
    {
        $output | Out-File -Append $global:error_log
        $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        throw "Private Key extraction failed. " + $($output.Split("`n") | Select-String "Error" | Select -First 1 | % {$_.Line} )
    }
}


<##################################################################################################
.NAME
    Remove-Certificate
.DESCRIPTION
    Removes an existing certificate from IAM.  Only implement the body of this function
    if TPP can/should remove old generations of the same certificate.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        AssetNameOld : the name of a certificate that was previously replaced and should be deleted
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Remove-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )
    "Remove Certificate"  | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    Assert-NotNullOrEmpty "Old Certificate Name" $Specific.AssetNameOld

    $passwd = ConvertTo-SecureString -String $General.UserPass -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential($General.UserName, $passwd)

    $session = New-SSHSession -ComputerName $General.HostAddress -Port $General.TcpPort -AcceptKey -Credential $creds
    $stream = $session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    Start-Sleep -Milliseconds (2000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ($output -like '*Confirm seeing above note `[y`]:*')
    {
        # acknowledge that there are pending changes
        $stream.Write("y`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
    }

    $stream.Write("/cfg/slb/ssl/certs/key $($Specific.AssetNameOld)`n")
    $stream.Write("del`n")
    $stream.Write("both`n") # requires an additional argument to remove certificate and CSR
    Start-Sleep -Milliseconds (5000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue

            
    if ( $output -like "*request *$($Specific.AssetNameOld)* deleted*" ) #Change 
    {
        $stream.Write("apply`n")

        if ( $General.VarBool1 )
        {
            Start-Sleep -Milliseconds (1000 * $global:latency_factor)
            $stream.Write("save`n")
            $stream.Write("y`n")
        }

        $stream.Write("exit`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        $stream.Read() | Out-Null
        $stream.Close()
        Remove-SSHSession -SSHSession $session | Out-Null

        return @{ Result="Success"; }
    }

    # that didn't work as expected so verify that the srvrcert does not exist
    $stream.Write("/cfg/slb/ssl/certs/srvrcert $($Specific.AssetNameOld)`n")
    $stream.Write("cur`n")
    Start-Sleep -Milliseconds (5000 * $global:latency_factor)
    $output = $stream.Read()
    $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    if ( $output -like "*Certificate : not generated*" ) # removed "Server" as part of the string
    {
        $stream.Write("exit`n")
        Start-Sleep -Milliseconds (1000 * $global:latency_factor)
        $stream.Read() | Out-Null
        $stream.Close()
        Remove-SSHSession -SSHSession $session | Out-Null

        return @{ Result="Success"; }
    }
    else
    {
        $output | Out-File -Append $global:error_log
        $output | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
        throw "Certificate removal failed. " + $($output.Split("`n") | Select-String "Error" | Select -First 1 | % {$_.Line} )
    }
}


<########## THE FUNCTIONS AND CODE BELOW THIS LINE ARE NOT CALLED DIRECTLY BY VENAFI ##########>

function Assert-NotNullOrEmpty( [string]$name, [string]$value )
{
    if ( !$value )
    {
        throw "$($name) is required."
    }
}

function Fix-CertKeyName ( [string]$name )
{
    # cert/key name must be less than 32 characters
    if ( $name.Length -gt 32 )
    {
        $parts = $name.Split("_")
        $name = "_" + $parts[1] + "_" + $parts[2]  # keep the suffix as-is
        $name = $parts[0].Substring(0, 32 - $name.Length) + $name
    }
    $name | out-file -Append $DEBUG_FILE -ErrorAction SilentlyContinue
    # cert/key name may not include periods or special characters other than - and _
    return $name -Replace "\.","-"
}
