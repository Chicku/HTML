$ErrorActionPreference = "SilentlyContinue"
$WarningActionPreference = "SilentlyContinue"

$CheckPS = Get-Command Get-Mailbox
If ($CheckPS.Name -ne "Get-Mailbox")
	{Write-Host "This script must be run using the Exchange Management Shell. Please close this PowerShell session, open the Exchange Management Shell, and then run the configuration script again." -back red -for black
	 $ErrorActionPreference = "Continue"
	 exit}

$ErrorActionPreference = "Continue"
$WarningActionPreference = "Continue"

Get-ExchangeServer *>&1 | Out-Null

$DC = (Get-ADDomain).InfrastructureMaster

$LabDomain = (Get-AcceptedDomain | where {$_.DomainName -like "Lab*"}).DomainName.Domain.Substring(0,8) 

$MBXServer = (Get-ExchangeServer | where-object {($_.ServerRole -like "Mailbox*") -and ($_.Name -eq $env:computername)}).Name

$LyncPool = "redpool.contoso.local"

Function VerifyPath1 {
$filepath = Test-Path "C:\LabFiles\DigiCert_certs.zip"
return $filepath
}

Function Extract {
if (VerifyPath1 -eq "True") {

$shell = new-object -com shell.application
$zip = $shell.NameSpace("C:\LabFiles\DigiCert_certs.zip")
foreach($item in $zip.items())
 {
 $shell.Namespace("C:\LabFiles").copyhere($item)
 }

} else {

write-host "The DigiCert_certs.zip file does not appear to be located in the C:\LabFiles folder. Please verify the file exists and rerun the script." -back red -for black

exit

}
}

Extract


#Importing the publicly trusted certificate and assigning services for Exchange Server

Write-Host "Importing the publicly trusted certificate and assigning services for Exchange Server" -back yellow -for black

$CertPath = "C:\LabFiles\certs\sip_" + $Labdomain + "_o365ready_com.cer"

Import-ExchangeCertificate -Server $MBXServer -FileData ([Byte[]]$(Get-Content -Path $CertPath -Encoding Byte -ReadCount 0)) | Out-Null

Start-Sleep -s 3

$Cert = Get-ExchangeCertificate | where {$_.Subject -like "CN=sip*"} 

Enable-ExchangeCertificate -Thumbprint $Cert.Thumbprint -Service IIS,SMTP -Force

Start-Sleep -s 3

$password = ConvertTo-SecureString 'Pa$$w0rd' -asplaintext -force

[String]$CertThumb = $Cert.Thumbprint

Export-PfxCertificate -Cert cert:\LocalMachine\My\$CertThumb -ChainOption BuildChain -FilePath C:\LabFiles\LabCert.pfx -Password $password | Out-Null


# Completing private certificate request and importing certificate

certreq -submit -config DC1.Contoso.local\Contoso-DC1-CA -attrib "CertificateTemplate:WebServer" C:\Scripts\PrivCertRequest.req C:\Scripts\PrivCert.cer | Out-Null

$CertPath = "C:\Scripts\PrivCert.cer"

Import-ExchangeCertificate -Server $MBXServer -FileData ([Byte[]]$(Get-Content -Path $CertPath -Encoding Byte -ReadCount 0)) | Out-Null

$PrivCert = Get-ExchangeCertificate | where {$_.Subject -like "CN=mail*"}

Get-ChildItem -Path C:\Scripts -Recurse | Where {$_.Name -like "Priv*"} | Remove-Item


# Configure Outlook Web App for IM integration

Write-Host "Configure Outlook Web App IM integration" -back yellow -for black

Get-OwaVirtualDirectory -Server $MBXServer | Set-OwaVirtualDirectory -InstantMessagingType OCS -InstantMessagingEnabled $true

Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -InstantMessagingEnabled $true -InstantMessagingType OCS

$filepath = "\\$MBXServer\C$\Program Files\Microsoft\Exchange Server\v15\ClientAccess\Owa\"

$file = "web.config"

$fileName = $filepath + $file

$tag = "<appSettings>"

$key1 = '<add key="IMCertificateThumbprint"' + ' value="' + $PrivCert.thumbprint + '" />'

$key2 = '<add key="IMServerName"' + ' value="' + $LyncPool + '" />'

$value = ($tag+"`r`n"+$key1+"`r`n"+$key2)

Copy-Item $filename ($filepath + $file + ".backup" + (Get-Date -format 'yyyy-MM-dd.hh.mm'))
  
(Get-Content $filename) | Foreach-Object {$_ -replace $tag,$value} | Set-Content $filename

C:\windows\system32\inetsrv\appcmd recycle apppool /apppool.name:"MSExchangeOWAAppPool" | Out-Null


# Import certificate into Local Machine Certificate Store on TMG1, configure Firewall and Web Listener

Write-Host "Importing the publicly trusted certificate, configuring firewall and web listener on TMG1" -back yellow -for black

Get-PsSession | where {$_.ComputerName -eq "TMG1"} | Remove-PsSession

$username = "Admin"

$password = ConvertTo-SecureString 'Pa$$w0rd' -asplaintext -force

$cred = New-Object System.Management.Automation.PsCredential($username,$password)

New-PSDrive -Name TMG -PSProvider FileSystem -Credential $cred -Root \\TMG1\c$\LabFiles | out-null

Copy-Item C:\LabFiles\Labcert.pfx TMG:\

$PubCertThumbprint = (Get-ExchangeCertificate | where {$_.Subject -like "CN=sip*"}).Thumbprint

$sessionTMG = New-PSSession -ComputerName TMG1 -Credential $cred

Invoke-Command -Session $sessionTMG -ScriptBlock {

$certcmd = 'certutil -p Pa$$w0rd -importpfx C:\LabFiles\Labcert.pfx'

cmd.exe /c $certcmd | Out-Null

# Import lab rules xml file

$FPC =  New-Object -ComObject FPC.root
$array = $FPC.GetContainingArray()
$LabTMGrules = "C:\LabFiles\LabTMGRules-$args.xml"
$PolicyRules = $Array.ArrayPolicy.PolicyRules
$PolicyRules.ImportFromFile($LabTMGrules,"")
$Array.Save($True,$True)

# Update existing web listener certificate with public certificate

$FPC =  New-Object -ComObject FPC.root
$array = $FPC.GetContainingArray()
$listener = $array.RuleElements.WebListeners | Where-Object {$_.Name -eq "Lab Services"}
$LabCert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object {$_.Subject -like "CN=sip*"}
$NewCertThumb = $LabCert.Thumbprint
$MyServer= $FPC.GetContainingServer()
$Listener.Properties.AppliedSSLCertificates.Remove(1)
$NewCert = $MyServer.SSLServerCertificates | Where-Object { (([byte[]]$_.Hash | ForEach-Object { $_.ToString("X2") } ) -Join '' ) -eq $NewCertThumb}
$Listener.Properties.AppliedSSLCertificates.Add($NewCert.Hash,"")
$listener.Save($True,$True)

} -args $LabDomain | Out-Null

# Import certificate into Local Machine Certificate Store on member servers

Write-Host "Importing the publicly trusted certificate on member server(s)" -back yellow -for black

#If (Test-Connection -ComputerName VIS1 -Count 1 -Quiet) {
#
#Copy-Item C:\LabFiles\LabCert.pfx \\VIS1\C$\LabFiles
#
#Invoke-Command -ComputerName VIS1 -ScriptBlock {
#	
#	Import-PfxCertificate -FilePath C:\LabFiles\LabCert.pfx -Password $args[0] -CertStoreLocation cert:\localMachine\My
#
#	} -args $password
#	}
#Else {Write-Host "VIS1 not online"}

If (Test-Connection -ComputerName SRV1 -Count 1 -Quiet) {	

Copy-Item C:\LabFiles\LabCert.pfx \\SRV1\C$\LabFiles

Invoke-Command -ComputerName SRV1 -ScriptBlock {
	
	Import-PfxCertificate -FilePath C:\LabFiles\LabCert.pfx -Password $args[0] -CertStoreLocation cert:\localMachine\My | Out-Null

	} -args $password
	}
Else {Write-Host "SRV1 not online"}

Copy-Item C:\LabFiles\LabCert.pfx \\$DC\C$\LabFiles


""
Write-Host "Complete" -back yellow -for black


