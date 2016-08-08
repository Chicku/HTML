$ErrorActionPreference = "SilentlyContinue"
$WarningActionPreference = "SilentlyContinue"

$CheckPS = Get-Command Get-Mailbox
If ($CheckPS.Name -ne "Get-Mailbox")
	{Write-Host "This script must be run using the Exchange Management Shell. Please close this PowerShell session, open the Exchange Management Shell, and then run the configuration script again." -back red -for black
	 $ErrorActionPreference = "Continue"
	 exit}
	
$ErrorActionPreference = "Continue"

[Void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
[Void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

# Start Exchange Services

$MBXServer = (Get-ExchangeServer | where-object {($_.ServerRole -like "Mailbox*") -and ($_.Name -eq $env:computername)}).Name

Get-Service -ComputerName $MBXServer | where-object {($_.Name -like "MSEx*") -and ($_.Name -notlike "MSExchangePop3*") -and ($_.Name -notlike "MSExchangeImap4*") -and ($_.Name -notlike "MSExchangeMonitoring")} | Start-Service

# Restart Certificate Services on Domain Controller

$DC = (Get-ADDomain).InfrastructureMaster

Invoke-Command -ComputerName $DC {Restart-Service CertSvc} | out-null

Start-Sleep -s 10

# Set child domain name

Do 
{
$cdname = [Microsoft.VisualBasic.Interaction]::InputBox("Please type your five digit lab number. This number will become part of the on-premises domain used throughout the labs.", "Lab Number")

if (($cdname.length -eq 5) -and ($cdname -match '\d{5}'))
{
[Void][System.Windows.Forms.MessageBox]::Show("Your On-premises public domain name is `n `nLab$cdname.O365Ready.com" , "On-premises Domain Name" , 0)
 $LabDomain = ("Lab" + $cdname + ".O365Ready.com")
 }
if ($cdname -eq "")
{
Write-Host "No value input detected or operation has been cancelled."
exit
}
if (($cdname.length -ne 5) -or ($cdname -notmatch '\d{5}'))
{
[Void][System.Windows.Forms.MessageBox]::Show("The lab number must be a five digit value. Please retry your entry" , "Invalid entry" , 1, "Warning")
}

}

While ($LabDomain -eq $null)

# Get Public IP address TMG1 from user input

[String]$IP = [Microsoft.VisualBasic.Interaction]::InputBox("Please type your organization's public IP address.", "Public IP Address")
	
if ($IP -notlike '*.*.*.*')
{
 [Microsoft.VisualBasic.Interaction]::MsgBox("The IP address does not appear to be in the correct format. For example 192.168.0.10 or 10.0.1.50")
 [String]$IP = [Microsoft.VisualBasic.Interaction]::InputBox("Please type your organization's public IP address.", "Public IP Address")
}

# Get Edge Server IP address from user input

[String]$EDG1PubIP = [Microsoft.VisualBasic.Interaction]::InputBox("Please type your Skype for Business Server Edge server's public IP address.", "Skype for Business Server Edge Public IP Address")
	
if ($EDG1PubIP -notlike '*.*.*.*')
{
 [Microsoft.VisualBasic.Interaction]::MsgBox("The IP address does not appear to be in the correct format. For example 192.168.0.10 or 10.0.1.50")
 [String]$EDG1PubIP = [Microsoft.VisualBasic.Interaction]::InputBox("Please type your Skype for Business Server Edge server's public IP address.", "Skype for Business Server Edge Public IP Address")
}


# Create new accepted domain based on lab domain and set as authoritative

Write-Host "Creating a new accepted domain for your lab domain" -back yellow -for black

New-AcceptedDomain -Name "On-premises Lab Domain" -DomainType "Authoritative" -DomainName $LabDomain | out-null

Start-Sleep -s 10


# Create e-mail address policy based on child domain and set as primary

Write-Host "Creating a new email address policy for your lab domain" -back yellow -for black

Set-EmailAddressPolicy -Identity "Default Policy" -EnabledEmailAddresstemplates "smtp:%m@contoso.local","SMTP:%m@$LabDomain"

Start-Sleep -s 5


# Remove secondary SMTP address

Set-EmailAddressPolicy -Identity "Default Policy" -EnabledEmailAddresstemplates "SMTP:%m@$LabDomain"

Start-Sleep -s 5


# Update e-mail address policy

Write-Host "Updating the organization's email address policy" -back yellow -for black

Update-EmailAddressPolicy -Identity "Default Policy"

Start-Sleep -s 5


# Create a new DNS zone based on the Child domain

Write-Host "Creating DNS records for your lab domain" -back yellow -for black

$session = New-PSSession -ComputerName $DC


# Create DNS zones

Invoke-Command -Session $session -ScriptBlock {

$ExchangeIP = ([System.Net.Dns]::GetHostAddresses("MBX1")).IPAddressToString

$SFE1IP = ([System.Net.Dns]::GetHostAddresses("SFE1")).IPAddressToString

$EDG1IP = ([System.Net.Dns]::GetHostAddresses("EDG1")).IPAddressToString

$SRV1IP = ([System.Net.Dns]::GetHostAddresses("SRV1")).IPAddressToString

[String]$Labdomain1 = $args

[String]$Rootdomain1 = $RootDomain

$IP = Get-NetIPAddress | Where-Object {($_.AddressFamily -eq "IPv4") -and ($_.IPAddress -ne "127.0.0.1")}


# Create Lab Domain Zone

Add-DnsServerPrimaryZone -Name $Labdomain1 -ReplicationScope 'Domain'

Start-Sleep -s 5


# Create new hosts in the lab domain DNS zones

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name $LabDomain1 -IPv4Address $ExchangeIP

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name mail -IPv4Address $ExchangeIP

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name EDG1 -IPv4Address $EDG1IP

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name lyncdiscoverinternal -IPv4Address $SFE1IP

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name admin -IPv4Address $SFE1IP

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name fs -IPv4Address $SRV1IP

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name meet -IPv4Address $SFE1IP

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name dialin -IPv4Address $SFE1IP

Add-DnsServerResourceRecord -ZoneName $LabDomain1 -Srv -Name "_sipinternaltls._tcp" -DomainName "sip.$LabDomain1" -Priority 0 -Weight 0 -Port 5061

Add-DnsServerResourceRecord -ZoneName $LabDomain1 -Srv -Name "_autodiscover._tcp" -DomainName "mail.$LabDomain1" -Priority 0 -Weight 0 -Port 443

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name sip -IPv4Address $SFE1IP

Add-DnsServerResourceRecordA -ZoneName $LabDomain1 -Name redpool -IPv4Address $SFE1IP

Add-DnsServerResourceRecordA -ZoneName $env:USERDNSDOMAIN -Name mail -IPv4Address $ExchangeIP

Add-DnsServerResourceRecordA -ZoneName $env:USERDNSDOMAIN -Name TMG1 -IPv4Address 192.168.0.254

Add-DnsServerResourceRecordA -ZoneName $env:USERDNSDOMAIN -Name sip -IPv4Address $SFE1IP

Add-DnsServerResourceRecordA -ZoneName $env:USERDNSDOMAIN -Name int-meetings -IPv4Address $SFE1IP

Add-DnsServerResourceRecordA -ZoneName $env:USERDNSDOMAIN -Name redpool -IPv4Address $SFE1IP

Add-DnsServerResourceRecordA -ZoneName $env:USERDNSDOMAIN -Name admin -IPv4Address $SFE1IP

#Add-DnsServerResourceRecordA -ZoneName $env:USERDNSDOMAIN -Name SRV2 -IPv4Address 192.168.0.195

Start-sleep -s 5

} -args $LabDomain


# Create Lab Organizational Units

Write-Host "Creating new organizational units" -back yellow -for black

New-ADOrganizationalUnit -Name Accounts | out-null 

New-ADOrganizationalUnit -Name Managers | out-null

New-ADOrganizationalUnit -Name Online | out-null


# Add the Child domain as a UPN Suffix

Write-Host "Creating the UPN suffix for your lab domain" -back yellow -for black

$usn = "$LabDomain"
$root = [ADSI]"LDAP://rootDSE"
$conf = [ADSI]"LDAP://cn=partitions,$($root.configurationNamingContext)"
$conf.uPNSuffixes += $usn
$conf.SetInfo()

Start-Sleep -s 10


# Setting the lab domain as the default accepted domain

Write-Host "Setting your lab domain as the default accepted domain" -back yellow -for black

Set-AcceptedDomain -Identity "On-premises Lab Domain" -MakeDefault $true | out-null 

Start-Sleep -s 5


# Create Mailboxes

Write-Host "Creating user mailboxes" -back yellow -for black

# Set Mailbox Database name variable

$MDBName = (Get-MailboxDatabase -Server $MBXServer).Name

# Mail Enable Adminsitrator

Enable-Mailbox -Identity Administrator -Alias Administrator -Database "$MDBName" | out-null

# Set Administrator account UPN suffix

Set-Mailbox -Identity Administrator -UserPrincipalName Administrator@$LabDomain | out-null

# Set Administrator mailbox language and location

Set-MailboxRegionalConfiguration -Identity Administrator -TimeZone "Pacific Standard Time" -Language en-us -ErrorAction SilentlyContinue

# Update Offline address book

Update-OfflineAddressBook -Identity (Get-OfflineAddressBook).Name

Start-Sleep -s 5

# Create users and mail enabled Users and set password to never expire

Import-Csv "DemoMailboxes.csv" | ForEach-Object {$Password = ConvertTo-SecureString $_.Password -asPlainText -force; New-Mailbox -Alias $_.Alias -FirstName $_.Fname -LastName $_.Lname -Name $_.name -userPrincipalName ($_.Alias + "@$LabDomain") -OrganizationalUnit $($env:USERDNSDOMAIN + $_.OU) -Password $Password -ResetPasswordOnNextLogon $False -Database "$MDBName" | out-null}

Start-Sleep -s 3

Import-Csv "DemoMailboxes.csv" | ForEach-Object {(Set-ADUser $_.Alias -PasswordNeverExpires $True);(Set-MailboxRegionalConfiguration -Identity $_.Alias -TimeZone "Pacific Standard Time" -Language en-us -ErrorAction SilentlyContinue)}

$count =0
$imagepath = ".\DemoUsersPictures\"
$csv = Import-Csv "DemoMailboxes.csv" 

foreach($line in $csv)
{
  $user = $photo = $image = $null
#  write-host $line.Name,$line.OfficePhone,$line.StreetAddress

  # Need to calculate progress and update UI
  #write-progress -percentcomplete 25 -Activity Installing -Status Installing

	$count=$count+1

try {
  
  $user = Get-ADUser $line.Alias -Properties city,company,country,department,displayname,emailaddress,givenname,initials,manager,officephone,postalcode,state,streetaddress,surname,title,office,userprincipalname
  if ($user -ne $null)
  {
     $image=$imagepath+$line.Name+".jpg"
     $photo=[byte[]](Get-Content $image -Encoding byte)
     if ($photo -ne $null)
     {
        Set-ADUser $line.Alias -Replace @{thumbnailPhoto=$photo}
     }
     $user.City=$line.City
     $user.Company="Contoso"
     $user.Department=$line.Department
     $user.Office=$line.Office
     
     $user.DisplayName=$line.Name

     $user.GivenName=$line.Fname
     if ($line.MiddleInitial -ne "")
     {
        $user.Initials=$line.MiddleInitial
     }
     
         
     if ($line.Zip -ne "")
     {
        $user.PostalCode=$line.PostalCode
     }
     
     if ($line.State -ne "")
     {
        $user.State=$line.State
     }

     if ($line.CountryCode -ne "")
     {
        $user.Country=$line.CountryCode
     }

     $user.OfficePhone=$line.OfficePhone
     $user.StreetAddress=$line.StreetAddress
     $user.Surname=$line.Lname
     $user.Title=$line.Title  
     
     Set-ADUser -instance $user
     if ($line.ManagerAlias -ne "")
     {
         Set-ADUser -Identity $line.Alias -Manager $line.ManagerAlias
     }
  }
 
 }
 catch {}

}

Start-Sleep -s 3


# Create Public and Private Certificate Requests 

Write-Host "Creating the certificate request for your lab domain's public certificate" -back yellow -for black

$PubCert = New-ExchangeCertificate -FriendlyName "Lab Certificate" -GenerateRequest -SubjectName cn=sip.$LabDomain -DomainName $LabDomain,mbx1.$LabDomain,fs.$LabDomain,mail.$LabDomain,Lyncdiscover.$LabDomain,sip.$LabDomain,webconf.$LabDomain,meet.$LabDomain,dialin.$LabDomain,meetings.$LabDomain,admin.$LabDomain,poola.$LabDomain -PrivateKeyExportable $true

Set-Content -Path "C:\LabFiles\PubCertRequest.txt" -Value $PubCert

$PrivCert = New-ExchangeCertificate -FriendlyName "IM Certificate" -GenerateRequest -SubjectName cn=mail.$env:USERDNSDOMAIN -DomainName mail.$env:USERDNSDOMAIN,$($MBXServer + "." + $env:USERDNSDOMAIN),mail.$LabDomain -PrivateKeyExportable $true

Set-Content -Path "C:\Scripts\PrivCertRequest.req" -Value $PrivCert


# Create external SMTP connector

Write-Host "Creating/Updating the SMTP connectors" -back yellow -for black

New-SendConnector -Name "External Email" -Usage Internet -AddressSpaces "SMTP:*;20" -SourceTransportServers $MBXServer | out-null 


# Update server URLs

Write-Host "Updating Exchange URLs for your lab domain" -back yellow -for black

Get-EcpVirtualDirectory | Set-EcpVirtualDirectory -ExternalURL https://mail.$LabDomain/ecp -WarningAction SilentlyContinue | out-null

Get-WebServicesVirtualDirectory | Set-WebServicesVirtualDirectory -ExternalURL https://mail.$LabDomain/EWS/Exchange.asmx -Force	| out-null 

Get-ActiveSyncVirtualDirectory | Set-ActiveSyncVirtualDirectory -ExternalURL https://mail.$LabDomain/Microsoft-Server-ActiveSync | out-null

Get-OabVirtualDirectory | Set-OabVirtualDirectory -ExternalURL https://mail.$LabDomain/OAB | out-null

Get-OwaVirtualDirectory | Set-OwaVirtualDirectory -ExternalUrl https://mail.$LabDomain/owa | out-null 

Get-PowerShellVirtualDirectory | Set-PowerShellVirtualDirectory -ExternalURL https://mail.$LabDomain/powershell | out-null

Set-OutlookAnywhere -Identity "$MBXServer\rpc (Default Web Site)" -ExternalHostname mail.$LabDomain -ExternalClientsRequireSsl $False -ExternalClientAuthenticationMethod Negotiate  -WarningAction SilentlyContinue | out-null

Get-ClientAccessServer | Set-ClientAccessServer -AutoDiscoverServiceInternalUri https://mail.$LabDomain/Autodiscover/Autodiscover.xml | out-null 

Set-EcpVirtualDirectory "$MBXServer\ECP (Default Web Site)" -InternalUrl ((Get-EcpVirtualDirectory "$MBXServer\ECP (Default Web Site)").ExternalUrl) -WarningAction SilentlyContinue

Set-WebServicesVirtualDirectory "$MBXServer\EWS (Default Web Site)" -InternalUrl ((get-WebServicesVirtualDirectory "$MBXServer\EWS (Default Web Site)").ExternalUrl)

Set-ActiveSyncVirtualDirectory "$MBXServer\Microsoft-Server-ActiveSync (Default Web Site)" -InternalUrl ((Get-ActiveSyncVirtualDirectory "$MBXServer\Microsoft-Server-ActiveSync (Default Web Site)").ExternalUrl)

Set-OabVirtualDirectory "$MBXServer\OAB (Default Web Site)" -InternalUrl ((Get-OabVirtualDirectory "$MBXServer\OAB (Default Web Site)").ExternalUrl)

Set-OwaVirtualDirectory "$MBXServer\OWA (Default Web Site)" -InternalUrl ((Get-OwaVirtualDirectory "$MBXServer\OWA (Default Web Site)").ExternalUrl)

Set-PowerShellVirtualDirectory "$MBXServer\PowerShell (Default Web Site)" -InternalUrl ((Get-PowerShellVirtualDirectory "$MBXServer\PowerShell (Default Web Site)").ExternalUrl)

Set-OutlookAnywhere -Identity "$MBXServer\rpc (Default Web Site)" -InternalHostname mail.$LabDomain -InternalClientsRequireSsl $False -WarningAction SilentlyContinue

#Set KDS Root Key

#Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10) | out-null

# Enable Office Web Apps Server

Set-OrganizationConfig -WACDiscoveryEndpoint https://was1.contoso.local/hosting/discovery  -WarningAction SilentlyContinue | out-null

Set-OWAVirtualDirectory "$MBXServer\OWA (Default Web Site)" -WacViewingOnPublicComputersEnabled:$true -WacViewingOnPrivateComputersEnabled:$true -ForceWacViewingFirstOnPublicComputers $true -ForceWacViewingFirstOnPrivateComputers $true  -WarningAction SilentlyContinue | out-null


# Update SfBTopology tbxml

Write-Host "Creating Skype for Business Server Topology TBXML" -back yellow -for black

#winrm set winrm/config/client '@{TrustedHosts = "EDG1,SRV2,TMG1"}'

$username = "Admin"

$password = ConvertTo-SecureString 'Pa$$w0rd' -asplaintext -force

$cred = New-Object System.Management.Automation.PsCredential($username,$password)

New-CimSession -Name EDG1 -ComputerName EDG1 -Credential $cred -Authentication Negotiate | out-null

$EDG1ExtIP = (Get-NetIPAddress -AddressFamily IPv4 -CimSession (Get-CimSession) | where {$_.IPAddress -ne ("127.0.0.1") -and ($_.IPAddress -ne "192.168.0.15")}).IPAddress

(Get-Content \\SFE1\C$\Scripts\SkypeTopology.tbxml) | Foreach-Object {$_ -replace "contoso.rename","$LabDomain"} | Foreach-Object {$_ -replace "192.168.1.3","$EDG1ExtIP"} | Foreach-Object {$_ -replace "192.168.1.2","$EDG1PubIP"} | Foreach-Object {$_ -replace "SkypeTopology.tbxml","SkypeTopology$Labdomain.tbxml"} | Set-Content \\SFE1\C$\LabFiles\SkypeTopology$Labdomain.tbxml


# Update TMG rules and DNS files

Write-Host "Updating TMG rules and creating your lab domain DNS zone and hosts" -back yellow -for black

New-PSDrive -Persist -Name T -PSProvider FileSystem -Credential $cred -Root \\TMG1\c$\LabFiles | out-null

(Get-Content T:\LabTMGRules.xml) | Foreach-Object {$_ -replace "XXXXX","$cdname"} | Set-Content T:\LabTMGRules-Lab$cdname.xml

(Get-Content T:\LabXXXXX.O365Ready.com.dns) | Foreach-Object {$_ -replace "XXXXX","$cdname"} | Foreach-Object {$_ -replace "192.168.1.1","$IP"} | Foreach-Object {$_ -replace "192.168.1.2","$EDG1PubIP"} | Set-Content T:\$LabDomain.dns

Remove-PSDrive T

# Create DNS zones

$sessionTMG = New-PSSession -ComputerName TMG1 -Credential $cred

Invoke-Command -Session $sessionTMG -ScriptBlock {

$Dnscmd = "Dnscmd /ZoneAdd $args /Primary /file $args.dns"

cmd.exe /c $Dnscmd | Out-Null

Stop-Service DNS

Copy-Item C:\LabFiles\$args.dns C:\Windows\System32\dns\$args.dns -Force

Start-Service DNS

} -args $LabDomain


# Stop Exchange Services

Write-Host "Restarting Exchange Services" -back yellow -for black

	$svcName = "MSExchangeADTopology"

	# Get dependent services
	$depSvcs = Get-Service -Name $svcName -dependentservices | Where-Object {$_.Status -eq "Running"} |Select -Property Name
 
	function StopDepServices {

	# Check to see if dependent services are started
	if ($depSvcs -ne $null) {
	# Stop dependencies
	foreach ($depSvc in $depSvcs)
	{
		Stop-Service $depSvc.Name
		do
		{
			$service = Get-Service -name $depSvc.Name | Select -Property Status
			Start-Sleep -seconds 1
		}
		until ($service.Status -eq "Stopped")
	}
	}
	}


	function RestartServices {
 
	# Restart service
	Restart-Service $svcName -force
	do
	{
	$service = Get-Service -name $svcName | Select -Property Status
	Start-Sleep -seconds 1
	}
	until ($service.Status -eq "Running")
 
 
	$depSvcs = Get-Service -name $svcName -dependentservices |Select -Property Name
 
	# Check for Auto start flag on dependent services and start them even if they were stopped before
	foreach ($depSvc in $depSvcs)
	{
	$startMode = gwmi win32_service -filter "NAME = '$($depSvc.Name)'" | Select -Property StartMode
	if ($startMode.StartMode -eq "Auto") {
		Start-Service $depSvc.Name
		do
		{
			$service = Get-Service -name $depSvc.Name | Select -Property Status
			Start-Sleep -seconds 1
		}
		until ($service.Status -eq "Running")
	}
	}
	}


StopDepServices
Stop-Service MSExchangeIS
Start-Sleep -s 5

RestartServices


# Delete Index

$CopyStatus = Get-MailboxDatabaseCopyStatus

If ($CopyStatus.ConentIndexState -eq "FailedAndSuspended"){

	Stop-Service MSExchangeFastSearch
	Stop-Service HostControllerService

	$IndexFolder = Get-ChildItem -Path "C:\Program Files\Microsoft\Exchange Server\V15\Mailbox\$MDBName" | Where-Object {($_.PSIsContainer) -and ($_.Name -like "*.Single")}
	Remove-Item "C:\Program Files\Microsoft\Exchange Server\V15\Mailbox\$MDBName\$IndexFolder" -Force -Recurse
	
	Start-Service MSExchangeFastSearch
	Start-Service HostControllerService
 
	}

# Complete
""
""
Write-Host "Configuration complete" -back yellow -for black