# Install Local Configuration Store

	Write-Host "Installing Local Configuration Store" -back yellow -for black
	
	$Path = Get-Location
	$File = "$env:temp\CSConfigData.zip"
	If (Test-Path $File)
		{Remove-Item $File}
	Start-Process Powershell.exe .\LocalConfigStore.ps1 -NoNewWindow -Wait

# Define Mailbox server and Lab domain variable

	$MBXServer = "MBX1"
	
# Install SfB FE

	Write-Host "Enabling Front End Server roles" -back yellow -for black
	
	$Source = "C:\Program Files\Skype for Business Server 2015\Deployment\amd64\Setup"	
	cd "C:\Program Files\Skype for Business Server 2015\Deployment"
	.\Bootstrapper.exe /SourceDirectory:$Source
	cd $Path

# Install certificates and start Windows services

	Write-Host "Requesting and assigning internal and external certificates" -back yellow -for black

	Start-Process Powershell.exe .\SetCsCertificates.ps1 -NoNewWindow -Wait
	
	Start-Process Powershell.exe .\EnableCsTopology.ps1 -NoNewWindow -Wait

	Write-Host "Starting Skype for Business Windows Services" -back yellow -for black

	Start-Process Powershell.exe .\StartCsWindowsService.ps1 -NoNewWindow -Wait

	Write-Host "Exporting the Skype for Business configurtion and copying it to the Edge server" -back yellow -for black

	Export-CsConfiguration -FileName "C:\LabFiles\SfBTopology.zip"

	$username = "Admin"

	$password = ConvertTo-SecureString 'Pa$$w0rd' -asplaintext -force

	$cred = New-Object System.Management.Automation.PsCredential($username,$password)

	New-PSDrive -Name EDG -PSProvider FileSystem -Credential $cred -Root \\edg1\c$\LabFiles | out-null

	Copy-Item C:\LabFiles\SfBTopology.zip EDG:\
	
# Configure Exchange UM and Enable users

	Write-Host "Configuring Exchange Unified Messaging" -back yellow -for black
	
	$LabDomain = ((Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.Subject -like "CN=sip.Lab*"}).Subject).Substring(7,22)
	
	$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionURI http://$MBXServer.contoso.local/powershell

	Import-PSSession $Session -DisableNameChecking -WarningAction 'SilentlyContinue' | out-null

	Get-Service -ComputerName $MBXServer | where-object {($_.Name -like "MSEx*") -and ($_.Name -notlike "MSExchangePop3*") -and ($_.Name -notlike "MSExchangeImap4*") -and ($_.Name -notlike "MSExchangeMonitoring")} | Start-Service

	New-UMDialPlan -Name Redmond -VoIPSecurity Secured -URIType sipname -NumberOfDigitsInExtension 4 -CountryOrRegionCode "1" -AccessTelephoneNumbers '+142555500290' | Out-Null
	
	Get-UMMailboxPolicy | Set-UMMailboxPolicy -LogonFailuresBeforePINReset Unlimited -MaxLogonAttempts Unlimited -MinPINLength 4 -PINLifetime Unlimited -PINHistoryCount 1 -AllowCommonPatterns $true
	
	$UMDialPlan = Get-UmDialPlan

	New-UMAutoAttendant -Name "RedmondAA" -UMDialPlan $UMDialPlan.Name -Status 'Enabled' -SpeechEnabled $True -PilotIdentifierList '+14255550291' | Out-Null
	
	Write-Host "Enabling Users for Unified Messaging" -back yellow -for black

	$UMUsers = Get-Mailbox -OrganizationalUnit $OU -Sortby Name | Where-Object {($_.RecipientType -like "UserMailbox") -and ($_.Name -notlike "Discover*") -and ($_.Name -notlike "ExchangeHealth*") -and ($_.Name -notlike "Admin*") -and ($_.Name -notlike "Conf*") -and ($_.Name -notlike "Guest") -and ($_.Name -notlike "krbtg*") -and ($_.Name -notlike "AD RM*")} 

	$UMP = Get-UMMailboxPolicy

	$i = 2201

	Foreach ($User in $UMUsers)
		{
		 $i++;Enable-UMMailbox -Identity $User.Alias -UMMailboxPolicy $UMP.Name -Pin 1234 -PINExpired $False -SIPResourceIdentifier $User.PrimarySmtpAddress -Extensions $i -NotifyEmail Administrator@$LabDomain | Out-Null
		}

	Get-UMService | Set-UmService -UMStartupMode Dual -DialPlans $UMDialPlan.Name -WarningAction 'SilentlyContinue'

	Set-UMCallRouterSettings -UMStartUpMode Dual -Server $MBXServer -WarningAction 'SilentlyContinue'

	$Cert = Get-ExchangeCertificate | where {$_.Subject -like "CN=sip.Lab*"}

	Enable-ExchangeCertificate -Server $MBXServer -Thumbprint $Cert.thumbprint -Services UM,UmCallRouter -Force -WarningAction 'SilentlyContinue'

	Get-Service -Computer $MBXServer | where {$_.Name -like "MSExchangeU*"} | Restart-Service -WarningAction 'SilentlyContinue'


# Configure SfB and IM integration

	Write-Host "Configuring Skype for Business and IM Integration" -back yellow -for black

	Set-CsAccessEdgeConfiguration -AllowOutsideUsers $True

	Set-CsOAuthConfiguration -Identity global -ExchangeAutodiscoverUrl "https://mail.$LabDomain/autodiscover/autodiscover.svc"
	
	Start-Process Powershell.exe .\SetCsTrustedPoolandApp.ps1 -NoNewWindow -Wait

	Set-CsUserServicesPolicy -Identity Global -UcsAllowed:$True

	Set-CsArchivingConfiguration -EnableExchangeArchiving $true
 
	New-CsPartnerApplication -Identity Exchange -ApplicationTrustLevel Full -MetadataUrl "https://mail.$LabDomain/autodiscover/metadata/json/1" | out-null
	

# Create Voice Routing Settings

	Write-Host "Configuring Voice Routing and Normalization rules" -back yellow -for black

	New-CsVoiceRoute -Identity "US-Redmond Local Route" -NumberPatter "^\*" -PstnUsage @{add = 'Local'} -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoiceRoute -Identity "US-National Route" -NumberPatter "^\*" -PstnUsage @{add = 'Local'} -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoiceRoute -Identity "US-International Local Route" -NumberPatter "^\*" -PstnUsage @{add = 'Long Distance'} -WarningAction 'SilentlyContinue' | Out-Null

	$PSTNUsage = Get-CsPstnUsage

	New-CsVoicePolicy -Identity site:contoso -PstnUsage @{add = $PSTNUsage.Usage} -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoicePolicy -Identity "US-Redmond Internaltional Policy" -PstnUsage @{add = 'Long Distance'} -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoicePolicy -Identity "US-Redmond National Policy" -PstnUsage @{add = 'Local'} -WarningAction 'SilentlyContinue' | Out-Null

	New-CsDialPlan -Identity site:contoso -SimpleName contoso -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoiceNormalizationRule -Identity "site:contoso/Redmond 4 Digit Dialing" -Pattern "^2(\d{3})$" -Translation "+14255550$1" -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoiceNormalizationRule -Identity "site:contoso/Redmond 7 Digit Dialing" -Pattern "^(\d{7})$" -Translation "+1425$1" -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoiceNormalizationRule -Identity "site:contoso/US 10 Digit Dialing" -Pattern "^(\d{10})$" -Translation "+1$1" -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoiceNormalizationRule -Identity "site:contoso/US 11 Digit Dialing" -Pattern "^(\d{11})$" -Translation "+1" -WarningAction 'SilentlyContinue' | Out-Null

	New-CsVoiceNormalizationRule -Identity "site:contoso/International Dialing" -Pattern "^011(\d*})$" -Translation "+1" -WarningAction 'SilentlyContinue' | Out-Null

	Remove-CsVoiceNormalizationRule -Identity "site:contoso/Keep All" -WarningAction 'SilentlyContinue' | Out-Null

# Enable federation and Public IM

	Write-Host "Enabling Federation and Public IM" -back yellow -for black

	Set-CsAccessEdgeConfiguration -AllowFederatedUsers $True -EnablePartnerDiscovery $True -UseDnsSrvRouting

	Set-CsExternalAccessPolicy -EnableFederationAccess $True -EnablePublicCloudAccess $True -EnableOutsideAccess $True
	
	Set-CsPushNotificationConfiguration -EnableApplePushNotificationService $True -EnableMicrosoftPushNotificationService $True

	Start-Process Powershell.exe .\EnableCsTopology.ps1 -NoNewWindow -Wait

	Start-Sleep -s 3

# Enable CS Users

	Write-Host "Enabling Skype for Business users" -back yellow -for black

	Foreach ($User in $UMUsers)
		{
		 $UPN = $User.UserPrincipalName
		 Enable-CsUser -Identity $UPN -SipAddress "sip:$UPN" -RegistrarPool "redpool.contoso.local" -WarningAction 'SilentlyContinue'
		}

	Set-Location C:\Scripts


	Write-Host "Complete" -back yellow -for black
