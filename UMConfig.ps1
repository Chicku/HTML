# Run ExchUCUtil

$ErrorActionPreference = "SilentlyContinue"
$CheckPS = Get-Command Get-Mailbox
If ($CheckPS.Name -ne "Get-Mailbox")
	{Write-Host "This script must be run using the Exchange Management Shell. Please close this PowerShell session, open the Exchange Management Shell, and then run the configuration script again." -back red -for black
	 $ErrorActionPreference = "Continue"
	 exit}
	
$ErrorActionPreference = "Continue"

$Location = Get-Location

Write-Host "Running ExchUCUtil" -back yellow -for black

cd $exscripts

.\ExchUCUtil.ps1

.\ExchUCUtil.ps1

# Run OAuth config

Write-Host "Configure OAuth with Skype for Business Server" -back yellow -for black

$LabDomain = (Get-AcceptedDomain | where {$_.DomainName -like "Lab*"}).DomainName.Domain

.\Configure-EnterprisePartnerApplication.ps1 -AuthMetadataUrl "https://redpool.$LabDomain/metadata/json/1" -ApplicationType "Lync"

iisreset

$ErrorActionPreference = "Continue"
$ErrorActionPreference = "Continue"

Set-Location C:\Scripts

Write-Host "Complete" -back yellow -for black
