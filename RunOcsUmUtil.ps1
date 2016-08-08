
	Write-Host "Running OcsUmUtil for your lab domain" -back yellow -for black

	Set-Location "C:\Program Files\Common Files\Skype for Business Server 2015\Support"
	
	$Labdomain = (Get-CsSipDomain | where {$_.Identity -like "*O365Ready.com"}).Name

	.\OcsUmUtil.exe /domain:$Labdomain

	.\OcsUmUtil.exe /domain:$Labdomain

	Set-Location "C:\Scripts"
	
	Start-Process Powershell.exe .\StopCsWindowsService.ps1 -NoNewWindow -Wait

	Start-Process Powershell.exe .\StartCsWindowsService.ps1 -NoNewWindow -Wait

	Write-Host "Complete" -back yellow -for black

