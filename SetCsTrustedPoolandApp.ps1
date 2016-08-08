# Set CS Trusted Application Pool and Application

	New-CsTrustedApplicationPool -Identity mail.contoso.local -Registrar redpool.contoso.local -Site (Get-CSsite).SiteID -RequiresReplication $False -Force -WarningAction 'SilentlyContinue' | out-null

	New-CsTrustedApplication -ApplicationId OutlookWebAccess -TrustedApplicationPoolFqdn (Get-CsTrustedApplicationPool).PoolFqdn -Port 51 -WarningAction 'SilentlyContinue' | out-null
	
Exit
