# Install certificates and start Windows services

	$Path = Get-Location
	
	$DC = Get-ADDomainController
	$DCName = $DC.Name
	cd Cert:\LocalMachine\Root
	$CASubject = Get-ChildItem | Where {$_.Subject -like "CN=contoso*"}
	$CACN = $CASubject.Subject.Substring(0,$CASubject.Subject.IndexOf(","))
	$CAName = $CACN.Substring(3)
	cd $Path

	$CAPath = $DC.HostName + "\" + $CAName

	Import-CsCertificate -Path "\\$DCName\c$\Labfiles\LabCert.pfx" -PrivateKeyExportable $True -Password 'Pa$$w0rd'

	$DefaultCert = (Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.FriendlyName -eq "Lab Certificate"}).Thumbprint

	Set-CsCertificate -Type WebServicesExternal -Thumbprint $DefaultCert -WarningAction SilentlyContinue

	$LabDomain = ((Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.Subject -like "CN=sip.Lab*"}).Subject).Substring(7,22)

	Request-CSCertificate -New -Type Default -CA $CAPath -Country US -State "Washington" -City "Redmond" -FriendlyName "Internal Default Lab Certificate" -KeySize 2048 -PrivateKeyExportable $true -Organization "contoso" -OU "IT" -DomainName "lsfe1.contoso.local,redpool.contoso.local,int-meetings.contoso.local,meetings.contoso.local,meet.$LabDomain,redpool.$LabDomain,dialin.$LabDomain,admin.$LabDomain,meetings.$LabDomain" -AllSipDomain -erroraction 'Silentlycontinue'

	$DefaultIntCert = (Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.FriendlyName -eq "Internal Default Lab Certificate"}).Thumbprint
	
	If ($DefaultIntCert -ne $null)
		{Set-CsCertificate -Type Default -Thumbprint $DefaultIntCert -WarningAction SilentlyContinue}
	Elseif ($DefaultIntCert -eq $null)
		{Write-Host "Internal Default Lab Certificate not found. Retrying request..."
		Get-Service -ComputerName $DC.Name -Name CertSvc | Restart-Service
		Start-Sleep -Seconds 20
		Request-CsCertificate -New -Type Default -CA $CAPath -Country US -State "Washington" -City "Redmond" -FriendlyName "Internal Default Lab Certificate" -KeySize 2048 -PrivateKeyExportable $true -Organization "contoso" -OU "IT" -DomainName "lsfe1.contoso.local,redpool.contoso.local,int-meetings.contoso.local,meetings.contoso.local,meet.$LabDomain,redpool.$LabDomain,dialin.$LabDomain,admin.$LabDomain,meetings.$LabDomain" -AllSipDomain
		$DefaultIntCert = (Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.FriendlyName -eq "Internal Default Lab Certificate"}).Thumbprint
	    If ($DefaultIntCert -ne $null)
		{Set-CsCertificate -Type Default -Thumbprint $DefaultIntCert -WarningAction SilentlyContinue}
	    Elseif ($DefaultLsCert -eq $null)
		{Write-Host "Internal Default Lab Certificate not found. Please verify AD Certificate Services are working properly."}}
	
	Request-CSCertificate -New -Type WebServicesInternal -CA $CAPath -Country US -State "Washington" -City "Redmond" -FriendlyName "Internal Web Services Lab Certificate" -KeySize 2048 -PrivateKeyExportable $true -Organization "contoso" -OU "IT" -DomainName "int-meetings.contoso.local,lsfe1.contoso.local,redpool.contoso.local,meetings.contoso.local,meet.$LabDomain,redpool.$LabDomain,dialin.$LabDomain,admin.$LabDomain,meetings.$LabDomain" -AllSipDomain -erroraction 'Silentlycontinue'

	$DefaultWebSvcCert = (Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.FriendlyName -eq "Internal Web Services Lab Certificate"}).Thumbprint
	
	If ($DefaultWebSvcCert  -ne $null)
		{Set-CsCertificate -Type WebServicesInternal -Thumbprint $DefaultWebSvcCert -WarningAction SilentlyContinue}
	Elseif ($DefaultWebSvcCert -eq $null)
		{Write-Host "Internal Web Services Lab Certificate not found. Retrying request..."
		Get-Service -ComputerName $DC.Name -Name CertSvc | Restart-Service
		Start-Sleep -Seconds 20
		Request-CsCertificate -New -Type WebServicesInternal -CA $CAPath -Country US -State "Washington" -City "Redmond" -FriendlyName "Internal Web Services Lab Certificate" -KeySize 2048 -PrivateKeyExportable $true -Organization "contoso" -OU "IT" -DomainName "int-meetings.contoso.local,lsfe1.contoso.local,redpool.contoso.local,meetings.contoso.local,meet.$LabDomain,redpool.$LabDomain,dialin.$LabDomain,admin.$LabDomain,meetings.$LabDomain" -AllSipDomain
		$DefaultWebSvcCert = (Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.FriendlyName -eq "Internal Web Services Lab Certificate"}).Thumbprint
	    If ($DefaultWebSvcCert -ne $null)
		{Set-CsCertificate -Type WebServicesInternal -Thumbprint $DefaultWebSvcCert -WarningAction SilentlyContinue}
	    Elseif ($DefaultWebSvcCert -eq $null)
		{Write-Host "Internal Web Services Lab Certificate not found. Please verify AD Certificate Services are working properly."}}
	
	Request-CSCertificate -New -Type Default -CA $CAPath -Country US -State "Washington" -City "Redmond" -FriendlyName "OAuthTokenIssuer Certificate" -KeySize 2048 -PrivateKeyExportable $true -Organization "contoso" -OU "IT" -erroraction 'Silentlycontinue'

	$OAuthCert = (Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.FriendlyName -eq "OAuthTokenIssuer Certificate"}).Thumbprint

	If ($OAuthCert -ne $null)
		{Set-CsCertificate -Type OAuthTokenIssuer -Thumbprint $OAuthCert -WarningAction SilentlyContinue}
	Elseif ($OAuthCert -eq $null)
		{Write-Host "OAuth certificate not found. Retrying request..."
		Get-Service -ComputerName $DC.Name -Name CertSvc | Restart-Service
		Start-Sleep -Seconds 20
		Request-CSCertificate -New -Type Default -CA $CAPath -Country US -State "Washington" -City "Redmond" -FriendlyName "OAuthTokenIssuer Certificate" -KeySize 2048 -PrivateKeyExportable $true -Organization "Contoso" -OU "IT" -AllSipDomain
		$OAuthCert = (Get-ChildItem -Path cert:\LocalMachine\My | Where {$_.FriendlyName -eq "OAuthTokenIssuer Certificate"}).Thumbprint
	    If ($OAuthCert -ne $null)
		{Set-CsCertificate -Type OAuthTokenIssuer -Thumbprint $OAuthCert -WarningAction SilentlyContinue}
	    Elseif ($OAuthCert -eq $null)
		{Write-Host "OAth Certificate not found. Please verify AD Certificate Services are working properly."}}


Exit