# Install Local Configuration Store
	
	$Source = "C:\Program Files\Skype for Business Server 2015\Deployment\amd64"
	cd "C:\Program Files\Skype for Business Server 2015\Deployment"
	.\Bootstrapper.exe /SourceDirectory:$Source /BootstrapLocalMgmt
	Export-CSConfiguration -FileName "$env:Temp\CSConfigData.zip" 
	Import-CSConfiguration -LocalStore -FileName "$env:Temp\CSConfigData.zip" 
	Enable-CsReplica
	Exit	

