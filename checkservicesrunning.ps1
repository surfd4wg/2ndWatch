# check and start the following Armor related Windows services in the specified order:
[Array] $Services = 'Amazon SSM Agent','Armor Core','armor-filebeat','armor-winlogbeat','Qualys Cloud Agent','Trend Micro Deep Security Agent','Trend Micro Deep Security Monitor','Trend Micro Deep Security Notifier','Trend Micro Solution Platform','sshd','Remote Desktop Services';

# loop through each service, if its not running, start it
foreach($ServiceName in $Services)
{
	$Service = $ServiceName
    	$arrService = Get-Service -Name $ServiceName
    	Write-Host $ServiceName is $arrService.Status
	If ((Get-Service $Service).Status -ne 'Running') {
	   do {
 	      Start-Service $Service -ErrorAction SilentlyContinue
	       Start-Sleep 10
	   } until ((Get-Service $Service).Status -eq 'Running')
	Write-Host $ServiceName is (Get-Service $Service).Status Now	
	} 
}
