# Check and to see if the following Armor related Windows services are installed
[Array] $Services = 'Amazon SSM Agent','Armor Core','armor-filebeat','armor-winlogbeat','Qualys Cloud Agent','Trend Micro Deep Security Agent','Trend Micro Deep Security Monitor','Trend Micro Deep Security Notifier','Trend Micro Solution Platform','sshd','Remote Desktop Services';

# loop through each service, if its not running, start it
foreach($ServiceName in $Services)
{
	$Service = $ServiceName
    	$arrService = Get-Service -Name $ServiceName
	if ($Service -eq- $null) {
		Write-Host $ServiceName is NOT Installed
	} else {
		Write-Host $ServiceName is Installed
	}
}
