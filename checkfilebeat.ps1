#Get-Service armor-filebeat | Where-Object {$_.Status -eq "Running"}

$servicename = "filebeat"
#if (Get-Service $servicename -ErrorAction 'SilentlyContinue')
if (Get-Service armor-filebeat | Where-Object {$_.Status -eq "Running"})
{
	Write-Host "$servicename is running on $server. "
}
else
{
	Write-Host "No service $servicename is NOT running on $server. "
}


