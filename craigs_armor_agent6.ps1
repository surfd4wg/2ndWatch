param (
    [ValidatePattern("^([2346789BCDFGHJKMPQRTVWXY{5}]-?){5}")]
    [string]
    $license,
    [switch]
    $full = $false,
    [string]
    $region,
    [string]
    $downloadBase = "https://agent.armor.com"
)
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host("The Armor Agent installation must be run with Administrative privileges.");
    exit;
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

$installationDirectory = "C:\.armor\opt";
$logDirectory = "C:\.armor\log";
$tempLog = "$env:TEMP\armor-install.log";
$global:reg = $false;

function LogTemp ([string] $message) {
    $message | Tee-Object -append -file $tempLog;
}

function Download_Fallback ([string]$source, [string]$destination, [string]$userAgent) {
    $webClient = (New-Object System.Net.WebClient);
    $webClient.Headers.Add("User-Agent", $userAgent);
    $webClient.DownloadFile( $source, $destination);
}

function Download ([string]$source, [string]$destination) {
    try {
    Write-Host "Downloading $source to $destination";
    $userAgent = "Armor Powershell Bootstrap/1.0";

    if (Test-Path -PathType Leaf -Path $destination) {
        Remove-Item -Path $destination -Force;
    }

    if (Get-Command Invoke-WebRequest -errorAction SilentlyContinue) {
        Invoke-WebRequest $source -OutFile $destination -UserAgent $userAgent;
    }
    else {
        Download_Fallback $source $destination $userAgent;
    }
    } catch {
        Write-Host "Unable to download ${source}"
        Write-Host $_
        exit(1)
    }
}

function DownloadAgent
(
    [string] $agentSourceUrl,
    [string] $agentDestFilePath,
    [string] $sha1SourceUrl,
    [string] $sha1DestFilePath
) {
    Download $agentSourceUrl  $agentDestFilePath;
    Download  $sha1SourceUrl  $sha1DestFilePath;
}

Function Get-ShaHash([String] $filePath) {
    $fileStream = [System.IO.File]::OpenRead($filePath);
    $bytes = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash($fileStream);
    $fileStream.Dispose();

    return (($bytes | ForEach-Object { $_.ToString("X2") }) -join "");
}

function ValidateChecksum
(
    [string] $agentFilePath,
    [string] $sha1FilePath
) {
    $fileHash = Get-ShaHash $agentFilePath;
    $expectedHash = (Get-Content -Raw $sha1FilePath);
    if ($expectedHash) {
        $expectedHash = $expectedHash.Trim("`n").Trim().ToUpper();
    }

    if ($fileHash -ne $expectedHash) {
        LogTemp "Checksum does not match.  Exiting. ";
        ConcatLog $tempLog;
        exit;
    }
}

function ExtractAgent
(
    [string] $filePath,
    [string] $destFolderPath

) {
    try {

        if (Test-Path c:\.armor\opt\armor.exe -PathType Leaf)
        {
           C:\.armor\opt\armor.exe stop
        }

        Unzip -zipfile $filePath -outdir $destFolderPath

    } catch {
        Write-Host "Unable to extract Armor Agent"
        Write-Host $_
        Exit(1)
    }
}

##Unzip and overwrites if exists
function Unzip($zipfile, $outdir)
{
   Add-Type -AssemblyName System.IO.Compression.FileSystem
   $archive = [System.IO.Compression.ZipFile]::OpenRead($zipfile)
   foreach ($entry in $archive.Entries)
   {
       $entryTargetFilePath = [System.IO.Path]::Combine($outdir, $entry.FullName)

       if(!$entryTargetFilePath.EndsWith("\")){
         [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryTargetFilePath, $true);
       }
   }
   $archive.Dispose()
}

function SetupArmorPath ([string]$newPath) {
    New-Item -ItemType Directory -Path $newPath -Force -ErrorAction Inquire | Out-Null;
}

function ExecuteProcess(
    [string]
    $prefix,
    [string]
    $filePath,
    [string]
    $arguments
) {

    try {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo;
    $pinfo.FileName = $filePath;
    $pinfo.RedirectStandardError = $false;
    $pinfo.RedirectStandardOutput = $false;
    $pinfo.UseShellExecute = $false;
    $pinfo.Arguments = $arguments;
    $p = New-Object System.Diagnostics.Process;
    $p.StartInfo = $pinfo;

    $stdOutName = "${prefix}Out";
    $stdErrName = "${prefix}Error";

    $action = { Write-Host $Event.SourceEventArgs.Data }
    Register-ObjectEvent -InputObject $p `
        -EventName "OutputDataReceived" `
        -Action $action `
        -SourceIdentifier $stdOutName | Out-Null;
    Register-ObjectEvent -InputObject $p `
        -EventName "ErrorDataReceived" `
        -Action $action `
        -SourceIdentifier $stdErrName | Out-Null;

    $p.Start() | Out-Null;

    $p.WaitForExit();

    Unregister-Event -SourceIdentifier $stdOutName;
    Unregister-Event -SourceIdentifier $stdErrName;

    return $p.ExitCode;
    } catch {
        Write-Host "Exception attempting to execute ${prefix}"
        Write-Host $_
        return 1;
    }
}

function AgentServiceInstall ([string]$armorAgentPath) {
    Write-Host "Registering agent";
    try {
    $licenseUpper = $license.ToUpper();
    $arguments = "register --license `"$licenseUpper`" --region $region";
    ExecuteProcess "AgentServiceInstall" $armorAgentPath $arguments;
    if (Test-Path c:\.armor\etc\core.data -PathType Leaf) {
      $global:reg = $true;
    }
    } catch {
        Write-Host "Failed to register the armor agent"
        Write-Host "Please remove the c:\.armor\ directory and retry"
        Remove-Item -Path $PSCommandPath
        Write-Host $_
        exit(0)
    }
}

function ScheduleSupervisor ([string]$armorAgentPath) {
    Write-Host "Scheduling agent supervisor";
    # added 3 mins delay so that supervisor cron job for get-tasks,
    # and agent get-tasks cron job will not be created at same time.
    $start = "00:{0}" -f [datetime]::Now.AddMinutes((3 + 15)).Minute.ToString("00");
    $interval = 15;
    $schedule = "MINUTE";
    $user = "NT AUTHORITY\SYSTEM";
    $taskName = "\Armor Defense\SUPERVISOR_TASKS";
    $taskRun = "$armorAgentPath get-tasks";
    $arguments = "/create /f /sc `"${schedule}`" /tn `"${taskName}`" /tr `"${taskRun}`" /np /st `"${start}`" /mo `"$interval`" /k /ru `"${user}`"";

    ExecuteProcess "ScheduleSupervisor" "schtasks.exe" $arguments | Out-Null
}

function InstallAgent() {
    Uncomment-Hosts
    $agentSourceUrl = "$downloadBase/latest/armor-windows.zip";
    $agentTempFilePath = Join-Path $env:TEMP "armor-windows.zip";
    $sha1SourceUrl = "$downloadBase/latest/armor-windows.zip.sha1";
    $sha1TempFilePath = Join-Path $env:TEMP "armor-windows.zip.sha1";
    SetupArmorPath $installationDirectory;
    DownloadAgent $agentSourceUrl $agentTempFilePath $sha1SourceUrl $sha1TempFilePath;
    ValidateChecksum $agentTempFilePath $sha1TempFilePath;
    ExtractAgent $agentTempFilePath $installationDirectory;
    AgentServiceInstall (Join-Path $installationDirectory "armor.exe");
    if ($global:reg) {
        ScheduleSupervisor (Join-Path $installationDirectory "armor-supervisor.exe")
    #    InstallSubAgents
    }
    Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum 90)
    # Install Trend SubAgent
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Installing the trend agent"
        $exitCode = Invoke-ArmorCmd -ArgumentList "trend install"

        if( $exitCode -ne 0 )
        {
            throw "Trend install failed with exit code: $($exitCode)"
        }
    }
    # Install Qualys Vulnerability Scanning SubAgent
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Installing the Qualys Vuln Scanning agent"
        $exitCode = Invoke-ArmorCmd -ArgumentList "vuln install"
    
        if( $exitCode -ne 0 )
        {
            throw "Qualys vulnerability install failed with exit code: $($exitCode)"
         }
    }
    # Install Logging SubAgents
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Installing logging agents"
        $exitCode = Invoke-ArmorCmd -ArgumentList "logging install"
    
        if( $exitCode -ne 0 )
        {
            throw "Logging agents install failed with exit code: $($exitCode)"
         }
    }
    # Install Trend FIM module and applying recommendations
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Installing Trend FIM module and auto apply recommendations"
        $exitCode = Invoke-ArmorCmd -ArgumentList "fim on auto-apply-recommendations=on async=true"
    
        if( $exitCode -ne 0 )
        {
            throw "FIM agents install failed with exit code: $($exitCode)"
         }
    }
    # Install Trend IPS module and applying recommendations
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Installing Trend IPS module and auto apply recommendations"
        $exitCode = Invoke-ArmorCmd -ArgumentList "ips detect auto-apply-recommendations=on async=true"
    
        if( $exitCode -ne 0 )
        {
            throw "IPS module install failed with exit code: $($exitCode)"
         }
    }
    # Install Trend AV module 
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Installing Trend AV module"
        $exitCode = Invoke-ArmorCmd -ArgumentList "av on async=true"
    
        if( $exitCode -ne 0 )
        {
            throw "AV module install failed with exit code: $($exitCode)"
         }
    }
    # Heartbeat Trend 
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Issuing Trend Heartbeat"
        $exitCode = Invoke-ArmorCmd -ArgumentList "trend heartbeat"
    
        if( $exitCode -ne 0 )
        {
            throw "Trend Heartbeat failed with exit code: $($exitCode)"
         }
    }
    # Setting Trend recommendation scan
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Setting Trend Recommendation Scan"
        $exitCode = Invoke-ArmorCmd -ArgumentList "trend recommendation-scan async=true"
    
        if( $exitCode -ne 0 )
        {
            throw "Trend recommendation scan failed with exit code: $($exitCode)"
         }
    }
    # Setting Trend ongoing recommendation scan
    if ($full -and ($global:reg -eq $true)) {
        Write-Verbose "Setting Trend Ongoing Recommendation Scan"
        $exitCode = Invoke-ArmorCmd -ArgumentList "trend ongoing-recommendation-scan on async=true"
    
        if( $exitCode -ne 0 )
        {
            throw "Trend ongoing recommendation scan failed with exit code: $($exitCode)"
         }
    }
    # Run a trend status
    #if ($full -and ($global:reg -eq $true)) {
    #    Write-Verbose "Running trend status"
    #    $exitCode = Invoke-ArmorCmd -ArgumentList "trend status"
    #
    #    if( $exitCode -ne 0 )
    #    {
    #        throw "Trend status failed with exit code: $($exitCode)"
    #     }
    #}    
}

# New Item
function Invoke-ArmorCmd
{
    [CmdletBinding()]
    param(
        [Parameter(
            Position = 0,
            Mandatory,
            HelpMessage = "Armor cli command arguments"
        )]
        [string]
        $ArgumentList
    )

    $armorExe = "C:\.armor\opt\armor.exe"
    $cmdArgs = @{
        FilePath     = $armorExe
        ArgumentList = $ArgumentList
    }

    return Invoke-Process @cmdArgs
}

function Uncomment-Hosts
{
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $hosts = get-content $hostsPath
    $hosts = $hosts | Foreach {if ($_ -match '^\s*#\s*(.*?\d{1,3}.*?localhost.*)')
                               {$matches[1]} else {$_}}
    $hosts | Out-File $hostsPath -enc ascii
}

function Invoke-Process
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(
            Position = 0,
            Mandatory,
            HelpMessage = "Path to process to invoke"
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $FilePath,

        [Parameter(
            Position = 1,
            Mandatory,
            HelpMessage = "Argumentlist for the invoked process"
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $ArgumentList
    )

    $ErrorActionPreference = 'Stop'

    try
    {
        $stdOutTempFile = "$env:TEMP\$([guid]::NewGuid())"
        $stdErrTempFile = "$env:TEMP\$([guid]::NewGuid())"

        $startProcessParams = @{
            FilePath               = $FilePath
            ArgumentList           = $ArgumentList
            RedirectStandardError  = $stdErrTempFile
            RedirectStandardOutput = $stdOutTempFile
            Wait                   = $true
            PassThru               = $true
            NoNewWindow            = $true
        }
        if ($PSCmdlet.ShouldProcess("Process [$($FilePath)]", "Run with args: [$($ArgumentList)]"))
        {
            $cmd = Start-Process @startProcessParams
            $cmdOutput = Get-Content -Path $stdOutTempFile -Raw
            $cmdError = Get-Content -Path $stdErrTempFile -Raw
            Write-Host "Process completed with exit code: $($cmd.ExitCode)"
            if ($cmd.ExitCode -ne 0)
            {
                if ($cmdError)
                {
                    throw $cmdError.Trim()
                }
                if ($cmdOutput)
                {
                    throw $cmdOutput.Trim()
                }
            }
            else
            {
                if ([string]::IsNullOrEmpty($cmdOutput) -eq $false)
                {
                    Write-Host $cmdOutput
                }
            }

            return $cmd.ExitCode
        }
    }
    catch
    {
        $PSCmdlet.ThrowTerminatingError($_)
    }
    finally
    {
        Remove-Item -Path $stdOutTempFile, $stdErrTempFile -Force -ErrorAction Ignore
    }
}

function InstallSubAgents() {


    if ($full -and ($global:reg -eq $true))
    {

        TrendInstall(Join-Path $installationDirectory "armor.exe");
        FIMInstall(Join-Path $installationDirectory "armor.exe");
        IDSInstall(Join-Path $installationDirectory "armor.exe");
        AVInstall(Join-Path $installationDirectory "armor.exe");
        $dsaControl = Join-Path $Env:ProgramFiles "Trend Micro\Deep Security Agent\dsa_control";
        & $dsaControl -m;
        sleep 20;
        VulnInstall(Join-Path $installationDirectory "armor.exe");
        LoggingInstall(Join-Path $installationDirectory "armor.exe");
        TrendRecommendationScanInstall(Join-Path $installationDirectory "armor.exe");
        TrendRecommendationScanOngoingInstall(Join-Path $installationDirectory "armor.exe");
    }
}

function ConcatLog($FileName) {
    if (-not (Test-Path -PathType Container $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory | Out-Null;
    }
    $date = Get-Date -UFormat '+%Y-%m-%dT%H:%M:%SZ';
    $out = (Get-Content $FileName) -Join " ";
    $logEntry = "time=`"$date`" level=info msg=`"$out`"";
    $logEntry | Out-File -Force (Join-Path $logDirectory "armor.log") -Append -Encoding ascii
}

function TrendInstall ([string]$armorAgentPath) {
    Write-Host "Installing trend";
    $arguments = "trend install";
    ExecuteProcess "TrendInstall" $armorAgentPath $arguments | Out-Null
}

function TrendRecommendationScanInstall ([string]$armorAgentPath) {
    Write-Host "Installing trend";
    $arguments = "trend recommendation-scan";
    ExecuteProcess "TrendInstall" $armorAgentPath $arguments | Out-Null
}

function TrendRecommendationScanOngoingInstall ([string]$armorAgentPath) {
    Write-Host "Installing trend";
    $arguments = "trend ongoing-recommendation-scan on";
    ExecuteProcess "TrendInstall" $armorAgentPath $arguments | Out-Null
}

function AVInstall ([string]$armorAgentPath) {
    Write-Host "Installing av";
    $arguments = "av on";
    ExecuteProcess "AVInstall" $armorAgentPath $arguments | Out-Null
}

function FIMInstall ([string]$armorAgentPath) {
    Write-Host "Installing fim";
    $arguments = "fim on auto-apply-recommendations=on";
    ExecuteProcess "FIMInstall" $armorAgentPath $arguments | Out-Null
}

function IDSInstall ([string]$armorAgentPath) {
    Write-Host "Installing ids";
    $arguments = "ips detect auto-apply-recommendations=on";
    ExecuteProcess "IDSInstall" $armorAgentPath $arguments | Out-Null
}

function VulnInstall ([string]$armorAgentPath) {
    Write-Host "Installing vuln";
    $arguments = "vuln install";
    ExecuteProcess "VulnInstall" $armorAgentPath $arguments | Out-Null
}

function LoggingInstall ([string]$armorAgentPath) {
    Write-Host "Installing logging";
    $arguments = "logging install";
    ExecuteProcess "LoggingInstall" $armorAgentPath $arguments | Out-Null
}



## Main
New-Item $tempLog -Force -ErrorAction Ignore -ItemType file | Out-Null;

if (!$license) {
  Write-Host "License not provided. Will not install Armor agent"
  exit(1)
}

if (!$region) {
  Write-Host "Region not provided. Will not install Armor agent"
  exit(1)
}
ConcatLog $tempLog;
InstallAgent

Remove-Item -Path $env:TEMP\armor-windows.zip -Force
Remove-Item -Path $env:TEMP\armor-windows.zip.sha1 -Force
Remove-Item -Path $PSCommandPath
