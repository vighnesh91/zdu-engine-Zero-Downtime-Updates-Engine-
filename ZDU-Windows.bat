@echo off
setlocal EnableExtensions DisableDelayedExpansion
REM ZDU-Windows.bat - single-file Windows launcher. The PowerShell engine is embedded below.
REM The engine runs in memory; no temporary PS1 payload file is created.
REM Apply is the default; -Plan selects a non-mutating plan. Apply/Cluster require an elevated BAT window.
set "ZDU_LAUNCH_DIRECTORY=%~dp0"
set "ZDU_SELF=%~f0"
set "ZDU_ARGS=%*"

REM -Plan and -Test are intentionally non-elevated. Default Apply and Cluster request UAC automatically.
set "ZDU_IS_PLAN="
if /I "%~1"=="-Plan" set "ZDU_IS_PLAN=1"
if /I "%~1"=="-Test" set "ZDU_IS_PLAN=1"
if /I "%~1"=="-PinReport" set "ZDU_IS_PLAN=1"
if not defined ZDU_IS_PLAN (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$id=[Security.Principal.WindowsIdentity]::GetCurrent();$pr=New-Object Security.Principal.WindowsPrincipal($id);if(-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){try{$cmd='"'+$env:ZDU_SELF+'"';if(-not [string]::IsNullOrWhiteSpace($env:ZDU_ARGS)){$cmd+=' '+$env:ZDU_ARGS};$arg='/d /s /c "'+$cmd+'"';$p=Start-Process -FilePath $env:ComSpec -Verb RunAs -ArgumentList $arg -Wait -PassThru;exit 200}catch{Write-Host ('[ZDU] Administrator approval was cancelled or failed: '+$_.Exception.Message);exit 201}}"
  if errorlevel 201 exit /b 1
  if errorlevel 200 exit /b 0
  if errorlevel 1 exit /b 1
)

REM Run the embedded PowerShell engine directly from this BAT; no .PS1 file is created.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$s=[System.IO.File]::ReadAllText($env:ZDU_SELF);$m=':__ZDU_POWERSHELL_PAYLOAD__';$i=$s.LastIndexOf($m);if($i -lt 0){throw 'Embedded ZDU payload marker not found.'};$p=$s.Substring($i+$m.Length).TrimStart([char]13,[char]10);$sb=[scriptblock]::Create($p); & $sb @args" %*
set "ZDU_EXIT=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %ZDU_EXIT%

:__ZDU_POWERSHELL_PAYLOAD__

#requires -Version 5.1
<#
 ZDU-Windows BAT-only edition - Zero-Downtime Update Engine (Windows control plane + local worker)
 IMPORTANT ENGINEERING BOUNDARY
 * This script ENFORCES no automatic restart; it cannot make vendor installers, Windows servicing,
   System Restore, firmware, or a singleton service "zero downtime". A Windows restore point is
   not an online rollback mechanism and restoring it needs a reboot. On an unhealthy result this
   worker drains/quarantines the node and executes only an explicitly-approved rollback hook.
 * Apply mode is the default; use -Plan for a non-mutating plan. In production, use a signed configuration file
   owned by Administrators, a tested proxy/DB adapter, and a non-critical named -CanaryHost.
 * Cluster remoting requires WinRM/PowerShell Remoting preconfigured by the platform team.
#>
[CmdletBinding()]
param(
    [ValidateSet('Local','Cluster')][string]$Mode = 'Local',
    [string[]]$ComputerName = @(),
    [string]$HostFile,
    [string]$Cidr,
    [string]$CanaryHost,
    [ValidateRange(1,64)][int]$BatchSize = 2,
    [ValidateRange(60,3600)][int]$CanaryObservationSeconds = 300,
    [string]$ConfigPath = '',
    [switch]$Apply,
    [switch]$Plan,
    [switch]$AllowServerOsUpdates,
    [switch]$AllowDatabasePackages,
    [switch]$Force,
    [switch]$Test,
    [switch]$PinReport
)
# Mutating apply mode is the default. Pass -Plan explicitly for a read-only plan.
if ($Plan -or $Test -or $PinReport) { $Apply = $false } else { $Apply = $true }
# Policy is embedded in this single-file tool; edit CriticalBinaryPaths and ExpectedPostHashes
# in Get-DefaultConfig below to enable pinned-binary validation without a separate JSON file.
# An external config is optional and only loaded when -ConfigPath is supplied.
# This single-file BAT edition runs the embedded engine in memory; no temporary PS1 is created.
# Arguments are reconstructed from the declared parameter surface, rather than trusting a raw
# command-line string. The same security contract applies: accepting the UAC prompt is required.
function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Restart-ZduElevated {
    # Serialize every declared parameter as data, then encode the bootstrap in UTF-16LE for
    # powershell.exe -EncodedCommand. The UAC boundary only receives static switches plus an
    # alphanumeric Base64 token: no user-controlled string is re-tokenized by cmd.exe or Win32.
    $state = [ordered]@{
        ScriptPath = $PSCommandPath; Mode = $Mode; ComputerName = @($ComputerName | Where-Object { $_ })
        HostFile = $HostFile; Cidr = $Cidr; CanaryHost = $CanaryHost; BatchSize = $BatchSize
        CanaryObservationSeconds = $CanaryObservationSeconds; ConfigPath = $ConfigPath
        Apply = [bool]$Apply; Plan = [bool]$Plan; AllowServerOsUpdates = [bool]$AllowServerOsUpdates
        AllowDatabasePackages = [bool]$AllowDatabasePackages; Force = [bool]$Force
    }
    $stateJson = [pscustomobject]$state | ConvertTo-Json -Depth 5 -Compress
    $state64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stateJson))
    $bootstrap = @'
$state = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ZDU_STATE__')) | ConvertFrom-Json
$splat = @{ Mode = [string]$state.Mode; BatchSize = [int]$state.BatchSize; CanaryObservationSeconds = [int]$state.CanaryObservationSeconds; ConfigPath = [string]$state.ConfigPath }
if($state.ComputerName){ $splat.ComputerName = @($state.ComputerName | ForEach-Object { [string]$_ }) }
if($state.HostFile){ $splat.HostFile = [string]$state.HostFile }
if($state.Cidr){ $splat.Cidr = [string]$state.Cidr }
if($state.CanaryHost){ $splat.CanaryHost = [string]$state.CanaryHost }
if([bool]$state.Plan){ $splat.Plan = $true } elseif([bool]$state.Apply){ $splat.Apply = $true }
if([bool]$state.AllowServerOsUpdates){ $splat.AllowServerOsUpdates = $true }
if([bool]$state.AllowDatabasePackages){ $splat.AllowDatabasePackages = $true }
if([bool]$state.Force){ $splat.Force = $true }
& ([string]$state.ScriptPath) @splat
exit 0
'@
    $bootstrap = $bootstrap.Replace('__ZDU_STATE__',$state64)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Write-Host 'Requesting Administrator approval (UAC)...' -ForegroundColor Yellow
    try {
        $child = Start-Process -FilePath $powershell -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-EncodedCommand',$encoded)
        exit $child.ExitCode
    } catch {
        Write-Error "Elevation was cancelled or could not be started: $($_.Exception.Message)"
        exit 1223 # ERROR_CANCELLED
    }
}
# Apply and cluster-control operations need an elevated local token. A remote worker must still
# be reached through a WinRM endpoint configured for an administrative, non-filtered token.
if(($Apply -or $Mode -eq 'Cluster') -and -not (Test-IsAdministrator)){ Restart-ZduElevated }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$EngineVersion = '1.1.0-singlefile'
$RunId = "zdu-win-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$env:COMPUTERNAME"
$RunRoot = if ($Test) { Join-Path $env:TEMP "ZDU-test-$RunId" } else { Join-Path ${env:ProgramData} "ZDU\runs\$RunId" }
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
$LogPath = Join-Path $RunRoot 'engine.log'
$script:Snapshot = $null
$script:Drained = $false
$script:RunStart = Get-Date
Write-Host "ZDU Windows $EngineVersion | Mode=$Mode | Apply=$Apply | Test=$Test" -ForegroundColor Cyan

function Write-Zdu {
    param([ValidateSet('INFO','OK','WARN','FAIL','STEP','PLAN')][string]$Level,[string]$Message)
    $colour = @{ INFO='Cyan'; OK='Green'; WARN='Yellow'; FAIL='Red'; STEP='Magenta'; PLAN='DarkCyan' }[$Level]
    $line = "[{0:u}] [{1,-4}] {2}" -f (Get-Date),$Level,$Message
    Write-Host $line -ForegroundColor $colour
    Add-Content -LiteralPath $LogPath -Value $line
}
function Get-DefaultConfig {
@'
{
  "RequiredPorts": [],
  "ObservePorts": [80,443,8080,8443],
  "ProductionPorts": [80,443,8080,8443],
  "ManagementPorts": [3389,5985,5986],
  "ProtectedProcessPatterns": ["nginx","apache","httpd","w3wp","iisexpress","docker","containerd","podman","kubelet","sqlservr","postgres","mysqld","mariadbd","mongod","oracle","redis-server"],
  "SafeProcessPatterns": ["chrome","msedge","firefox","teams","slack","onedrive"],
  "CriticalBinaryPaths": [],
  "ExpectedPostHashes": {},
  "RequirePinnedHashes": true,
  "SupplyChainPolicyNote": "Use -PinReport to inventory configured and Windows-service executable paths. Reported hashes are observations only, not trusted pins. Add exact absolute paths and SHA-256 values only after independent verification against trusted vendor release metadata or a verified build attestation. Hashes are version/build-specific.",
  "WingetIncludeIds": [],
  "WingetPackages": [],
  "WindowsUpdateKbIncludeIds": [],
  "DriverUpdates": [],
  "WingetOverride": "",
  "AllowWindowsUpdateOnWorkstation": true,
  "AllowServerOsUpdates": false,
  "AllowNoSnapshot": false,
  "EnableDependencyRepair": false,
  "ErrorRatePercent": 10,
  "MinNewErrors": 2,
  "HistoricalMetricsFile": "",
  "MaxDiskLatencyMs": 40,
  "QuarantinedPackages": [],
  "QuarantinedCVEs": [],
  "ThreatFeedUrl": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "ThreatCacheTtlSeconds": 21600,
  "CacheUrl": "",
  "ClusterCapacityCommand": "",
  "NetworkQuarantineCommand": "",
  "DrainCommand": "Invoke-ZduDrainAdapter",
  "ActiveConnectionsCommand": "Invoke-ZduActiveConnectionsAdapter",
  "EnableCommand": "Invoke-ZduEnableAdapter",
  "RollbackCommand": "Invoke-ZduRollbackAdapter",
  "ForensicCertificateThumbprint": "",
  "DatabaseChangeWindowApproved": false,
  "DatabaseBackupCommand": "Invoke-ZduDbBackupGuardAdapter",
  "DatabaseBackupAttestationPath": "",
  "DatabaseTransactionCheckCommand": "Invoke-ZduDbTransactionCheckAdapter",
  "Cluster": { "CanaryHost": "", "NonCriticalHosts": [], "BatchSize": 2, "CanaryWaitSeconds": 300, "MinimumHealthyNodes": 1 }
}
'@ | ConvertFrom-Json
}
function Get-Config {
    # The default policy JSON is embedded in this single-file tool via Get-DefaultConfig.
    # No sidecar JSON file is required. An explicit operator-supplied -ConfigPath remains an override.
    $c = Get-DefaultConfig
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)) {
        Write-Zdu INFO "Loading operator configuration override: $ConfigPath"
        try { $c = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json } catch { throw "Invalid JSON config: $($_.Exception.Message)" }
    } elseif ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        Write-Zdu INFO 'Using embedded conservative configuration; no external JSON file is required.'
    } else {
        throw "Specified config file not found: $ConfigPath"
    }
    return $c
}
$Cfg = Get-Config
function Cfg { param([string]$Name,$Default=$null) $p=$Cfg.PSObject.Properties[$Name]; if($null -ne $p){return $p.Value}; return $Default }
function Invoke-ApprovedHook {
    param([string]$Name,[string]$Command,[switch]$Required)
    if ([string]::IsNullOrWhiteSpace($Command)) {
        if($Required){ throw "Required adapter '$Name' is not configured." }
        Write-Zdu WARN "No $Name adapter configured; no external action taken."
        return $null
    }
    Write-Zdu STEP "Adapter: $Name"
    # Hooks are PowerShell code, so capture PowerShell success independently from native exit status.
    # Clear the native status before invocation so a cmdlet-only hook cannot inherit a stale failure.
    $global:LASTEXITCODE = $null
    $result = @(& ([scriptblock]::Create($Command)) 2>&1)
    $hookSucceeded = $?
    $code = $LASTEXITCODE
    Add-Content -LiteralPath $LogPath -Value ("HOOK {0}: {1}" -f $Name,($result -join "`n"))
    if(-not $hookSucceeded){ throw "Adapter '$Name' failed (PowerShell command reported failure)." }
    if($null -ne $code -and $code -ne 0){ throw "Adapter '$Name' failed with native exit code $code." }
    return ($result -join "`n")
}
# Inline adapters keep this deployment self-contained. Local firewall quarantine only affects
# configured production listener ports; management ports are deliberately never modified.
function Get-ZduProductionPorts {
    $configuredPorts = Cfg ProductionPorts @(80,443,8080,8443)
    $ports = @($configuredPorts | ForEach-Object { [int]$_ } | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Select-Object -Unique)
    if ($ports.Count -eq 0) { throw 'ProductionPorts is empty; refusing an unscoped traffic operation.' }
    return $ports
}
function Invoke-ZduDrainAdapter {
    $ports = Get-ZduProductionPorts
    foreach ($port in $ports) {
        $name = "ZDU-Quarantine-In-TCP-$port"
        if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -Enabled True `
                -Profile Domain,Private,Public -Protocol TCP -LocalPort $port -RemoteAddress '0.0.0.0/0','::/0' `
                -EdgeTraversalPolicy Block | Out-Null
        }
    }
    Write-Zdu WARN "Local inbound quarantine applied to production ports [$($ports -join ',')]. This is not an upstream load-balancer drain."
    return 'drain-requested'
}
function Invoke-ZduActiveConnectionsAdapter {
    $ports = Get-ZduProductionPorts
    $connections = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in $ports -and $_.RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::') })
    [Console]::Out.WriteLine([string]$connections.Count)
}
function Invoke-ZduEnableAdapter {
    foreach ($rule in @(Get-NetFirewallRule -DisplayName 'ZDU-Quarantine-In-TCP-*' -ErrorAction SilentlyContinue)) {
        Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
    }
    Write-Zdu INFO 'Removed ZDU-owned inbound quarantine rules; unrelated firewall rules were not changed.'
    return 'traffic-enabled'
}
function Invoke-ZduDbTransactionCheckAdapter {
    $longSeconds = 300
    $sql = @(Get-Process sqlservr -ErrorAction SilentlyContinue)
    $pg = @(Get-Process postgres -ErrorAction SilentlyContinue)
    if ($sql.Count -gt 0) {
        if (-not (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue)) { throw 'SQL Server detected but sqlcmd.exe is unavailable; DBA gate fails closed.' }
        $q = "SET NOCOUNT ON; IF EXISTS (SELECT 1 FROM sys.dm_exec_requests r CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t WHERE r.session_id <> @@SPID AND r.total_elapsed_time >= $($longSeconds*1000) AND (t.text LIKE '%INSERT%' OR t.text LIKE '%UPDATE%' OR t.text LIKE '%DELETE%' OR t.text LIKE '%MERGE%')) SELECT 1 ELSE SELECT 0;"
        $out = & sqlcmd.exe -S localhost -E -b -h -1 -W -Q $q 2>&1
        if ($LASTEXITCODE -ne 0) { throw "SQL Server transaction check failed: $($out -join ' ')" }
        if (($out -join '').Trim() -match '(?m)^1$') { throw 'Long-running SQL Server write request detected.' }
    }
    if ($pg.Count -gt 0) {
        if (-not (Get-Command psql.exe -ErrorAction SilentlyContinue)) { throw 'PostgreSQL detected but psql.exe is unavailable; DBA gate fails closed.' }
        $q = "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND now()-xact_start > interval '$longSeconds seconds' AND state IN ('active','idle in transaction') AND query ~* '\m(insert|update|delete|merge|alter|drop|truncate)\M';"
        $out = & psql.exe -w -X -A -t -v ON_ERROR_STOP=1 -h localhost -d postgres -c $q 2>&1
        if ($LASTEXITCODE -ne 0) { throw "PostgreSQL transaction check failed: $($out -join ' ')" }
        [int]$count = 0
        if (-not [int]::TryParse(($out -join '').Trim(), [ref]$count)) { throw 'PostgreSQL returned an invalid transaction count.' }
        if ($count -gt 0) { throw 'Long-running PostgreSQL write transaction detected.' }
    }
    return 'database-transaction-check-passed'
}
function Invoke-ZduDbBackupGuardAdapter {
    # Verify backup evidence; CHECKPOINT alone is not a backup and is not accepted as one.
    if (Get-Process sqlservr -ErrorAction SilentlyContinue) {
        if (-not (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue)) { throw 'SQL Server detected but sqlcmd.exe is unavailable; refusing to claim a backup guard passed.' }
        $q = "SET NOCOUNT ON; SELECT CASE WHEN MAX(backup_finish_date) >= DATEADD(hour,-24,GETDATE()) THEN 1 ELSE 0 END FROM msdb.dbo.backupset WHERE type='D';"
        $out = & sqlcmd.exe -S localhost -E -b -h -1 -W -Q $q 2>&1
        if ($LASTEXITCODE -ne 0) { throw "SQL Server backup-history query failed: $($out -join ' ')" }
        if (($out -join '').Trim() -notmatch '(?m)^1$') { throw 'No successful SQL Server full backup within the last 24 hours was verified.' }
    }
    if (Get-Process postgres -ErrorAction SilentlyContinue) {
        $attestation = [string](Cfg DatabaseBackupAttestationPath '')
        if ([string]::IsNullOrWhiteSpace($attestation) -or -not (Test-Path -LiteralPath $attestation -PathType Leaf)) {
            throw 'PostgreSQL detected but DatabaseBackupAttestationPath is not configured to a trusted backup-system attestation; refusing to claim a backup guard passed.'
        }
        try { $evidence = Get-Content -LiteralPath $attestation -Raw | ConvertFrom-Json } catch { throw "PostgreSQL backup attestation is invalid JSON: $($_.Exception.Message)" }
        $status = [string]$evidence.Status
        $backupTime = [datetime]::MinValue
        if ($status -ne 'success' -or -not [datetime]::TryParse([string]$evidence.BackupUtc, [ref]$backupTime) -or $backupTime.ToUniversalTime() -lt (Get-Date).ToUniversalTime().AddHours(-24) -or $backupTime.ToUniversalTime() -gt (Get-Date).ToUniversalTime().AddMinutes(5)) {
            throw 'PostgreSQL backup attestation must contain Status=success and a BackupUtc timestamp within the last 24 hours.'
        }
    }
    return 'database-backup-evidence-verified'
}
function Invoke-ZduRollbackAdapter {
    param([string]$Reason = 'ZDU deployment health gate failed')
    $ports = Get-ZduProductionPorts
    foreach ($port in $ports) {
        $name = "ZDU-Quarantine-In-TCP-$port"
        if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -Enabled True `
                -Profile Domain,Private,Public -Protocol TCP -LocalPort $port -RemoteAddress '0.0.0.0/0','::/0' `
                -EdgeTraversalPolicy Block | Out-Null
        }
    }
    $stateDir = Join-Path ${env:ProgramData} 'ZDU\state'
    New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    [pscustomobject]@{Host=$env:COMPUTERNAME;State='Degraded';Reason=$Reason;Utc=(Get-Date).ToUniversalTime().ToString('o')} |
        ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $stateDir 'cluster-degraded.json') -Encoding UTF8
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('ZDU-Windows')) { New-EventLog -LogName Application -Source 'ZDU-Windows' }
        Write-EventLog -LogName Application -Source 'ZDU-Windows' -EntryType Error -EventId 9101 -Message "ZDU failure on $env:COMPUTERNAME: $Reason. Node quarantined pending operator recovery."
    } catch { Write-Zdu WARN "Could not write Windows Event Log marker: $($_.Exception.Message)" }
    Write-Zdu FAIL 'Node marked degraded and production listener ports quarantined; no automatic package rollback or reboot was attempted.'
    return 'degraded-quarantined'
}
function Test-ZduDiskLatencyValue {
    param([double]$P95Ms)
    if ($P95Ms -gt [double](Cfg MaxDiskLatencyMs 40)) { throw "Predictive maintenance gate: historical disk latency P95 is $P95Ms ms." }
    return $true
}
function Test-ZduDrainTimeoutContract {
    param([int]$ActiveConnections,[datetime]$Deadline,[datetime]$Now=(Get-Date))
    return ($ActiveConnections -ne 0 -and $Now -ge $Deadline)
}
function Invoke-ZduSelfTest {
    $failed = New-Object System.Collections.Generic.List[string]
    try { Test-ZduDiskLatencyValue -P95Ms ([double](Cfg MaxDiskLatencyMs 40) + 1) | Out-Null; $failed.Add('P95 disk latency gate did not reject an over-limit sample.') } catch { if ($_.Exception.Message -notlike '*Predictive maintenance gate*') { $failed.Add("Unexpected P95 test error: $($_.Exception.Message)") } }
    if (-not (Test-ZduDrainTimeoutContract -ActiveConnections 1 -Deadline (Get-Date).AddSeconds(-1) -Now (Get-Date))) { $failed.Add('Drain timeout contract did not flag lingering connections after deadline.') }
    if (Test-ZduDrainTimeoutContract -ActiveConnections 0 -Deadline (Get-Date).AddSeconds(-1) -Now (Get-Date)) { $failed.Add('Drain timeout contract incorrectly failed at zero connections.') }
    if ($failed.Count) { $failed | ForEach-Object { Write-Host "[FAIL] $_" -ForegroundColor Red }; return 1 }
    Write-Host '[PASS] P95 disk-latency resource gate rejects over-limit samples.' -ForegroundColor Green
    Write-Host '[PASS] Drain timeout contract fails on lingering connections and passes at zero.' -ForegroundColor Green
    Write-Host '[PASS] Self-tests are offline and do not alter firewall, database, or services.' -ForegroundColor Green
    return 0
}
function Get-Environment {
    $os=Get-CimInstance Win32_OperatingSystem
    $cs=Get-CimInstance Win32_ComputerSystem
    $server = $os.ProductType -ne 1
    $cpuSample = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
    $cpu=[math]::Round($cpuSample.CounterSamples[0].CookedValue,1)
    $ramFreePct=[math]::Round((($os.FreePhysicalMemory*1KB)/($cs.TotalPhysicalMemory))*100,1)
    [pscustomobject]@{ Host=$env:COMPUTERNAME; IsServer=$server; CPU=$cpu; FreeRamPct=$ramFreePct; ProductType=$os.ProductType; Build=$os.BuildNumber }
}
function Test-ResourceGate {
    param($Env)
    Write-Zdu INFO "Capacity: CPU $($Env.CPU)% | free RAM $($Env.FreeRamPct)% | server=$($Env.IsServer)"
    if($Env.CPU -gt 85 -or $Env.FreeRamPct -lt 10){ throw 'Resource Constrained: CPU exceeds 85% or available RAM is below 10%.' }
    $history=Cfg HistoricalMetricsFile ''
    if($history -and (Test-Path $history)) {
        try {
            $m=Get-Content $history -Raw|ConvertFrom-Json
            Test-ZduDiskLatencyValue -P95Ms ([double]$m.DiskLatencyP95Ms) | Out-Null
        } catch { if($_.Exception.Message -like '*Predictive*'){throw}; Write-Zdu WARN "Historical metrics unreadable: $($_.Exception.Message)" }
    }
}
function Get-ProcessFence {
    $protected=@(Cfg ProtectedProcessPatterns @()); $safe=@(Cfg SafeProcessPatterns @())
    $all=Get-Process -ErrorAction SilentlyContinue
    $high=@($all|Where-Object { $n=$_.ProcessName; $protected|Where-Object{$n -match $_} }|Select-Object -ExpandProperty ProcessName -Unique)
    $safeFound=@($all|Where-Object { $n=$_.ProcessName; $safe|Where-Object{$n -match $_} }|Select-Object -ExpandProperty ProcessName -Unique)
    Write-Zdu INFO "Fence: protected=[$($high -join ', ')]; recyclable=[$($safeFound -join ', ')]"
    [pscustomobject]@{Protected=$high; Safe=$safeFound}
}
function Get-DatabaseEngines {
    $patterns='postgres|sqlservr|mysql|mariadbd|mongod|oracle|redis-server'
    @(Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -match $patterns} | Select-Object -ExpandProperty ProcessName -Unique)
}
function New-Sbom {
    param([string]$Phase)
    $apps=@()
    $paths=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach($path in $paths) {
        foreach($entry in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
            # Under StrictMode, shorthand Where-Object DisplayName throws when a registry
            # entry lacks that property. Check properties explicitly; uninstall keys vary.
            $nameProp = $entry.PSObject.Properties['DisplayName']
            if ($null -eq $nameProp -or [string]::IsNullOrWhiteSpace([string]$nameProp.Value)) { continue }
            $versionProp = $entry.PSObject.Properties['DisplayVersion']
            $publisherProp = $entry.PSObject.Properties['Publisher']
            $apps += [pscustomobject]@{
                Name = [string]$nameProp.Value
                Version = if ($null -ne $versionProp) { [string]$versionProp.Value } else { '' }
                Publisher = if ($null -ne $publisherProp) { [string]$publisherProp.Value } else { '' }
            }
        }
    }
    $bins=@()
    foreach($f in @(Cfg CriticalBinaryPaths @())) {
        if(Test-Path -LiteralPath $f){
            $sig=Get-AuthenticodeSignature -FilePath $f
            $bins += [pscustomobject]@{Path=$f;SHA256=(Get-FileHash $f -Algorithm SHA256).Hash;Signature=$sig.Status.ToString();Signer=$sig.SignerCertificate.Subject}
        }
    }
    $doc=[pscustomobject]@{Schema='zdu-sbom-v1';Phase=$Phase;GeneratedAt=(Get-Date).ToUniversalTime().ToString('o');Host=$env:COMPUTERNAME;Applications=$apps;CriticalBinaries=$bins}
    $path=Join-Path $RunRoot "sbom-$Phase.json"; $doc|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $path -Encoding UTF8
    Write-Zdu INFO "SBOM written: $path ($($apps.Count) registered packages, $($bins.Count) critical binaries)"
    return $doc
}
function Test-PostSbom {
    param($Sbom)
    $critical=@(Cfg CriticalBinaryPaths @() | ForEach-Object { [string]$_ })
    $expected=Cfg ExpectedPostHashes ([pscustomobject]@{})
    $requirePinned=[bool](Cfg RequirePinnedHashes $true)

    # Fail closed when a binary is explicitly designated critical but is missing, unsigned,
    # or does not match an operator-pinned SHA-256. Hashes must be collected from a trusted,
    # independently verified release; never populate these values from the post-update host.
    if($critical.Count -eq 0) {
        if($Apply) { throw 'Supply-chain gate: no CriticalBinaryPaths configured. Pin critical binaries and their trusted SHA-256 values in the embedded policy before applying updates.' }
        Write-Zdu WARN 'Supply-chain hash pinning is NOT active: CriticalBinaryPaths is empty. Plan/test only; configure the embedded policy before production use.'
        return
    }
    foreach($path in $critical) {
        $bin=@($Sbom.CriticalBinaries | Where-Object { [string]::Equals([string]$_.Path,$path,[StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)[0]
        if($null -eq $bin) { throw "Supply-chain gate: critical binary is missing or unreadable: $path" }
        if($bin.Signature -ne 'Valid') { throw "Supply-chain gate: $($bin.Path) signature is $($bin.Signature)." }
        $wanted=$expected.PSObject.Properties[$path]
        if($null -eq $wanted) {
            if($requirePinned) { throw "Supply-chain gate: no ExpectedPostHashes pin configured for '$path'." }
            Write-Zdu WARN "No SHA-256 pin configured for '$path'; signature was valid but hash pinning was waived by policy."
            continue
        }
        $wantedHash=([string]$wanted.Value).Trim().ToUpperInvariant()
        if($wantedHash -notmatch '^[A-F0-9]{64}$') { throw "Supply-chain gate: ExpectedPostHashes entry for '$path' is not a 64-character SHA-256 hex value." }
        if($wantedHash -ne ([string]$bin.SHA256).ToUpperInvariant()) { throw "Supply-chain gate: unexpected SHA-256 for '$path'. Expected=$wantedHash Actual=$($bin.SHA256)." }
    }
    Write-Zdu OK "Supply-chain gate passed for $($critical.Count) pinned critical binary/binaries."
}
function Write-ZduPinReport {
    # Read-only discovery for the current host. These observations are candidates only,
    # NOT trusted policy pins. Never copy observed values into ExpectedPostHashes automatically.
    $configured=@(Cfg CriticalBinaryPaths @() | ForEach-Object { [string]$_ })
    $candidates=New-Object System.Collections.Generic.List[string]
    foreach($p in $configured){ if(-not [string]::IsNullOrWhiteSpace($p)){ $candidates.Add($p) } }
    # Discover executable paths registered with Windows services, including third-party proxies,
    # agents, databases and custom services. ImagePath may include arguments or environment vars.
    try {
        foreach($svc in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
            $raw=[Environment]::ExpandEnvironmentVariables([string]$svc.PathName).Trim()
            if(-not $raw){continue}
            $exe=$null
            if($raw -match '^\s*"([^\"]+\.exe)"'){ $exe=$Matches[1] }
            elseif($raw -match '^\s*(.+?\.exe)(?:\s|$)'){ $exe=$Matches[1].Trim('"') }
            if($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)){ $candidates.Add($exe) }
        }
    } catch { Write-Zdu WARN "Service executable discovery failed: $($_.Exception.Message)" }
    # Include common web-server locations when installed outside a Windows service registration.
    foreach($p in @(
      "$env:ProgramFiles\nginx\nginx.exe",
      "${env:ProgramFiles(x86)}\nginx\nginx.exe",
      "$env:ProgramFiles\Apache Group\Apache2\bin\httpd.exe",
      "$env:ProgramFiles\Apache24\bin\httpd.exe",
      "${env:ProgramFiles(x86)}\Apache24\bin\httpd.exe",
      "$env:windir\System32\inetsrv\w3wp.exe"
    )) { if($p -and (Test-Path -LiteralPath $p -PathType Leaf)){ $candidates.Add($p) } }
    $paths=@($candidates | Select-Object -Unique)
    $rows=@()
    foreach($path in $paths) {
      if(-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
      try {
        $sig=Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
        $item=Get-Item -LiteralPath $path -ErrorAction Stop
        $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
        $rows += [pscustomobject]@{
          Path=$path; SHA256=$hash; Signature=$sig.Status.ToString()
          Signer=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{''}
          FileVersion=[string]$item.VersionInfo.FileVersion
          ProductVersion=[string]$item.VersionInfo.ProductVersion
          ProductName=[string]$item.VersionInfo.ProductName
          Publisher=[string]$item.VersionInfo.CompanyName
          TrustStatus='UNVERIFIED_OBSERVATION_NOT_A_PIN'
        }
      } catch { Write-Zdu WARN "Could not inspect '$path': $($_.Exception.Message)" }
    }
    if($rows.Count -eq 0) {
      Write-Zdu WARN 'No configured or registered service executables could be inspected. Run elevated if required, and verify service paths.'
      return
    }
    $report=Join-Path $RunRoot 'supply-chain-pin-report.json'
    $doc=[pscustomobject]@{
      Schema='zdu-pin-candidate-report-v2'
      GeneratedAt=(Get-Date).ToUniversalTime().ToString('o')
      Host=$env:COMPUTERNAME
      Notice='Hashes are observations from this host, not independently trusted pins. Verify against vendor-signed release metadata or a trusted build attestation before approving.'
      Count=$rows.Count
      Binaries=@($rows)
    }
    $doc | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $report -Encoding UTF8
    Write-Zdu INFO "Discovered $($rows.Count) configured/registered service binaries. Candidate report: $report"
    Write-Host ''
    Write-Host 'UNTRUSTED CANDIDATE REPORT: do not treat host-observed hashes as approved pins.' -ForegroundColor Yellow
    foreach($r in $rows) {
      Write-Host ("Path      : {0}" -f $r.Path)
      Write-Host ("Version   : {0} | {1}" -f $r.FileVersion,$r.ProductVersion)
      Write-Host ("Signature : {0} | {1}" -f $r.Signature,$r.Signer)
      Write-Host ("SHA-256   : {0}" -f $r.SHA256)
      Write-Host ''
    }
    Write-Host 'Approve only after independent comparison with trusted vendor/build metadata; then add exact path/hash pairs to Get-DefaultConfig.' -ForegroundColor Cyan
}

function Test-ThreatGate {
    $blocked=@(Cfg QuarantinedPackages @())+@(Cfg QuarantinedCVEs @())
    if(@($blocked).Count -gt 0){ Write-Zdu WARN "Operator quarantine policy active: $($blocked -join ', '). Package-to-CVE mapping must be supplied by the change system." }
    $url=Cfg ThreatFeedUrl ''
    if(!$url){ return }
    [int]$ttl=0
    if(-not [int]::TryParse([string](Cfg ThreatCacheTtlSeconds 21600),[ref]$ttl) -or $ttl -lt 0){ throw 'ThreatCacheTtlSeconds must be a non-negative integer.' }
    $runFeed=Join-Path $RunRoot 'threat-feed.json'
    $cacheDir=Join-Path ${env:ProgramData} 'ZDU\cache'; $cache=Join-Path $cacheDir 'cisa-kev.json'
    if(Test-Path -LiteralPath $cache){
        $age=((Get-Date)-(Get-Item -LiteralPath $cache).LastWriteTime).TotalSeconds
        if($age -ge 0 -and $age -le $ttl){ Copy-Item -LiteralPath $cache -Destination $runFeed -Force; Write-Zdu INFO "Using cached CISA KEV feed ($([math]::Round($age))s old)."; return }
    }
    try {
        Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -OutFile $runFeed | Out-Null
        if($Apply){ New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null; Copy-Item -LiteralPath $runFeed -Destination $cache -Force }
        Write-Zdu INFO 'CISA KEV feed refreshed (evidence, not a vendor-recall feed).'
    } catch {
        if(Test-Path -LiteralPath $cache){ Copy-Item -LiteralPath $cache -Destination $runFeed -Force; Write-Zdu WARN "Threat feed refresh failed; using stale cache: $($_.Exception.Message)" }
        else { Write-Zdu WARN "Threat feed unavailable: $($_.Exception.Message)" }
    }
}
function New-Snapshot {
    if(-not $Apply){ Write-Zdu PLAN 'Would create Windows restore point (where System Protection is enabled).'; return [pscustomobject]@{Created=$false;Type='Plan'} }
    try {
        Checkpoint-Computer -Description "ZDU $RunId" -RestorePointType MODIFY_SETTINGS
        Write-Zdu OK 'Windows System Restore checkpoint created.'
        return [pscustomobject]@{Created=$true;Type='SystemRestore';Id=$RunId}
    } catch {
        if(Cfg AllowNoSnapshot $false){ Write-Zdu WARN "Snapshot unavailable but policy permits continuation: $($_.Exception.Message)"; return [pscustomobject]@{Created=$false;Type='Unavailable'} }
        throw "Snapshot gate failed. System Restore is not enabled or is rate-limited: $($_.Exception.Message)"
    }
}
function Get-ListeningPorts { @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Select-Object -ExpandProperty LocalPort -Unique) }
function Test-Ports {
    param([int[]]$Required)
    $listeners=Get-ListeningPorts; $failed=@()
    foreach($port in $Required){ if($listeners -notcontains $port){$failed+=$port} }
    $observed=@(Cfg ObservePorts @())|ForEach-Object{[pscustomobject]@{Port=$_;Listening=($listeners -contains [int]$_)}}
    Write-Zdu INFO "Port smoke check: required=[$($Required -join ',')] failed=[$($failed -join ',')]; observed=$($observed|ConvertTo-Json -Compress)"
    if(@($failed).Count){ throw "Health gate: expected listening port(s) missing: $($failed -join ', ')." }
}
function Get-ErrorCount { param([datetime]$Start,[datetime]$End) @(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$Start;EndTime=$End;Level=2} -ErrorAction SilentlyContinue).Count }
function Test-LogAnomaly {
    param([int]$Baseline,[datetime]$Started)
    $post=Get-ErrorCount $Started (Get-Date); $min=[int](Cfg MinNewErrors 2); $pct=[int](Cfg ErrorRatePercent 10)
    # Baseline is a five-minute window. This conservative rate check avoids treating a single known error as an incident.
    if($post -ge $min -and $post -gt ($Baseline*(1+$pct/100.0))){ throw "Log anomaly gate: $post new Application errors vs baseline $Baseline." }
    Write-Zdu INFO "Event health: baseline=$Baseline; new=$post."
}
function Invoke-Drain {
    if((Cfg DrainCommand '') -ne ''){ Invoke-ApprovedHook 'proxy drain' (Cfg DrainCommand) -Required; $script:Drained=$true
        $deadline=(Get-Date).AddMinutes(20)
        do {
            $out=Invoke-ApprovedHook 'active connection probe' (Cfg ActiveConnectionsCommand) -Required
            $trimmed = ([string]$out).Trim()
            [int]$n = -1
            if($trimmed -notmatch '^\d+$' -or -not [int]::TryParse($trimmed,[ref]$n) -or $n -lt 0){ throw "ActiveConnectionsCommand must emit exactly one non-negative integer; received: '$trimmed'. Failing closed." }
            if($n -eq 0){break}
            Write-Zdu INFO "Drain waiting: $n inflight connections"
            Start-Sleep 10
        } while((Get-Date)-lt $deadline)
        if($n -ne 0){throw 'Drain timeout: active inflight connections did not reach zero; update phase aborted.'}
    } else { Write-Zdu WARN 'No proxy adapter: the worker will not stop or restart protected production services.' }
}
function Invoke-Rejoin { if($script:Drained){ Invoke-ApprovedHook 'proxy rejoin' (Cfg EnableCommand) -Required; $script:Drained=$false } }
function Invoke-DbGuard {
    $db=@(Get-DatabaseEngines)
    if(@($db).Count -eq 0){return}
    Write-Zdu WARN "Active database engine(s): $($db -join ', ')"
    if(-not $Apply){ Write-Zdu PLAN 'Would require DBA approval and invoke transaction/backup adapters; no DB command runs in plan mode.'; return }
    if(-not $AllowDatabasePackages -or -not (Cfg DatabaseChangeWindowApproved $false)){ throw 'DBA gate: database package work is blocked without -AllowDatabasePackages and DatabaseChangeWindowApproved=true.' }
    Invoke-ApprovedHook 'database transaction check' (Cfg DatabaseTransactionCheckCommand) -Required | Out-Null
    Invoke-ApprovedHook 'database backup/lock adapter' (Cfg DatabaseBackupCommand) -Required | Out-Null
}
function Invoke-UpdatePlan {
    param($Env,$Fence)
    $cache=Cfg CacheUrl ''
    if($cache -and $cache -notmatch '^https://'){throw 'CacheUrl must be HTTPS and certificate-pinned by enterprise policy; raw LAN HTTP mirrors are refused.'}
    $quarantined = @((Cfg QuarantinedPackages @()))
    if(@($Fence.Protected).Count -gt 0){
        Write-Zdu WARN "Protected workload detected: [$($Fence.Protected -join ', ')]. Broad automatic updates are blocked unless a drain adapter is configured."
        if([string]::IsNullOrWhiteSpace([string](Cfg DrainCommand ''))){
            throw 'Protected workload gate: configure and test DrainCommand/ActiveConnectionsCommand before running broad automatic updates.'
        }
    }
    $packages = @(Cfg WingetPackages @())
    $kbConfigured = @((Cfg WindowsUpdateKbIncludeIds @()) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $driverConfigured = @(Cfg DriverUpdates @())
    if(-not $Apply){
        Write-Zdu PLAN ("Would update only explicitly pinned WingetPackages ({0}), allowlisted Windows KBs ({1}), and exact driver UpdateID/revision pairs ({2}). Empty lists mean no updates." -f $packages.Count,$kbConfigured.Count,$driverConfigured.Count)
        return
    }
    if($packages.Count -eq 0 -and $kbConfigured.Count -eq 0 -and $driverConfigured.Count -eq 0){ Write-Zdu INFO 'No package, Windows KB, or driver allowlist configured; no update or drain action will be performed.'; return }
    Invoke-Drain

    # Fail closed: no `winget upgrade --all`. Each package must have an exact ID and pinned version.
    if($packages.Count -gt 0){
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if($null -eq $winget){ throw 'winget.exe is not available. No package changes were made.' }
        foreach($pkg in $packages){
            $idProp=$pkg.PSObject.Properties['Id']; $verProp=$pkg.PSObject.Properties['Version']
            if($null -eq $idProp -or $null -eq $verProp -or [string]::IsNullOrWhiteSpace([string]$idProp.Value) -or [string]::IsNullOrWhiteSpace([string]$verProp.Value)){
                throw 'Each WingetPackages entry must contain non-empty Id and Version properties. No unpinned package updates are permitted.'
            }
            $id=[string]$idProp.Value; $version=[string]$verProp.Value
            # Validate the complete strings, then pass each value as its own native argument.
            if(-not [regex]::IsMatch($id,'\A[A-Za-z0-9][A-Za-z0-9._-]*\z',[System.Text.RegularExpressions.RegexOptions]::CultureInvariant) -or
               -not [regex]::IsMatch($version,'\A[A-Za-z0-9][A-Za-z0-9.+_-]*\z',[System.Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
                throw "Invalid package ID or version in allowlist: '$id' / '$version'."
            }
            Write-Zdu STEP "Updating explicitly pinned package: $id version $version"
            $wingetArgs = @('upgrade','--id',$id,'--version',$version,'--exact','--silent','--disable-interactivity','--accept-package-agreements','--accept-source-agreements')
            & $winget.Source @wingetArgs 2>&1 | ForEach-Object { $line=[string]$_; Add-Content -LiteralPath $LogPath -Value $line; Write-Host $line }
            $wingetExit=$LASTEXITCODE
            Add-Content -LiteralPath $LogPath -Value ("winget upgrade --id {0} --version {1}; exit={2}" -f $id,$version,$wingetExit)
            if($wingetExit -ne 0){ throw "Pinned winget update failed for '$id' version '$version' (exit $wingetExit)." }
        }
    } else { Write-Zdu INFO 'WingetPackages is empty; no application package updates will be attempted.' }

    $mayWindowsUpdate = (!$Env.IsServer -and [bool](Cfg AllowWindowsUpdateOnWorkstation $true)) -or ($Env.IsServer -and $AllowServerOsUpdates -and [bool](Cfg AllowServerOsUpdates $false))
    if(-not $mayWindowsUpdate){
        Write-Zdu WARN 'Windows Update is disabled by server policy. On servers, pass -AllowServerOsUpdates and set AllowServerOsUpdates=true in an explicit protected configuration.'
        return
    }
    if(@($Fence.Protected).Count -gt 0 -and [string]::IsNullOrWhiteSpace([string](Cfg DrainCommand ''))){
        throw 'Windows Update blocked because protected workloads were detected and no drain adapter is configured.'
    }

    # Windows Update is allowlist-only. Empty WindowsUpdateKbIncludeIds means no OS updates.
    $allowedKb = @((Cfg WindowsUpdateKbIncludeIds @()) | ForEach-Object { ([string]$_ -replace '[^0-9]','') } | Where-Object { $_ })
    if($allowedKb.Count -eq 0){ Write-Zdu INFO 'WindowsUpdateKbIncludeIds is empty; no Windows software updates will be installed.' }
    if($allowedKb.Count -gt 0){
    # Built-in Windows Update Agent; only software updates whose KB IDs exactly match the allowlist are selected.
    Write-Zdu STEP "Searching Windows Update for explicitly allowlisted KBs: $($allowedKb -join ', ') (drivers excluded)."
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software' and BrowseOnly=0")
        $updates = New-Object -ComObject Microsoft.Update.UpdateColl
        for($j=0; $j -lt [int]$searchResult.Updates.Count; $j++){
            $candidate=$searchResult.Updates.Item($j)
            $candidateKbs=@($candidate.KBArticleIDs | ForEach-Object { [string]$_ -replace '[^0-9]','' })
            if(@($candidateKbs | Where-Object { $_ -in $allowedKb }).Count -gt 0){ [void]$updates.Add($candidate) }
        }
        $updateCount = [int]$updates.Count
        Write-Zdu INFO "Windows Update found $updateCount allowlisted software update(s)."
        if($updateCount -gt 0){
            for($i=0; $i -lt $updateCount; $i++){
                $u = $updates.Item($i)
                if(-not $u.EulaAccepted){ $u.AcceptEula() }
                Write-Zdu INFO ("Windows Update candidate: {0}" -f $u.Title)
            }
            $downloader = $session.CreateUpdateDownloader()
            $downloader.Updates = $updates
            $downloadResult = $downloader.Download()
            if([int]$downloadResult.ResultCode -notin @(2,3)){ throw "Windows Update download failed (result code $($downloadResult.ResultCode))." }
            $installer = $session.CreateUpdateInstaller()
            $installer.Updates = $updates
            $installer.AllowSourcePrompts = $false
            $installer.ForceQuiet = $true
            $installResult = $installer.Install()
            $rebootRequired = [bool]$installResult.RebootRequired
            Add-Content -LiteralPath $LogPath -Value ("Windows Update result={0}; HResult={1}; rebootRequired={2}" -f $installResult.ResultCode,$installResult.HResult,$rebootRequired)
            for($i=0; $i -lt $updateCount; $i++){
                $uResult = $installResult.GetUpdateResult($i)
                $uTitle = $updates.Item($i).Title
                Write-Zdu INFO ("Windows Update result: {0}; resultCode={1}; HRESULT={2}" -f $uTitle,$uResult.ResultCode,$uResult.HResult)
            }
            if([int]$installResult.ResultCode -notin @(2,3)){ throw "Windows Update installation failed (result code $($installResult.ResultCode), HRESULT $($installResult.HResult))." }
            if($rebootRequired){ Write-Zdu WARN 'Windows Update reports that a restart is required. Per policy, ZDU will NOT restart the computer.' }
            else { Write-Zdu OK 'Windows software updates installed; no restart requested.' }
        } else {
            Write-Zdu OK 'Windows is already up to date for applicable software updates.'
        }
    } catch {
        throw "Windows Update phase failed: $($_.Exception.Message)"
    }
    }

    # Driver updates are deliberately opt-in and pinned to both Windows Update UpdateID and RevisionNumber.
    # A model/vendor name alone is not a stable identifier; no driver updates run with an empty allowlist.
    if($driverConfigured.Count -eq 0){ Write-Zdu INFO 'DriverUpdates is empty; no device drivers will be installed.'; return }
    $driverPins = @{}
    foreach($pin in $driverConfigured){
        $idProp=$pin.PSObject.Properties['UpdateID']; $revProp=$pin.PSObject.Properties['RevisionNumber']
        if($null -eq $idProp -or $null -eq $revProp){ throw 'Each DriverUpdates entry must contain UpdateID (GUID) and RevisionNumber. No driver updates permitted.' }
        $driverId=[string]$idProp.Value; $driverRev=0
        if($driverId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -or -not [int]::TryParse([string]$revProp.Value,[ref]$driverRev) -or $driverRev -lt 1){ throw 'Invalid DriverUpdates pin. Use a valid UpdateID GUID and positive RevisionNumber.' }
        $driverPins[($driverId.ToLowerInvariant() + ':' + $driverRev)]=$true
    }
    Write-Zdu STEP ("Searching Windows Update for {0} exact driver UpdateID/revision pin(s)." -f $driverPins.Count)
    try {
        $driverSession = New-Object -ComObject Microsoft.Update.Session
        $driverSearcher = $driverSession.CreateUpdateSearcher()
        $driverSearchResult = $driverSearcher.Search("IsInstalled=0 and IsHidden=0 and Type='Driver' and BrowseOnly=0")
        $driverUpdates = New-Object -ComObject Microsoft.Update.UpdateColl
        for($j=0; $j -lt [int]$driverSearchResult.Updates.Count; $j++){
            $candidate=$driverSearchResult.Updates.Item($j)
            $identity=$candidate.Identity
            $key=([string]$identity.UpdateID).ToLowerInvariant() + ':' + [int]$identity.RevisionNumber
            if($driverPins.ContainsKey($key)){ [void]$driverUpdates.Add($candidate) }
        }
        Write-Zdu INFO ("Windows Update found {0} exact allowlisted driver update(s)." -f [int]$driverUpdates.Count)
        if([int]$driverUpdates.Count -gt 0){
            for($i=0; $i -lt [int]$driverUpdates.Count; $i++){
                $u=$driverUpdates.Item($i)
                if(-not $u.EulaAccepted){ $u.AcceptEula() }
                Write-Zdu INFO ("Pinned driver candidate: {0} [UpdateID={1}; Revision={2}]" -f $u.Title,$u.Identity.UpdateID,$u.Identity.RevisionNumber)
            }
            $driverDownloader=$driverSession.CreateUpdateDownloader(); $driverDownloader.Updates=$driverUpdates
            $driverDownloadResult=$driverDownloader.Download()
            if([int]$driverDownloadResult.ResultCode -notin @(2,3)){ throw "Driver download failed (result code $($driverDownloadResult.ResultCode))." }
            $driverInstaller=$driverSession.CreateUpdateInstaller(); $driverInstaller.Updates=$driverUpdates
            $driverInstaller.AllowSourcePrompts=$false; $driverInstaller.ForceQuiet=$true
            $driverInstallResult=$driverInstaller.Install()
            Add-Content -LiteralPath $LogPath -Value ("Driver install result={0}; HResult={1}; rebootRequired={2}" -f $driverInstallResult.ResultCode,$driverInstallResult.HResult,$driverInstallResult.RebootRequired)
            for($i=0; $i -lt [int]$driverUpdates.Count; $i++){
                $ur=$driverInstallResult.GetUpdateResult($i); $du=$driverUpdates.Item($i)
                Write-Zdu INFO ("Driver result: {0}; resultCode={1}; HRESULT={2}" -f $du.Title,$ur.ResultCode,$ur.HResult)
            }
            if([int]$driverInstallResult.ResultCode -notin @(2,3)){ throw "Driver installation failed (result code $($driverInstallResult.ResultCode), HRESULT $($driverInstallResult.HResult))." }
            if([bool]$driverInstallResult.RebootRequired){ Write-Zdu WARN 'Driver update reports that a restart is required. Per policy, ZDU will NOT restart the computer.' } else { Write-Zdu OK 'Pinned driver updates installed; no restart requested.' }
        } else { Write-Zdu WARN 'None of the pinned driver UpdateID/revision pairs were offered by Windows Update; no driver was installed.' }
    } catch { throw "Windows driver update phase failed: $($_.Exception.Message)" }
}
function New-ForensicBundle {
    param([string]$Reason)
    $evidence=Join-Path $RunRoot 'evidence'; New-Item -ItemType Directory -Force -Path $evidence|Out-Null
    # Preserve inherited access needed by the active process; add explicit SYSTEM/Admin rules.
    # Do not disable inheritance here: doing so can make evidence files unreadable during ZIP creation.
    try { $acl=Get-Acl -LiteralPath $RunRoot; $system=New-Object Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'); $admins=New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.SetAccessRule($system); $acl.SetAccessRule($admins); Set-Acl -LiteralPath $RunRoot -AclObject $acl } catch { Write-Zdu WARN "Could not harden forensic folder ACL: $($_.Exception.Message)" }
    Get-Process|Select-Object ProcessName,Id,CPU,WS,Path|ConvertTo-Json|Set-Content (Join-Path $evidence 'processes.json')
    Get-NetTCPConnection -ErrorAction SilentlyContinue|ConvertTo-Json|Set-Content (Join-Path $evidence 'sockets.json')
    Get-ChildItem $RunRoot -File|Copy-Item -Destination $evidence -Force -ErrorAction SilentlyContinue
    $zip=Join-Path $RunRoot "forensic-$RunId.zip"; Compress-Archive -Path "$evidence\*" -DestinationPath $zip -Force
    $thumb=Cfg ForensicCertificateThumbprint ''
    if($thumb){ $cert=Get-ChildItem "Cert:\LocalMachine\My\$thumb" -ErrorAction SilentlyContinue; if($cert){ Protect-CmsMessage -To $cert -Path $zip -OutFile "$zip.p7m"; Remove-Item $zip -Force; Write-Zdu OK 'CMS-encrypted forensic bundle created.'; return } }
    Write-Zdu WARN 'Forensic ZIP is NOT encrypted because no usable CMS certificate was configured. Restrict ACLs immediately.'
}
function Invoke-EmergencyResponse {
    param([string]$Reason)
    Write-Zdu FAIL "Emergency response: $Reason"
    New-ForensicBundle $Reason
    # Restoring a checkpoint requires reboot and is intentionally never attempted by this zero-restart worker.
    $rollback=Cfg RollbackCommand ''
    if($rollback){ try { Invoke-ApprovedHook 'approved rollback' $rollback -Required | Out-Null } catch { Write-Zdu FAIL "Rollback hook failed: $($_.Exception.Message)" } }
    else { Write-Zdu WARN 'Node remains drained/quarantined. Configure and test RollbackCommand for package/app rollback; System Restore cannot roll back online.' }
}
function Send-Webhook {
    param([string]$Status,[string]$Detail)
    $uri=$env:ZDU_WEBHOOK_URL
    if(!$uri){return}
    $payload=[pscustomobject]@{text="ZDU Windows $Status &#8212; $env:COMPUTERNAME";run_id=$RunId;status=$Status;host=$env:COMPUTERNAME;detail=$Detail;log=$LogPath;timestamp=(Get-Date).ToUniversalTime().ToString('o')}
    try{Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body ($payload|ConvertTo-Json -Depth 5)|Out-Null}catch{Write-Zdu WARN "Webhook failed: $($_.Exception.Message)"}
}
function Invoke-Local {
    $envInfo=Get-Environment; $baseline=Get-ErrorCount (Get-Date).AddMinutes(-5) (Get-Date)
    $required=@(@(Cfg RequiredPorts @())|ForEach-Object{[int]$_}); $beforeListeners=@(Get-ListeningPorts)
    # If no explicit required ports exist, only ports observed before the change become the smoke-test set.
    if(@($required).Count -eq 0){$required=@($beforeListeners|Where-Object{$_ -in @(Cfg ObservePorts @())})}
    try {
        Write-Zdu STEP "[1/9] Pre-flight fingerprint"; Test-ResourceGate $envInfo; $fence=Get-ProcessFence
        Write-Zdu STEP '[2/9] Threat-intelligence / supply-chain gates'; Test-ThreatGate; $null=New-Sbom 'pre'
        Write-Zdu STEP '[3/9] Snapshot gate'; $script:Snapshot=New-Snapshot
        Write-Zdu STEP '[4/9] Database and transaction gate'; Invoke-DbGuard
        Write-Zdu STEP '[5/9] Controlled deployment'; Invoke-UpdatePlan $envInfo $fence
        Write-Zdu STEP '[6/9] Post-flight SBOM'; $post=New-Sbom 'post'; Test-PostSbom $post
        Write-Zdu STEP '[7/9] Network smoke tests'; Test-Ports $required
        Write-Zdu STEP '[8/9] Event anomaly scan'; Test-LogAnomaly $baseline $script:RunStart
        Write-Zdu STEP '[9/9] Rejoin / reboot status'; Invoke-Rejoin
        $reboot='Unknown'; if(Get-Command Get-WURebootStatus -ErrorAction SilentlyContinue){$reboot=(Get-WURebootStatus -Silent)}
        $detail="Success. Reboot status: $reboot"; Write-Zdu OK $detail; Send-Webhook 'success' $detail
        return [pscustomobject]@{RunId=$RunId;Host=$env:COMPUTERNAME;Status='success';RebootStatus=$reboot;Log=$LogPath}
    } catch {
        $why=$_.Exception.Message; Invoke-EmergencyResponse $why; Send-Webhook 'failure' $why
        return [pscustomobject]@{RunId=$RunId;Host=$env:COMPUTERNAME;Status='failure';Reason=$why;Log=$LogPath}
    }
}
function ConvertTo-Targets {
    $t=New-Object System.Collections.Generic.List[string]; foreach($x in $ComputerName){if($x){$t.Add($x)}}
    if($HostFile){ if(!(Test-Path $HostFile)){throw "Host file not found: $HostFile"}; Get-Content $HostFile|ForEach-Object{$v=$_.Trim();if($v -and !$v.StartsWith('#')){$t.Add($v)}} }
    if($Cidr){
        $pair=$Cidr.Split('/');if(@($pair).Count -ne 2){throw 'CIDR must look like 10.10.0.0/24'};$prefix=[int]$pair[1];if($prefix -lt 16 -or $prefix -gt 32){throw 'CIDR is limited to /16-/32; use a host file for larger sets.'}
        $bytes=[Net.IPAddress]::Parse($pair[0]).GetAddressBytes();[array]::Reverse($bytes);$base=[BitConverter]::ToUInt32($bytes,0);$count=[math]::Pow(2,32-$prefix);if($count-gt 4096){throw 'CIDR exceeds 4096 nodes.'};$mask=[uint32]([uint64]0xffffffff -shl (32-$prefix));$network=$base -band $mask
        for($i=1;$i -lt ($count-1);$i++){$b=[BitConverter]::GetBytes([uint32]($network+$i));[array]::Reverse($b);$t.Add(([Net.IPAddress]::new($b)).ToString())}
    }
    return @($t|Sort-Object -Unique)
}
function Invoke-RemoteWorker {
    param([string[]]$Targets)
    $args=@('-Mode','Local');if(-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)){$args+=@('-ConfigPath','C:\ProgramData\ZDU\zdu-windows.json')};if(-not $Apply){$args+='-Plan'};if($AllowServerOsUpdates){$args+='-AllowServerOsUpdates'};if($AllowDatabasePackages){$args+='-AllowDatabasePackages'}
    # Copy the non-secret config through the authenticated WinRM channel. Secrets belong in the target's secret store.
    if(-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)){$json=Get-Content $ConfigPath -Raw;Invoke-Command -ComputerName $Targets -ThrottleLimit $BatchSize -ScriptBlock {param($j) New-Item 'C:\ProgramData\ZDU' -ItemType Directory -Force|Out-Null;Set-Content 'C:\ProgramData\ZDU\zdu-windows.json' $j -Encoding UTF8} -ArgumentList $json}
    return Invoke-Command -ComputerName $Targets -FilePath $PSCommandPath -ArgumentList $args -AsJob -ThrottleLimit $BatchSize
}
function Test-ClusterCapacity {
    $command=Cfg ClusterCapacityCommand ''
    if([string]::IsNullOrWhiteSpace($command)){ throw 'Apply-mode cluster rollout requires ClusterCapacityCommand to enforce the minimum healthy-capacity threshold.' }
    $value=(Invoke-ApprovedHook 'cluster HA capacity' $command -Required).Trim()
    [int]$healthy=0
    if(-not [int]::TryParse($value,[ref]$healthy)){throw 'ClusterCapacityCommand must print one integer healthy-node count.'}
    $cluster=Cfg Cluster ([pscustomobject]@{MinimumHealthyNodes=1})
    $minimum=if($cluster.MinimumHealthyNodes){[int]$cluster.MinimumHealthyNodes}else{1}
    if($healthy -lt $minimum){throw "HA capacity gate: healthy=$healthy, minimum=$minimum."}
    Write-Zdu INFO "HA capacity gate passed: healthy=$healthy, minimum=$minimum."
}
function Invoke-Cluster {
    if(-not (Test-IsAdministrator)){throw 'Cluster mode must run elevated.'}
    if($Apply -and [string]::IsNullOrWhiteSpace((Cfg ClusterCapacityCommand ''))){throw 'Apply-mode cluster rollout requires ClusterCapacityCommand to enforce HA capacity.'}
    $targets=@(ConvertTo-Targets);if(@($targets).Count -lt 2){throw 'Cluster mode requires at least two targets.'}
    $cluster=Cfg Cluster ([pscustomobject]@{CanaryHost='';BatchSize=2;MinimumHealthyNodes=1})
    $configuredCanary=if($CanaryHost){$CanaryHost}else{$cluster.CanaryHost}
    if(!$configuredCanary -or $targets -notcontains $configuredCanary){throw 'Set -CanaryHost to a pre-designated non-critical host in the target set; automatic criticality guesses are forbidden.'}
    Write-Zdu STEP "Cluster canary: $configuredCanary (exactly one node)"
    if($Apply){Test-ClusterCapacity}
    $cj=Invoke-RemoteWorker @($configuredCanary);Wait-Job $cj|Out-Null;$cr=@(Receive-Job $cj -Keep);Remove-Job $cj
    if(@($cr|Where-Object Status -eq 'failure').Count){throw "Canary failed; entire rollout aborted. See: $($cr|ConvertTo-Json -Compress)"}
    Write-Zdu INFO "Canary succeeded. Observing for $CanaryObservationSeconds seconds before progressive rollout.";Start-Sleep $CanaryObservationSeconds
    $remaining=@($targets|Where-Object{$_ -ne $configuredCanary});$effectiveBatch=$BatchSize;if($cluster.BatchSize){$effectiveBatch=[int]$cluster.BatchSize}
    $all=@($cr);for($i=0;$i -lt (@($remaining).Count);$i+=$effectiveBatch){$batch=@($remaining[$i..([math]::Min($i+$effectiveBatch-1,$remaining.Count-1))]);if($Apply){Test-ClusterCapacity};Write-Zdu STEP "Progressive batch: $($batch -join ', ')";$j=Invoke-RemoteWorker $batch;Wait-Job $j|Out-Null;$r=@(Receive-Job $j -Keep);Remove-Job $j;$all+=$r;if(@($r|Where-Object Status -eq 'failure').Count){throw 'A rollout batch failed; remaining nodes were not touched.'}}
    $all|ConvertTo-Json -Depth 5|Set-Content (Join-Path $RunRoot 'cluster-results.json');Write-Zdu OK 'Cluster rollout completed.';Send-Webhook 'success' 'Cluster rollout completed.'
}
try {
    if ($Test) { $testExit = Invoke-ZduSelfTest; exit $testExit }
    if ($PinReport) { Write-ZduPinReport; exit 0 }
    if($Apply -and -not (Test-IsAdministrator)){throw 'Elevation required for -Apply. Accept the UAC prompt or start an elevated PowerShell session.'}
    if($Mode -eq 'Cluster'){
        Invoke-Cluster
    } else {
        $result=Invoke-Local
        $result
        if($result.Status -ne 'success'){ exit 1 }
    }
} catch { Write-Zdu FAIL $_.Exception.Message;Send-Webhook 'failure' $_.Exception.Message;exit 1 }
