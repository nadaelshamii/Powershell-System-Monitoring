<#
Lab 1 – System Health & Security Monitoring
#>

# ===================== Identity & Logging Config =====================
$Name = "Nada Elshami"
$ID   = "123123123"
$LabLogName   = "Lab1-Monitoring"    # custom Windows Event Log name
$LabLogSource = "Lab1-Monitoring"    # custom source (same name)
$DailyLogDir  = "C:\Logs"

function Get-DailyLogPath {
    Join-Path $DailyLogDir ("Lab1_{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))
}

function Initialize-LabLogging {
    try {
        if (-not (Test-Path -LiteralPath $DailyLogDir)) {
            New-Item -ItemType Directory -Path $DailyLogDir -Force | Out-Null
        }
    } catch {
        Write-Host "WARN: Could not create $DailyLogDir: $($_.Exception.Message)"
    }

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($LabLogSource)) {
            New-EventLog -LogName $LabLogName -Source $LabLogSource
        }
    } catch {
        Write-Host "WARN: Creating custom event log/source '$LabLogName' failed (run as admin once): $($_.Exception.Message)"
    }
}
Initialize-LabLogging

# ===================== Health Config (edit if needed) ================
$CPU_THRESHOLD   = 80      # %
$MEM_WARN_USED   = 85      # %
$DISK_MIN_FREE   = 15      # %
$SAMPLE_INTERVAL = 5       # seconds between CPU samples
$SUSTAIN_WINDOW  = 30      # seconds total sustained window
$CYCLE_SLEEP     = 60      # seconds between cycles

# ===================== Security Config ===============================
$SEC_LOOKBACK_MIN = 5
$FAIL_THRESHOLD   = 5
$SERVICE_ALLOWLIST = @()   # e.g., @("Some Service Display Name")

# ===================== Unified Logger ================================
function Write-AppEvent {
    param(
        [ValidateSet('Information','Warning','Error')] [string]$Level,
        [int]$EventId,
        [string]$Message
    )

    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line  = "[$stamp][$Level][$EventId] $Message"

    Write-Host $line

    try { Add-Content -LiteralPath (Get-DailyLogPath) -Value $line } catch { Write-Host "WARN: File log write failed: $($_.Exception.Message)" }

    try {
        Write-EventLog -LogName Application -Source "Windows PowerShell" -EntryType $Level -EventId $EventId -Message $Message
    } catch { }

    try {
        if ([System.Diagnostics.EventLog]::SourceExists($LabLogSource)) {
            Write-EventLog -LogName $LabLogName -Source $LabLogSource -EntryType $Level -EventId $EventId -Message $Message
        }
    } catch { }
}

# ===================== Health Helpers ================================
function Get-CPUPercent {
    (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
}

function Test-CPUHighForWindow {
    param(
        [double]$Threshold = 80,
        [int]$WindowSeconds = 30,
        [int]$SampleEverySeconds = 5
    )
    $samples = [Math]::Max(1, [Math]::Floor($WindowSeconds / $SampleEverySeconds))
    $high = 0
    for ($i = 1; $i -le $samples; $i++) {
        $cpu = Get-CPUPercent
        if ($cpu -ge $Threshold) { $high++ }
        Start-Sleep -Seconds $SampleEverySeconds
    }
    return ($high -ge [Math]::Ceiling(0.8 * $samples))  # e.g., 5 of 6
}

function Invoke-HighCPUAction {
    param([double]$Threshold = 80)

    $protected = @('System','Registry','smss','csrss','wininit','winlogon','services','lsass','svchost','fontdrvhost','dwm','explorer')

    $top = (Get-Counter '\Process(*)\% Processor Time').CounterSamples |
           Where-Object { $_.InstanceName -notin @('_Total','Idle') } |
           Sort-Object CookedValue -Descending |
           Select-Object -First 1

    if (-not $top) {
        Write-AppEvent -Level Error -EventId 3000 -Message "High CPU > $Threshold% for ~30s, but no process identified."
        return
    }

    $name = $top.InstanceName
    if ($protected -contains $name) {
        Write-AppEvent -Level Error -EventId 3002 -Message "High CPU sustained, top '$name' is protected. No termination."
        return
    }

    try {
        $procs = Get-Process -Name $name -ErrorAction Stop
        $pids = ($procs.Id -join ',')
        $procs | Stop-Process -Force
        Write-AppEvent -Level Error -EventId 3001 -Message "High CPU sustained. Terminated '$name' (PID: $pids)."
    } catch {
        Write-AppEvent -Level Error -EventId 3003 -Message "High CPU action failed for '$name': $($_.Exception.Message)"
    }
}

function Check-Memory {
    param([double]$WarnUsedPercent = 85)
    $os = Get-CimInstance Win32_OperatingSystem
    $totalMB = [double]$os.TotalVisibleMemorySize / 1024
    $freeMB  = [double]$os.FreePhysicalMemory     / 1024
    $usedPct = [math]::Round((($totalMB - $freeMB) / $totalMB) * 100, 2)
    if ($usedPct -ge $WarnUsedPercent) {
        $topMem = (Get-Process | Sort-Object WS -Desc | Select-Object -First 3 | ForEach-Object { "$($_.ProcessName):$([math]::Round($_.WS/1MB,1))MB" }) -join ', '
        Write-AppEvent -Level Warning -EventId 2001 -Message "Memory usage high: $usedPct% (≥ $WarnUsedPercent%). Recommend investigation. Top RAM users: $topMem"
    }
}

function Cleanup-CTemp {
    param([string]$Path = 'C:\Temp')

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-AppEvent -Level Warning -EventId 1201 -Message "Low disk detected but '$Path' does not exist. No cleanup performed."
        return
    }

    $before = 0
    try {
        $before = (Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if (-not $before) { $before = 0 }
    } catch { $before = 0 }

    try {
        Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    } catch { }

    $after = 0
    try {
        $after = (Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if (-not $after) { $after = 0 }
    } catch { $after = 0 }

    $freed = [Math]::Max(0, $before - $after)
    $mb = [Math]::Round(($freed/1MB),2)
    Write-AppEvent -Level Error -EventId 1202 -Message "Low disk remediation: cleaned '$Path', freed ${mb} MB."
}

function Check-DiskC {
    param([double]$MinFreePercent = 15)
    $c = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    if (-not $c) { return }
    $freePct = [math]::Round(($c.FreeSpace / $c.Size) * 100, 2)
    if ($freePct -lt $MinFreePercent) {
        Write-AppEvent -Level Error -EventId 1001 -Message "CRITICAL: C: free space $freePct% (< $MinFreePercent%)."
        Cleanup-CTemp
    }
}

function Find-HighCPUOffenders {
    param(
        [double]$Threshold = 80,
        [int]$WindowSeconds = 60,
        [int]$SampleEverySeconds = 5
    )
    $samples = [Math]::Max(1, [Math]::Floor($WindowSeconds / $SampleEverySeconds))
    $countsByPid = @{}

    for ($i = 1; $i -le $samples; $i++) {
        $c = Get-Counter -Counter '\Process(*)\% Processor Time','\Process(*)\ID Process'
        $cpuSamples = $c.CounterSamples | Where-Object { $_.Path -like '*% Processor Time*' }
        $pidSamples = $c.CounterSamples | Where-Object { $_.Path -like '*ID Process*' }
        $pidMap = @{ }
        foreach ($s in $pidSamples) { $pidMap[$s.InstanceName] = [int]$s.CookedValue }

        foreach ($s in $cpuSamples) {
            $inst = $s.InstanceName
            if ($inst -in @('_Total','Idle')) { continue }
            if (-not $pidMap.ContainsKey($inst)) { continue }
            $pid  = $pidMap[$inst]
            $pct  = $s.CookedValue
            if ($pct -ge $Threshold) {
                if (-not $countsByPid.ContainsKey($pid)) { $countsByPid[$pid] = 0 }
                $countsByPid[$pid]++
            }
        }
        Start-Sleep -Seconds $SampleEverySeconds
    }

    $need = [Math]::Ceiling(0.8 * $samples)
    $offenders = @()
    foreach ($kv in $countsByPid.GetEnumerator()) {
        if ($kv.Value -ge $need) { $offenders += [int]$kv.Key }
    }
    return $offenders
}

function Stop-ProcessSafe {
    param([int[]]$Pids)

    $protected = @('System','Registry','smss','csrss','wininit','winlogon','services','lsass','svchost','fontdrvhost','dwm','explorer')

    foreach ($pid in $Pids) {
        try {
            $p = Get-Process -Id $pid -ErrorAction Stop
            if ($protected -contains $p.ProcessName) {
                Write-AppEvent -Level Error -EventId 3102 -Message "High CPU offender PID $pid ('$($p.ProcessName)') is protected. No termination."
                continue
            }
            $name = $p.ProcessName
            Stop-Process -Id $pid -Force
            Write-AppEvent -Level Error -EventId 3101 -Message "Terminated high-CPU process PID $pid ('$name') after ≥1 min above $CPU_THRESHOLD%."
        } catch {
            Write-AppEvent -Level Error -EventId 3103 -Message "Failed to terminate PID $pid: $($_.Exception.Message)"
        }
    }
}

# ===================== Security Helpers ==============================
if (-not $script:LastSecurityCheck) { $script:LastSecurityCheck = (Get-Date).AddMinutes(-10) }
if (-not $script:LastSystemCheck)   { $script:LastSystemCheck   = (Get-Date).AddMinutes(-10) }

function Check-AuthSecurityEvents {
    param([datetime]$Since)

    $failed = @()
    try {
        $failed = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$Since } -ErrorAction SilentlyContinue
    } catch { }

    if ($failed.Count -gt 0) {
        $byUser = @{}
        foreach ($e in $failed) {
            try {
                $xml = [xml]$e.ToXml()
                $u = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                if ([string]::IsNullOrWhiteSpace($u)) { $u = "<unknown>" }
            } catch { $u = "<unknown>" }
            if (-not $byUser.ContainsKey($u)) { $byUser[$u] = 0 }
            $byUser[$u]++
        }

        foreach ($kv in $byUser.GetEnumerator()) {
            if ($kv.Value -ge $FAIL_THRESHOLD) {
                $console = "[SECURITY ALERT] Multiple failed login attempts detected for user: {0} , identified by {1} {2} on {3}" -f `
                           $kv.Key, $Name, $ID, (Get-Date -Format 'yyyy-MM-dd')
                Write-Host $console
                Write-AppEvent -Level Error -EventId 4625 -Message "$console — Count=$($kv.Value)"
            }
        }
    }

    $locks = @()
    try {
        $locks = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4740; StartTime=$Since } -ErrorAction SilentlyContinue
    } catch { }

    foreach ($e in $locks) {
        try {
            $xml = [xml]$e.ToXml()
            $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            if (-not $user) { $user = "<unknown>" }
        } catch { $user = "<unknown>" }

        $console = "[SECURITY ALERT] Account lockout detected for user: {0} , identified by {1} {2} on {3}" -f `
                   $user, $Name, $ID, (Get-Date -Format 'yyyy-MM-dd')
        Write-Host $console
        Write-AppEvent -Level Error -EventId 4740 -Message $console
    }

    $script:LastSecurityCheck = Get-Date
}

function Get-ServiceByAnyName {
    param([string]$NameOrDisplay)
    try { return Get-Service -Name $NameOrDisplay -ErrorAction Stop } catch { }
    try { return Get-Service -DisplayName $NameOrDisplay -ErrorAction Stop } catch { }
    return $null
}

function Check-ServiceStopEvents {
    param([datetime]$Since, [string[]]$AllowList)

    $svcEvents = @()
    try {
        $svcEvents = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=@(7034,7036); StartTime=$Since } -ErrorAction SilentlyContinue
    } catch { }

    foreach ($e in $svcEvents) {
        $txt = $e.Message
        $svc = if ($txt -match "The (.+?) service") { $matches[1] } else { "<unknown>" }

        if ($AllowList -and ($AllowList -contains $svc)) { continue }

        if ($e.Id -eq 7034) {
            $console = "[SECURITY ALERT] Service terminated unexpectedly: {0} , identified by {1} {2} on {3}" -f `
                       $svc, $Name, $ID, (Get-Date -Format 'yyyy-MM-dd')
            Write-Host $console
            Write-AppEvent -Level Error -EventId 7034 -Message $console
        }
        elseif ($e.Id -eq 7036 -and $txt -like "*entered the stopped state*") {
            $shouldAlert = $true
            try {
                $svcObj = Get-ServiceByAnyName -NameOrDisplay $svc
                if ($null -ne $svcObj) {
                    if ($svcObj.StartType -ne 'Automatic' -or $svcObj.Status -ne 'Stopped') { $shouldAlert = $false }
                }
            } catch { }
            if ($shouldAlert) {
                $console = "[SECURITY ALERT] Automatic service entered Stopped state: {0} , identified by {1} {2} on {3}" -f `
                           $svc, $Name, $ID, (Get-Date -Format 'yyyy-MM-dd')
                Write-Host $console
                Write-AppEvent -Level Warning -EventId 7036 -Message $console
            }
        }
    }

    $script:LastSystemCheck = Get-Date
}

# ===================== Start-up banner ===============================
Write-AppEvent -Level Information -EventId 9000 -Message "Lab1 monitoring started. CPU>$CPU_THRESHOLD% (~30s)=>action; Mem>$MEM_WARN_USED%=>warn; C:<$DISK_MIN_FREE% free=>critical; Security: 4625/4740/7034/7036."

# ===================== Main Loop ====================================
while ($true) {
    if (Test-CPUHighForWindow -Threshold $CPU_THRESHOLD -WindowSeconds $SUSTAIN_WINDOW -SampleEverySeconds $SAMPLE_INTERVAL) {
        Write-AppEvent -Level Information -EventId 9100 -Message "CPU > $CPU_THRESHOLD% sustained ~${SUSTAIN_WINDOW}s. Taking action."
        Invoke-HighCPUAction -Threshold $CPU_THRESHOLD
    } else {
        $nowCpu = [math]::Round((Get-CPUPercent),1)
        Write-Host "CPU OK: ${nowCpu}% (not sustained high)."
    }

    Check-Memory -WarnUsedPercent $MEM_WARN_USED
    Check-DiskC  -MinFreePercent  $DISK_MIN_FREE

    $offenders = Find-HighCPUOffenders -Threshold $CPU_THRESHOLD -WindowSeconds 60 -SampleEverySeconds 5
    if ($offenders.Count -gt 0) {
        Write-AppEvent -Level Information -EventId 9150 -Message "Per-process high CPU offenders (≥1min > $CPU_THRESHOLD%): PIDs $($offenders -join ', ')."
        Stop-ProcessSafe -Pids $offenders
    } else {
        Write-Host "No per-process high CPU offenders this window."
    }

    Check-AuthSecurityEvents -Since $script:LastSecurityCheck
    Check-ServiceStopEvents  -Since $script:LastSystemCheck -AllowList $SERVICE_ALLOWLIST

    Start-Sleep -Seconds $CYCLE_SLEEP
}
