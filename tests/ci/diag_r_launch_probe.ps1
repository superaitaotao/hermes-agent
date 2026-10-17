param(
    [ValidateSet('DN', 'ND', 'control')][string]$Order,
    [string]$Replica,
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$root = $env:GITHUB_WORKSPACE
$receipt = [ordered]@{
    schema_version = 1
    run_id = $env:GITHUB_RUN_ID
    run_attempt = $env:GITHUB_RUN_ATTEMPT
    job_key = $Replica
    runner_name = $env:RUNNER_NAME
    runner_os = $env:RUNNER_OS
    runner_arch = $env:RUNNER_ARCH
    image_os = $env:ImageOS
    image_version = $env:ImageVersion
    tested_sha = (git rev-parse HEAD)
    order = $Order
    started_utc = [DateTime]::UtcNow.ToString('o')
    core_count = [Environment]::ProcessorCount
    python = $env:HERMES_PYTHON
    probes = [System.Collections.Generic.List[object]]::new()
    remedies = [System.Collections.Generic.List[object]]::new()
    remedy_slot_seconds = 900
}
function Save-Receipt {
    $receipt | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $OutputPath -Encoding utf8
}
function Get-ProbeState {
    $status = $null; $preference = $null; $errors = @()
    try {
        $status = Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,
            AntivirusSignatureAge, AntispywareSignatureAge, AMServiceEnabled,
            AMRunningMode, AntivirusEnabled, NISEnabled
    } catch { $errors += $_.Exception.ToString() }
    try {
        $preference = Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent,
            DisableBlockAtFirstSeen, CloudBlockLevel, CloudExtendedTimeout,
            DisableRealtimeMonitoring, DisableScriptScanning
    } catch { $errors += $_.Exception.ToString() }
    return [ordered]@{
        utc = [DateTime]::UtcNow.ToString('o')
        defender = $status
        cloud_preferences = $preference
        dotnet_processes = @(Get-Process -Name mscorsvw, ngen -ErrorAction SilentlyContinue |
            Select-Object Id, ProcessName, CPU, Path)
        amsi_provider_registration = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue |
            Select-Object PSChildName)
        errors = $errors
    }
}
function Invoke-Launch([string]$Kind, [int]$Index, [int]$Probe) {
    $probeHome = Join-Path $env:RUNNER_TEMP "launch-$Replica-$Probe-$Kind-$Index"
    New-Item -ItemType Directory -Path (Join-Path $probeHome 'hermes-agent') -Force | Out-Null
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.Environment['HERMES_HOME'] = $probeHome
    switch ($Kind) {
        'marker' {
            $info.FileName = 'powershell.exe'
            @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
              (Join-Path $root 'scripts/desktop-update/windows.ps1'),
              '-SelfTestMarker', '-NoMarkerCleanup', '-NoUi', '-InstallRoot',
              (Join-Path $probeHome 'hermes-agent')) | ForEach-Object { $info.ArgumentList.Add($_) }
        }
        'powershell' {
            $info.FileName = 'powershell.exe'
            @('-NoProfile', '-Command', 'exit') | ForEach-Object { $info.ArgumentList.Add($_) }
        }
        'cmd' {
            $info.FileName = 'cmd.exe'
            @('/c', 'exit') | ForEach-Object { $info.ArgumentList.Add($_) }
        }
        'python' {
            $info.FileName = $env:HERMES_PYTHON
            @('-c', 'pass') | ForEach-Object { $info.ArgumentList.Add($_) }
        }
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    $samples = [System.Collections.Generic.List[object]]::new()
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $started = [DateTime]::UtcNow
    $null = $process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $killed = $false
    while (-not $process.WaitForExit(500)) {
        if ($clock.Elapsed.TotalSeconds -ge 120) {
            $killed = $true
            $process.Kill($true)
            $process.WaitForExit()
            break
        }
        try {
            $connections = @(Get-NetTCPConnection -State SynSent -ErrorAction SilentlyContinue |
                Select-Object OwningProcess, RemoteAddress, RemotePort)
            $samples.Add([ordered]@{elapsed_seconds = $clock.Elapsed.TotalSeconds; connections = $connections})
        } catch {
            $samples.Add([ordered]@{elapsed_seconds = $clock.Elapsed.TotalSeconds; error = $_.Exception.ToString()})
        }
    }
    $clock.Stop()
    $text = $stdout.GetAwaiter().GetResult()
    $errorText = $stderr.GetAwaiter().GetResult()
    $row = [ordered]@{
        kind = $Kind; repetition = $Index; pid = $process.Id
        started_utc = $started.ToString('o')
        wall_seconds = ($process.ExitTime.ToUniversalTime() - $started).TotalSeconds
        observer_wall_seconds = $clock.Elapsed.TotalSeconds
        cpu_seconds = $process.TotalProcessorTime.TotalSeconds
        exit_code = $process.ExitCode; killed = $killed
        stdout = $text; stderr = $errorText; syn_sent_samples = $samples
        marker_body = $(if (Test-Path (Join-Path $probeHome '.hermes-update-in-progress')) {
            Get-Content -Raw (Join-Path $probeHome '.hermes-update-in-progress')
        } else { $null })
    }
    $process.Dispose()
    return $row
}
function Invoke-Probe([int]$Number) {
    $probe = [ordered]@{number = $Number; state = (Get-ProbeState); launches = [System.Collections.Generic.List[object]]::new()}
    $receipt.probes.Add($probe)
    Save-Receipt
    foreach ($kind in @('marker', 'powershell', 'cmd', 'python')) {
        foreach ($index in 1..5) {
            $row = Invoke-Launch $kind $index $Number
            $probe.launches.Add($row)
            Save-Receipt
            Write-Host "$Replica probe=$Number kind=$kind repetition=$index wall=$($row.wall_seconds) exit=$($row.exit_code) killed=$($row.killed)"
        }
    }
}
function Invoke-Remedy([string]$Kind) {
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $commands = [System.Collections.Generic.List[object]]::new()
    if ($Kind -eq 'D') {
        foreach ($path in @($env:GITHUB_WORKSPACE, $env:RUNNER_TEMP, $env:TEMP) | Select-Object -Unique) {
            try {
                Add-MpPreference -ExclusionPath $path -ErrorAction Stop
                $commands.Add(@{command = 'Add-MpPreference -ExclusionPath'; path = $path; status = 'success'})
            } catch { $commands.Add(@{command = 'Add-MpPreference -ExclusionPath'; path = $path; error = $_.Exception.ToString()}) }
        }
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            $commands.Add(@{command = 'DisableRealtimeMonitoring'; status = 'success'})
        } catch { $commands.Add(@{command = 'DisableRealtimeMonitoring'; error = $_.Exception.ToString()}) }
        try {
            Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction Stop
            $commands.Add(@{command = 'MAPSReporting 0 SubmitSamplesConsent 2'; status = 'success'})
        } catch { $commands.Add(@{command = 'MAPSReporting 0 SubmitSamplesConsent 2'; error = $_.Exception.ToString()}) }
    } else {
        foreach ($framework in @('Framework64', 'Framework', 'FrameworkArm64')) {
            $ngen = Join-Path $env:WINDIR "Microsoft.NET/$framework/v4.0.30319/ngen.exe"
            if (Test-Path $ngen) {
                $output = & $ngen executeQueuedItems 2>&1 | Out-String
                $commands.Add(@{command = $ngen; exit_code = $LASTEXITCODE; output = $output})
            }
        }
    }
    $clock.Stop()
    $receipt.remedies.Add([ordered]@{kind = $Kind; wall_seconds = $clock.Elapsed.TotalSeconds; commands = $commands})
    Save-Receipt
}
try {
    Invoke-Probe 0
    if ($Order -eq 'control') {
        foreach ($stage in 1..2) {
            $receipt.remedies.Add(@{kind = 'control_no_remedy'; wall_seconds = 0; matching_stage = $stage})
            Start-Sleep -Seconds $receipt.remedy_slot_seconds
            Invoke-Probe $stage
        }
    } else {
        $stage = 1
        foreach ($kind in $Order.ToCharArray()) {
            Invoke-Remedy ([string]$kind)
            $remaining = $receipt.remedy_slot_seconds - $receipt.remedies[-1].wall_seconds
            if ($remaining -gt 0) { Start-Sleep -Seconds $remaining }
            Invoke-Probe $stage
            $stage++
        }
    }
    $receipt.status = 'completed'
} catch {
    $receipt.status = 'failed'
    $receipt.error = $_.Exception.ToString()
    throw
} finally {
    $receipt.finished_utc = [DateTime]::UtcNow.ToString('o')
    Save-Receipt
}
$bad = @($receipt.probes | ForEach-Object { $_.launches } | Where-Object {
    $_.killed -or $_.exit_code -ne 0 -or ($_.kind -eq 'marker' -and -not $_.marker_body)
})
if ($bad.Count -gt 0) { throw "$($bad.Count) launches failed their execution check; timings cannot certify a remedy" }
