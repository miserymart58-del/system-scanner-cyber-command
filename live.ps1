# CYBER COMMAND live snapshot collector. It is launched only after the user
# separately enables live monitoring in the local dashboard. Read-only only.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$os = Get-CimInstance Win32_OperatingSystem
$totalMB = if ($os) { [math]::Round([double]$os.TotalVisibleMemorySize / 1024, 0) } else { $null }
$freeMB = if ($os) { [math]::Round([double]$os.FreePhysicalMemory / 1024, 0) } else { $null }
$cpuPct = $null
try {
    $counter = Get-Counter -Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
    $cpuPct = [math]::Round([double]$counter.CounterSamples[0].CookedValue, 1)
} catch { }

$top = @()
try {
    $top = @(Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 8 | ForEach-Object {
        [pscustomobject]@{
            name = [string]$_.ProcessName
            processId = [int]$_.Id
            memoryMB = [math]::Round([double]$_.WorkingSet64 / 1MB, 1)
            cpuSecondsTotal = if ($_.CPU -ne $null) { [math]::Round([double]$_.CPU, 1) } else { $null }
        }
    })
} catch { }

$volumes = @()
try {
    $volumes = @(Get-Volume | Where-Object { $_.DriveLetter -and $_.Size -gt 0 } | ForEach-Object {
        [pscustomobject]@{
            drive = "$($_.DriveLetter):"
            totalGB = [math]::Round([double]$_.Size / 1GB, 1)
            freeGB = [math]::Round([double]$_.SizeRemaining / 1GB, 1)
            freePercent = [math]::Round(([double]$_.SizeRemaining / [double]$_.Size) * 100, 1)
        }
    })
} catch { }

$networkBytes = [int64]0
try {
    foreach ($n in (Get-NetAdapterStatistics | Where-Object { $_.Name })) {
        $networkBytes += [int64]$n.ReceivedBytes + [int64]$n.SentBytes
    }
} catch { }

$result = [ordered]@{
    cpuPercent = $cpuPct
    memory = [ordered]@{ totalMB = $totalMB; availableMB = $freeMB; usedMB = if ($totalMB -ne $null -and $freeMB -ne $null) { [math]::Max(0, $totalMB - $freeMB) } else { $null } }
    topMemoryProcesses = $top
    volumes = $volumes
    networkBytesTotal = $networkBytes
    note = 'CPU is a one-second sample. Process CPU values are cumulative process CPU seconds, not instantaneous percentages. GPU temperature/load is not measured by this universal collector.'
}
ConvertTo-Json -InputObject $result -Depth 6 -Compress