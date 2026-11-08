<#
Windows System Health Scanner - local read-only collector

This script only runs when the local dashboard has received explicit consent for
its module. It does not upload data, read document contents, or change settings.
The optional DefenderQuickScan switch invokes Microsoft Defender; Defender may
quarantine/remediate according to the owner's existing Defender policy.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('security','processes','startup','storage','performance','integrity','browser')]
    [string]$Module,
    [switch]$DefenderQuickScan
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:Notes = New-Object 'System.Collections.Generic.List[string]'

function Add-Note {
    param([string]$Text)
    if (-not [string]::IsNullOrWhiteSpace($Text)) { $script:Notes.Add($Text) }
}

function Add-Finding {
    param(
        [ValidateSet('Critical','Warning','Info')][string]$Severity,
        [string]$Title,
        [string]$Explanation,
        [string]$Evidence,
        [string]$Action,
        [string]$Classification = 'Confirmed problem',
        [string]$Confidence = 'High'
    )
    $script:Findings.Add([pscustomobject]@{
        severity = $Severity
        title = $Title
        explanation = $Explanation
        evidence = $Evidence
        recommendedAction = $Action
        classification = $Classification
        confidence = $Confidence
    })
}

function Test-UserWritablePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($Path).Trim('"')
    $roots = @(
        $env:TEMP,
        $env:TMP,
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:LOCALAPPDATA 'Temp')
    ) | Where-Object { $_ }
    foreach ($root in $roots) {
        $r = [IO.Path]::GetFullPath($root).TrimEnd('\')
        if ($p.Equals($r, [StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith(($r + '\'), [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-ExecutableFromCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $raw = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($raw -match '^\s*"([^"]+)"') { return $Matches[1] }
    if ($raw -match '^\s*(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|msi))(?=\s|$)') { return $Matches[1].Trim('"') }
    return (($raw -split '\s+')[0]).Trim('"')
}

function Get-AdminStatus {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $null }
}

$data = [ordered]@{}

try {
    switch ($Module) {
        'security' {
            $avProviders = @()
            $providerQueryAvailable = $false
            try {
                $avProviders = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct | ForEach-Object { [pscustomobject]@{ name = [string]$_.DisplayName; productState = [string]$_.ProductState } })
                $providerQueryAvailable = $true
            } catch { Add-Note 'Registered antivirus providers could not be read from Windows Security Center.' }
            $data.antivirusProviders = $avProviders

            $defender = [ordered]@{ available = $false }
            try {
                $s = Get-MpComputerStatus
                $defender = [ordered]@{
                    available = $true
                    antivirusEnabled = [bool]$s.AntivirusEnabled
                    realTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
                    behaviorMonitorEnabled = [bool]$s.BehaviorMonitorEnabled
                    ioavProtectionEnabled = [bool]$s.IoavProtectionEnabled
                    signatureLastUpdated = if ($s.AntivirusSignatureLastUpdated) { $s.AntivirusSignatureLastUpdated.ToString('o') } else { $null }
                    amServiceEnabled = [bool]$s.AMServiceEnabled
                    runningMode = [string]$s.AMRunningMode
                }
                if (-not $s.AntivirusEnabled -or -not $s.RealTimeProtectionEnabled) {
                    $otherProviders = @($avProviders | Where-Object { $_.name -notmatch 'Microsoft Defender|Windows Defender' })
                    if ($otherProviders.Count -gt 0) {
                        Add-Finding 'Warning' 'Microsoft Defender protection is off; another provider is registered' 'Windows reports that Defender antivirus or real-time protection is off, while Windows Security Center lists another antivirus product. Confirm that the other product is active and up to date.' "AntivirusEnabled=$($s.AntivirusEnabled); RealTimeProtectionEnabled=$($s.RealTimeProtectionEnabled); Registered provider(s): $(($otherProviders.name) -join ', ')" 'Open Windows Security > Security providers and confirm that a trusted antivirus is active. Do not enable two real-time antivirus products at once.' 'Confirmed Defender state; alternative provider needs verification' 'Medium'
                    } elseif ($providerQueryAvailable) {
                        Add-Finding 'Warning' 'No antivirus provider is reported by Windows Security Center' 'Defender reports antivirus or real-time protection off, and Windows Security Center returned no alternative provider. Some managed or third-party security products may not register here, so verify your protection status in Windows Security.' "AntivirusEnabled=$($s.AntivirusEnabled); RealTimeProtectionEnabled=$($s.RealTimeProtectionEnabled); RunningMode=$($s.AMRunningMode); No alternative provider returned." 'Open Windows Security > Security providers and confirm that a trusted real-time protection product is active and up to date.' 'Confirmed reported state; actual protection needs verification' 'Medium'
                    } else {
                        Add-Finding 'Warning' 'Microsoft Defender protection appears disabled' 'Windows reports that Defender antivirus or real-time protection is off. The scanner could not verify whether another antivirus is registered.' "AntivirusEnabled=$($s.AntivirusEnabled); RealTimeProtectionEnabled=$($s.RealTimeProtectionEnabled)" 'Open Windows Security and verify that a trusted real-time antivirus is active and up to date.' 'Confirmed Defender state; overall protection needs review' 'Medium'
                    }
                }
                if ($s.AntivirusEnabled -and $s.AntivirusSignatureLastUpdated -and ((Get-Date) - $s.AntivirusSignatureLastUpdated).TotalDays -gt 7) {
                    Add-Finding 'Warning' 'Defender signatures may be stale' 'The installed Defender security intelligence is more than seven days old. This can reduce detection of newer threats.' "Last signature update: $($s.AntivirusSignatureLastUpdated)" 'Open Windows Security and check for protection updates. Confirm internet access and update status.' 'Confirmed age; cause needs review' 'High'
                }
            } catch {
                Add-Note 'Microsoft Defender status could not be read. Defender may be unavailable, managed by another security product, or require elevated access.'
            }
            $data.defender = $defender

            $firewall = @()
            try {
                $profiles = Get-NetFirewallProfile
                foreach ($p in $profiles) {
                    $firewall += [pscustomobject]@{ name = $p.Name; enabled = [bool]$p.Enabled }
                    if (-not $p.Enabled) {
                        Add-Finding 'Warning' "Windows Firewall is disabled for $($p.Name)" 'A Windows Firewall profile is reported as disabled. Another network firewall may exist, but this profile is not protecting traffic.' "Profile=$($p.Name); Enabled=$($p.Enabled)" 'Open Windows Security > Firewall & network protection and review the affected profile. Do not enable it blindly on a managed network; check with the administrator.' 'Confirmed configuration state' 'High'
                    }
                }
            } catch { Add-Note 'Windows Firewall profile status could not be read.' }
            $data.firewall = $firewall

            $enabledUsers = $null
            try { $enabledUsers = @(Get-LocalUser | Where-Object { $_.Enabled }).Count }
            catch {
                try { $enabledUsers = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Where-Object { $_.Disabled -eq $false }).Count }
                catch { Add-Note 'Local account count is unavailable with the current permissions.' }
            }
            $data.accountPosture = [ordered]@{
                currentUserIsAdministrator = Get-AdminStatus
                enabledLocalAccountCount = $enabledUsers
                note = 'Account names and passwords are not collected.'
            }

            $hostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
            $hostEntries = @()
            try {
                $hostEntries = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
                $data.hostsFile = [ordered]@{ path = $hostsPath; customEntryCount = $hostEntries.Count; entries = @($hostEntries | Select-Object -First 8) }
                if ($hostEntries.Count -gt 0) {
                    Add-Finding 'Info' 'Hosts file contains custom mappings' 'Custom hosts-file entries can be legitimate (for example, developer or ad-blocking settings). Review them if you did not add them.' "$($hostEntries.Count) non-comment line(s) found; first entries: $(($hostEntries | Select-Object -First 3) -join ' | ')" 'Compare the entries with changes you recognize. Do not delete mappings solely because they are present.' 'Possibly suspicious, needs review' 'Low'
                }
            } catch { Add-Note 'The Windows hosts file could not be read.' }

            $detections = @()
            try {
                $rawDetections = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10)
                foreach ($d in $rawDetections) {
                    $resources = @($d.Resources | ForEach-Object { [string]$_ } | Select-Object -First 3)
                    $detections += [pscustomobject]@{
                        threatId = [string]$d.ThreatID
                        initialDetectionTime = if ($d.InitialDetectionTime) { $d.InitialDetectionTime.ToString('o') } else { $null }
                        actionSuccess = $d.ActionSuccess
                        resources = $resources
                    }
                }
                if ($detections.Count -gt 0) {
                    $failed = @($rawDetections | Where-Object { $_.ActionSuccess -eq $false }).Count
                    $severity = if ($failed -gt 0) { 'Critical' } else { 'Warning' }
                    Add-Finding $severity 'Microsoft Defender has recorded threat detections' 'These are Defender protection-history records, not proof that a threat is still active. Check current quarantine and protection history in Windows Security.' "$($detections.Count) recent record(s); $failed record(s) report an unsuccessful action." 'Open Windows Security > Virus & threat protection > Protection history. Follow Defender guidance and run a full scan if appropriate.' 'Confirmed historical detection; current status needs review' 'High'
                }
            } catch { Add-Note 'Defender threat history could not be read.' }
            $data.recentDetections = $detections

            if ($DefenderQuickScan) {
                try {
                    if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
                        $null = Start-MpScan -ScanType QuickScan
                        $data.defenderQuickScan = [ordered]@{
                            requested = $true
                            result = 'Microsoft Defender accepted the Quick Scan request.'
                            caution = 'Defender may quarantine or remediate detections according to its existing policy. This action is separate from the read-only checks.'
                        }
                        Add-Note 'A Microsoft Defender Quick Scan was requested separately by the user. Defender controls the scan and any remediation.'
                    } else {
                        $data.defenderQuickScan = [ordered]@{ requested = $false; result = 'Start-MpScan is unavailable.' }
                    }
                } catch {
                    $data.defenderQuickScan = [ordered]@{ requested = $false; result = "Defender Quick Scan could not be started: $($_.Exception.Message)" }
                }
            } else {
                $data.defenderQuickScan = [ordered]@{ requested = $false; result = 'Not requested. No antivirus scan was launched.' }
            }
        }

        'processes' {
            $procs = @()
            $suspicious = @()
            try {
                $all = @(Get-CimInstance Win32_Process | Select-Object -First 1200)
                foreach ($p in $all) {
                    $path = [string]$p.ExecutablePath
                    $item = [pscustomobject]@{ name = [string]$p.Name; processId = [int]$p.ProcessId; path = $path }
                    $procs += $item
                    if ($path -and (Test-UserWritablePath $path)) {
                        $suspicious += $item
                        Add-Finding 'Warning' "Process running from a user-writable location: $($p.Name)" 'Programs can legitimately run from Downloads or AppData, but malware also commonly uses writable folders. A path alone cannot identify malware.' "PID=$($p.ProcessId); Path=$path" 'Verify the publisher and origin. Scan the exact file with Windows Security; do not terminate or delete it solely because of its location.' 'Possibly suspicious, needs review' 'Medium'
                    }
                }
            } catch { Add-Note 'The process inventory was partially or wholly unavailable.' }
            $data.processCount = $procs.Count
            $data.suspiciousLocationProcesses = @($suspicious | Select-Object -First 25)
            $data.processSample = @($procs | Select-Object -First 80)

            $connections = @()
            try {
                $nameByPid = @{}
                foreach ($p in $procs) { $nameByPid[[int]$p.processId] = $p.name }
                $tcp = @(Get-NetTCPConnection -State Established | Select-Object -First 100)
                foreach ($c in $tcp) {
                    $pidValue = [int]$c.OwningProcess
                    $connections += [pscustomobject]@{
                        process = if ($nameByPid.ContainsKey($pidValue)) { $nameByPid[$pidValue] } else { 'Unknown' }
                        processId = $pidValue
                        localAddress = [string]$c.LocalAddress
                        localPort = [int]$c.LocalPort
                        remoteAddress = [string]$c.RemoteAddress
                        remotePort = [int]$c.RemotePort
                        state = [string]$c.State
                    }
                }
            } catch { Add-Note 'Established TCP connections could not be inventoried; the networking cmdlet may be unavailable.' }
            $data.establishedConnections = $connections
            Add-Note 'Network connections are shown as an inventory only. A public IP address or an established connection is not, by itself, evidence of malicious activity.'

            $riskyExtensions = @('.exe','.msi','.scr','.bat','.cmd','.ps1','.vbs','.js','.hta','.com','.dll','.lnk','.reg','.psm1')
            $riskyFiles = @()
            $scanDirs = @((Join-Path $env:USERPROFILE 'Downloads'), $env:TEMP) | Select-Object -Unique
            foreach ($dir in $scanDirs) {
                if (Test-Path -LiteralPath $dir) {
                    try {
                        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue | Where-Object { $riskyExtensions -contains $_.Extension.ToLowerInvariant() } | Select-Object -First 25)) {
                            $riskyFiles += [pscustomobject]@{ name = $f.Name; folder = $dir; fullPath = $f.FullName; sizeBytes = [int64]$f.Length; extension = $f.Extension; sizeMB = [math]::Round($f.Length / 1MB, 2); lastWrite = $f.LastWriteTime.ToString('o') }
                        }
                    } catch { Add-Note "Could not inspect file metadata in $dir." }
                }
            }
            $data.riskyExtensionFiles = @($riskyFiles | Select-Object -First 40)
            if ($riskyFiles.Count -gt 0) {
                Add-Finding 'Warning' 'Executable or script files found in Downloads/Temp' 'These file types can run code. Their presence is common and does not mean they are infected; verify the source and scan files you do not recognize.' "$($riskyFiles.Count) matching file(s) found in the top level of Downloads and Temp." 'Do not open unknown files. Use Microsoft Defender to scan them and remove only files you can identify as unwanted.' 'Possibly suspicious, needs review' 'Low'
            }
        }

        'startup' {
            $items = @()
            $runKeys = @(
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
            )
            foreach ($key in $runKeys) {
                if (Test-Path $key) {
                    try {
                        $props = Get-ItemProperty -Path $key
                        foreach ($prop in $props.PSObject.Properties) {
                            if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' -and $prop.Value) {
                                $exe = Get-ExecutableFromCommand ([string]$prop.Value)
                                $valueFingerprint = ''
                                if ($prop.Value -is [string]) {
                                    $sha = [Security.Cryptography.SHA256]::Create()
                                    $valueFingerprint = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$prop.Value)))).Replace('-', '').ToLowerInvariant()
                                    $sha.Dispose()
                                }
                                $item = [pscustomobject]@{ type = 'Registry Run'; name = $prop.Name; valueName = $prop.Name; source = $key; executable = $exe; valueFingerprint = $valueFingerprint }
                                $items += $item
                                if (Test-UserWritablePath $exe) {
                                    Add-Finding 'Warning' "Startup item runs from a user-writable path: $($prop.Name)" 'This location is writable by the current user and deserves verification. Legitimate applications sometimes use it too.' "$($prop.Name) -> $exe" 'Check the publisher and whether you recognize the application. Do not disable security, driver, accessibility, or work-managed entries.' 'Possibly suspicious, needs review' 'Medium'
                                }
                            }
                        }
                    } catch { Add-Note "Could not read startup registry key: $key" }
                }
            }

            $startupDirs = @((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'), (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'))
            foreach ($dir in $startupDirs) {
                if (Test-Path $dir) {
                    try {
                        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue)) {
                            $items += [pscustomobject]@{ type = 'Startup folder'; name = $f.Name; source = $dir; executable = $f.FullName; fullPath = $f.FullName; sizeBytes = [int64]$f.Length; lastWrite = $f.LastWriteTime.ToString('o') }
                        }
                    } catch { Add-Note "Could not enumerate startup folder: $dir" }
                }
            }

            $tasks = @()
            try {
                foreach ($t in (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object -First 60)) {
                    foreach ($a in $t.Actions) {
                        $exe = [string]$a.Execute
                        $task = [pscustomobject]@{ name = $t.TaskName; taskPath = $t.TaskPath; state = [string]$t.State; executable = $exe }
                        $tasks += $task
                        if (Test-UserWritablePath $exe) {
                            Add-Finding 'Warning' "Scheduled task action uses a user-writable path: $($t.TaskName)" 'Scheduled tasks can be used by legitimate updaters, but an action launching from a writable folder should be reviewed.' "Task=$($t.TaskPath)$($t.TaskName); Executable=$exe" 'Open Task Scheduler, inspect the task publisher and trigger, and disable it only if you recognize it as unwanted.' 'Possibly suspicious, needs review' 'Medium'
                        }
                    }
                }
            } catch { Add-Note 'Scheduled task inventory was unavailable or incomplete.' }

            $services = @()
            try {
                foreach ($s in (Get-CimInstance Win32_Service -Filter "StartMode='Auto'" | Select-Object -First 80)) {
                    $exe = Get-ExecutableFromCommand ([string]$s.PathName)
                    $services += [pscustomobject]@{ name = $s.Name; displayName = $s.DisplayName; state = $s.State; startMode = $s.StartMode; executable = $exe }
                    if (Test-UserWritablePath $exe) {
                        Add-Finding 'Warning' "Automatic service uses a user-writable path: $($s.Name)" 'Services that start automatically from writable folders are worth checking. Some vendor software may use non-standard paths.' "$($s.Name); State=$($s.State); Executable=$exe" 'Verify its publisher and purpose. Do not stop or disable Windows, security, storage, network, or driver services based on this flag alone.' 'Possibly suspicious, needs review' 'Medium'
                    }
                }
            } catch { Add-Note 'Automatic service inventory could not be read.' }

            $data.startupItems = @($items | Select-Object -First 100)
            $data.nonMicrosoftScheduledTasks = $tasks
            $data.automaticServices = $services
            $impactLevel = if ($items.Count -gt 15) { 'Potentially high' } elseif ($items.Count -gt 8) { 'Potentially moderate' } else { 'No high-count signal' }
            $data.counts = [ordered]@{ startupEntries = $items.Count; scheduledTaskActions = $tasks.Count; automaticServices = $services.Count }
            $data.impactEstimate = [ordered]@{ level = $impactLevel; basis = 'Heuristic from the count of Run-key and Startup-folder entries only; boot-time impact was not measured.' }
            if ($items.Count -gt 15) {
                Add-Finding 'Info' 'Many startup entries are configured' 'A large startup list can increase sign-in time and background activity. This is a performance clue, not evidence of malware.' "$($items.Count) Run-key and Startup-folder item(s) detected." 'Review applications you recognize and turn off only non-essential launch-at-login options in each app or Windows Settings.' 'Performance observation' 'Medium'
            }
        }

        'storage' {
            $volumes = @()
            try {
                foreach ($v in (Get-Volume | Where-Object { $_.DriveLetter -or $_.Path })) {
                    if ($v.Size -gt 0) {
                        $used = [double]($v.Size - $v.SizeRemaining)
                        $freePct = [math]::Round(($v.SizeRemaining / [double]$v.Size) * 100, 1)
                        $volumes += [pscustomobject]@{
                            drive = if ($v.DriveLetter) { "$($v.DriveLetter):" } else { [string]$v.Path }
                            label = [string]$v.FileSystemLabel
                            fileSystem = [string]$v.FileSystem
                            totalGB = [math]::Round($v.Size / 1GB, 1)
                            usedGB = [math]::Round($used / 1GB, 1)
                            freeGB = [math]::Round($v.SizeRemaining / 1GB, 1)
                            freePercent = $freePct
                        }
                        if (($v.SizeRemaining / 1GB) -lt 5 -or $freePct -lt 10) {
                            Add-Finding 'Warning' "Low free space on $($v.DriveLetter):" 'A drive with very little free space can slow updates, temporary work, and applications. The threshold is a practical warning, not a disk failure diagnosis.' "Free=$([math]::Round($v.SizeRemaining/1GB,1)) GB; $freePct% free." 'Empty Recycle Bin, remove temporary files through Windows Settings > System > Storage, and move personal files only after backing them up.' 'Confirmed capacity condition' 'High'
                        }
                    }
                }
            } catch { Add-Note 'Drive capacity information could not be read.' }
            $data.volumes = $volumes

            # A bounded metadata-only walk of common user folders. No file contents
            # are opened; reparse points are skipped to avoid traversing junctions.
            $targets = @(
                (Join-Path $env:USERPROFILE 'Desktop'),
                (Join-Path $env:USERPROFILE 'Downloads'),
                (Join-Path $env:USERPROFILE 'Documents'),
                (Join-Path $env:USERPROFILE 'Pictures'),
                (Join-Path $env:USERPROFILE 'Videos'),
                $env:TEMP
            ) | Select-Object -Unique
            $folderStats = @()
            $largeFiles = New-Object System.Collections.ArrayList
            $totalVisited = 0
            $partial = $false
            $watch = [Diagnostics.Stopwatch]::StartNew()
            foreach ($target in $targets) {
                if (-not $target -or -not (Test-Path -LiteralPath $target)) { continue }
                $sumBytes = [int64]0
                $folderVisited = 0
                $stack = New-Object 'System.Collections.Generic.Stack[string]'
                $stack.Push($target)
                while ($stack.Count -gt 0) {
                    if ($watch.Elapsed.TotalSeconds -gt 18 -or $totalVisited -ge 12000) { $partial = $true; break }
                    $current = $stack.Pop()
                    try {
                        foreach ($filePath in [IO.Directory]::EnumerateFiles($current)) {
                            if ($watch.Elapsed.TotalSeconds -gt 18 -or $totalVisited -ge 12000) { $partial = $true; break }
                            try {
                                $fi = [System.IO.FileInfo]::new($filePath)
                                $len = [int64]$fi.Length
                                $sumBytes += $len
                                $totalVisited++
                                $folderVisited++
                                if ($len -ge 512MB -and $largeFiles.Count -lt 30) {
                                    $ageDays = [math]::Round(((Get-Date) - $fi.LastWriteTime).TotalDays, 0)
                                    $null = $largeFiles.Add([pscustomobject]@{ name = $fi.Name; folder = $target; path = $fi.FullName; sizeBytes = $len; sizeGB = [math]::Round($len / 1GB, 2); lastWrite = $fi.LastWriteTime.ToString('o'); ageDays = $ageDays })
                                }
                            } catch { }
                        }
                        foreach ($sub in [IO.Directory]::EnumerateDirectories($current)) {
                            try {
                                $attrs = [IO.File]::GetAttributes($sub)
                                if (($attrs -band [IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($sub) }
                            } catch { }
                        }
                    } catch { }
                    if ($partial) { break }
                }
                $folderStats += [pscustomobject]@{ folder = $target; scannedFileCount = $folderVisited; scannedSizeGB = [math]::Round($sumBytes / 1GB, 2); partial = $partial }
                if ($partial) { break }
            }
            $watch.Stop()
            $data.folderMetadataScan = [ordered]@{ folders = $folderStats; filesVisited = $totalVisited; durationSeconds = [math]::Round($watch.Elapsed.TotalSeconds,1); partial = $partial; scope = 'Common folders in the current user profile and the current temporary folder; metadata only.' }
            $data.largeFiles = @($largeFiles | Sort-Object sizeGB -Descending | Select-Object -First 20)

            # Top-level old temporary files are cleanup candidates, not threats.
            # Only file metadata is read; directories and file contents are skipped.
            $tempCleanup = @()
            try {
                $tempCutoff = (Get-Date).AddDays(-14)
                foreach ($tf in (Get-ChildItem -LiteralPath $env:TEMP -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $tempCutoff } | Sort-Object LastWriteTime | Select-Object -First 30)) {
                    $tempCleanup += [pscustomobject]@{
                        name = $tf.Name
                        path = $tf.FullName
                        folder = $env:TEMP
                        sizeBytes = [int64]$tf.Length
                        sizeMB = [math]::Round($tf.Length / 1MB, 2)
                        lastWrite = $tf.LastWriteTime.ToString('o')
                        ageDays = [math]::Round(((Get-Date) - $tf.LastWriteTime).TotalDays, 0)
                    }
                }
            } catch { Add-Note 'Temporary-file cleanup metadata could not be enumerated.' }
            $data.tempCleanupCandidates = $tempCleanup
            if ($tempCleanup.Count -gt 0) { Add-Note 'Older temporary files are listed as optional cleanup candidates only. Age does not prove a file is safe to remove; review individually and skip files used by active applications.' }

            if ($partial) { Add-Note 'The folder metadata scan reached its time or file-count limit. Folder sizes and large-file candidates may be incomplete.' }
            if ($largeFiles.Count -gt 0) {
                $oldLarge = @($largeFiles | Where-Object { $_.ageDays -gt 180 })
                if ($oldLarge.Count -gt 0) {
                    Add-Finding 'Info' 'Large files older than six months were found' 'Old large files can be cleanup candidates, but they may be important. The scanner did not open their contents.' "$($oldLarge.Count) file(s) at least 512 MB and older than 180 days were identified." 'Review each file and confirm it is backed up and no longer needed before moving or deleting it.' 'Cleanup candidate, not a confirmed problem' 'Medium'
                }
            }
            Add-Note 'Duplicate-file detection is not performed: this version does not hash or read file contents.'

            try {
                $physical = @()
                foreach ($d in (Get-PhysicalDisk)) {
                    $health = [string]$d.HealthStatus
                    $entry = [ordered]@{ friendlyName = [string]$d.FriendlyName; mediaType = [string]$d.MediaType; healthStatus = $health; operationalStatus = [string]($d.OperationalStatus -join ', '); sizeGB = [math]::Round($d.Size / 1GB,1); reliability = $null }
                    try {
                        $r = Get-StorageReliabilityCounter -PhysicalDisk $d
                        $entry.reliability = [ordered]@{ temperatureC = $r.Temperature; wearPercent = $r.Wear; powerOnHours = $r.PowerOnHours; readErrorsTotal = $r.ReadErrorsTotal; writeErrorsTotal = $r.WriteErrorsTotal }
                    } catch { }
                    $physical += [pscustomobject]$entry
                    if ($health -and $health -notin @('Healthy','Unknown')) {
                        Add-Finding 'Warning' "Storage device reports health status: $health" 'Windows Storage reports a non-Healthy status for this physical disk. Back up important files and investigate the device health.' "$($d.FriendlyName); Health=$health; Operational=$($d.OperationalStatus -join ', ')" 'Back up important data promptly and use the device manufacturer diagnostics or a technician to confirm drive health.' 'Confirmed device status; diagnosis needs confirmation' 'Medium'
                    }
                }
                $data.physicalDisks = $physical
            } catch { $data.physicalDisks = @(); Add-Note 'Physical disk health / SMART-style counters are unavailable on this device or with the current driver.' }
        }

        'performance' {
            $os = Get-CimInstance Win32_OperatingSystem
            $totalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
            $availableMB = [math]::Round($os.FreePhysicalMemory / 1024, 0)
            $usedMB = [math]::Max(0, $totalMB - $availableMB)
            $availablePct = if ($totalMB -gt 0) { [math]::Round(($availableMB / $totalMB) * 100, 1) } else { 0 }

            $first = @{}
            foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
                try { $first[[int]$p.Id] = [pscustomobject]@{ cpu = [double]$p.CPU; workingSet = [int64]$p.WorkingSet64; name = $p.ProcessName } } catch { }
            }
            Start-Sleep -Seconds 1
            $second = @{}
            foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
                try { $second[[int]$p.Id] = [pscustomobject]@{ cpu = [double]$p.CPU; workingSet = [int64]$p.WorkingSet64; name = $p.ProcessName } } catch { }
            }
            $cpuCount = [math]::Max(1, [int]$env:NUMBER_OF_PROCESSORS)
            $cpuTop = @()
            foreach ($id in $second.Keys) {
                if ($first.ContainsKey($id)) {
                    $delta = [math]::Max(0, $second[$id].cpu - $first[$id].cpu)
                    $pct = [math]::Round(($delta / $cpuCount) * 100, 1)
                    if ($pct -gt 0) { $cpuTop += [pscustomobject]@{ name = $second[$id].name; processId = $id; cpuPercentSampled = $pct } }
                }
            }
            $cpuTop = @($cpuTop | Sort-Object cpuPercentSampled -Descending | Select-Object -First 10)

            $memoryTop = @($second.GetEnumerator() | ForEach-Object { [pscustomobject]@{ name = $_.Value.name; processId = $_.Key; workingSetMB = [math]::Round($_.Value.workingSet / 1MB, 1) } } | Sort-Object workingSetMB -Descending | Select-Object -First 12)

            # A short three-second sample only identifies growth candidates; it
            # cannot prove a memory leak.
            $sampleStart = @{}
            foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { try { $sampleStart[[int]$p.Id] = [int64]$p.WorkingSet64 } catch { } }
            Start-Sleep -Seconds 1
            Start-Sleep -Seconds 1
            $growth = @()
            foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
                try {
                    $id = [int]$p.Id
                    if ($sampleStart.ContainsKey($id)) {
                        $deltaMB = [math]::Round(($p.WorkingSet64 - $sampleStart[$id]) / 1MB, 1)
                        if ($deltaMB -ge 100) { $growth += [pscustomobject]@{ name = $p.ProcessName; processId = $id; growthMBInAbout2Seconds = $deltaMB } }
                    }
                } catch { }
            }
            $pagefile = @()
            try {
                foreach ($p in (Get-CimInstance Win32_PageFileUsage)) {
                    $pagefile += [pscustomobject]@{ name = $p.Name; allocatedMB = $p.AllocatedBaseSize; currentUsageMB = $p.CurrentUsage; peakUsageMB = $p.PeakUsage }
                }
            } catch { Add-Note 'Pagefile usage counters are unavailable.' }

            $data.memory = [ordered]@{ totalMB = $totalMB; usedMB = $usedMB; availableMB = $availableMB; availablePercent = $availablePct }
            $data.topMemoryProcesses = $memoryTop
            $data.topCpuProcesses = $cpuTop
            $data.memoryGrowthCandidates = @($growth | Sort-Object growthMBInAbout2Seconds -Descending | Select-Object -First 8)
            $data.pagefile = $pagefile
            $data.cpuSampleDurationSeconds = 1

            if ($availableMB -lt 1024 -or $availablePct -lt 10) {
                Add-Finding 'Warning' 'Low available physical memory at sample time' 'Windows reported low available RAM. This can cause paging and application lag, but memory pressure can be temporary.' "Available=$availableMB MB of $totalMB MB ($availablePct%)." 'Close applications you recognize but are not using; then recheck. If memory remains low during normal use, compare typical workload with installed RAM before considering an upgrade.' 'Confirmed snapshot; persistent pressure needs retesting' 'Medium'
            }
            if ($growth.Count -gt 0) {
                Add-Finding 'Info' 'A process showed rapid working-set growth in a short sample' 'This is only a two-second observation. App startup, file loading, or caching can cause temporary growth; it does not prove a memory leak.' "Process candidate(s): $(($growth | Select-Object -First 3 | ForEach-Object { "$($_.name) +$($_.growthMBInAbout2Seconds) MB" }) -join ', ')" 'Repeat the measurement during the slowdown. Update or troubleshoot the application only if the growth continues over time.' 'Possibly transient; needs repeat measurement' 'Low'
            }
            Add-Note 'CPU usage is estimated from a one-second process CPU-time sample. Memory growth candidates use about a two-second sample; neither is a long-term trend.'
        }

        'integrity' {
            $os = Get-CimInstance Win32_OperatingSystem
            $data.os = [ordered]@{ caption = [string]$os.Caption; version = [string]$os.Version; build = [string]$os.BuildNumber; architecture = [string]$os.OSArchitecture; lastBoot = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('o') } else { $null } }
            $data.currentUserIsAdministrator = Get-AdminStatus

            $latestHotfix = $null
            try {
                $hotfix = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
                if ($hotfix) { $latestHotfix = [ordered]@{ hotFixId = $hotfix.HotFixID; installedOn = ([datetime]$hotfix.InstalledOn).ToString('yyyy-MM-dd'); description = $hotfix.Description } }
            } catch { Add-Note 'Installed hotfix metadata could not be read.' }
            $data.latestInstalledHotfix = $latestHotfix
            if ($latestHotfix) {
                try {
                    $patchDate = [datetime]::Parse($latestHotfix.installedOn)
                    if (((Get-Date) - $patchDate).TotalDays -gt 60) {
                        Add-Finding 'Info' 'Latest listed hotfix is more than 60 days old' 'This is a reminder to check Windows Update, not proof that updates are missing. Some update channels and cumulative update records are not represented by Get-HotFix.' "Latest Get-HotFix record: $($latestHotfix.hotFixId), $($latestHotfix.installedOn)." 'Open Settings > Windows Update > Check for updates and review update history.' 'Needs update-status verification' 'Low'
                    }
                } catch { }
            }

            $pending = $false
            $pendingKeys = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            )
            foreach ($k in $pendingKeys) { if (Test-Path $k) { $pending = $true } }
            try {
                $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
                if ($sm.PendingFileRenameOperations) { $pending = $true }
            } catch { }
            $data.pendingRebootIndicator = $pending
            if ($pending) { Add-Finding 'Info' 'Windows reports a pending-restart indicator' 'Some updates or driver changes require a restart to finish. This is usually straightforward but may affect stability until completed.' 'One or more standard Windows pending-reboot registry indicators are present.' 'Save your work and restart at a convenient time. Do not interrupt an update that is already applying.' 'Confirmed configuration indicator' 'High' }

            try {
                $users = @(Get-LocalUser)
                $enabled = @($users | Where-Object { $_.Enabled }).Count
                $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop).Count
                $data.localAccounts = [ordered]@{ total = $users.Count; enabled = $enabled; localAdministrators = $admins; namesCollected = $false }
            } catch { Add-Note 'Local account and administrator-group counts could not be read.' }

            # Installed software inventory from uninstall registry metadata only.
            # Win32_Product is deliberately avoided because querying it can trigger MSI repair checks.
            $programs = @()
            $uninstallKeys = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            foreach ($key in $uninstallKeys) {
                try {
                    foreach ($app in (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object -First 200)) {
                        $programs += [pscustomobject]@{
                            name = [string]$app.DisplayName
                            version = [string]$app.DisplayVersion
                            publisher = [string]$app.Publisher
                            installDate = [string]$app.InstallDate
                        }
                    }
                } catch { Add-Note 'Some installed-program registry metadata could not be read.' }
            }
            $data.installedPrograms = @($programs | Sort-Object name -Unique | Select-Object -First 200)
            $data.installedProgramCount = $programs.Count

            $eventRows = @()
            $since = (Get-Date).AddDays(-7)
            foreach ($logName in @('System','Application')) {
                try {
                    foreach ($ev in (Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1,2); StartTime = $since } -MaxEvents 15 -ErrorAction Stop)) {
                        $eventRows += [pscustomobject]@{ log = $logName; time = $ev.TimeCreated.ToString('o'); level = if ($ev.Level -eq 1) { 'Critical' } else { 'Error' }; eventId = $ev.Id; provider = [string]$ev.ProviderName }
                    }
                } catch { }
            }
            $data.recentSystemErrors = @($eventRows | Sort-Object time -Descending | Select-Object -First 25)
            if ($eventRows.Count -gt 15) {
                Add-Finding 'Info' 'Multiple system/application error events were logged' 'Windows logs record errors for many normal software and driver events. Review repeating providers and timestamps around the slowdown; this count alone does not identify a root cause.' "$($eventRows.Count) critical/error events were returned from System and Application logs in the last seven days (up to 25 shown)." 'Open Event Viewer and look for repeated events at the time problems occur. Avoid changing drivers or services based on a single event.' 'Diagnostic evidence; cause needs review' 'Low'
            }
        }

        'browser' {
            $extensions = @()
            $roots = @(
                [pscustomobject]@{ browser = 'Google Chrome'; root = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') },
                [pscustomobject]@{ browser = 'Microsoft Edge'; root = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') }
            )
            foreach ($b in $roots) {
                if (Test-Path $b.root) {
                    try {
                        foreach ($profile in (Get-ChildItem -LiteralPath $b.root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
                            $extRoot = Join-Path $profile.FullName 'Extensions'
                            if (Test-Path $extRoot) {
                                foreach ($idDir in (Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue)) {
                                    foreach ($versionDir in (Get-ChildItem -LiteralPath $idDir.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 2)) {
                                        $manifestPath = Join-Path $versionDir.FullName 'manifest.json'
                                        if (Test-Path $manifestPath) {
                                            try {
                                                $m = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
                                                $perms = @(@($m.permissions) + @($m.host_permissions) + @($m.optional_permissions) + @($m.optional_host_permissions) | Where-Object { $_ } | Select-Object -First 24)
                                                $extensions += [pscustomobject]@{ browser = $b.browser; profile = $profile.Name; id = $idDir.Name; name = [string]$m.name; version = [string]$m.version; manifestVersion = $m.manifest_version; permissions = $perms }
                                            } catch { }
                                        }
                                    }
                                }
                            }
                        }
                    } catch { Add-Note "Could not fully read $($b.browser) extension metadata." }
                }
            }
            $firefoxRoot = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
            if (Test-Path $firefoxRoot) {
                try {
                    foreach ($profile in (Get-ChildItem -LiteralPath $firefoxRoot -Directory -ErrorAction SilentlyContinue)) {
                        $jsonPath = Join-Path $profile.FullName 'extensions.json'
                        if (Test-Path $jsonPath) {
                            try {
                                $json = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
                                foreach ($a in $json.addons) {
                                    $perms = @($a.permissions | ForEach-Object { [string]$_ } | Select-Object -First 24)
                                    $extensions += [pscustomobject]@{ browser = 'Mozilla Firefox'; profile = $profile.Name; id = [string]$a.id; name = [string]$a.defaultLocale.name; version = [string]$a.version; active = [bool]$a.active; permissions = $perms }
                                }
                            } catch { }
                        }
                    }
                } catch { Add-Note 'Could not fully read Firefox extension metadata.' }
            }
            $data.extensions = @($extensions | Select-Object -First 150)
            $data.extensionCount = $extensions.Count
            foreach ($e in $extensions) {
                $permText = @($e.permissions | ForEach-Object { [string]$_ })
                $broad = @($permText | Where-Object { $_ -in @('<all_urls>','cookies','history','webRequest','webRequestBlocking','debugger','nativeMessaging','management') })
                if ($broad.Count -gt 0) {
                    Add-Finding 'Info' 'Browser extension requests powerful permissions' 'Some browser permissions can allow broad access to tabs, browsing activity or browser integration. These permissions can be legitimate; verify that you recognize the extension and trust its publisher.' "$($e.browser) / $($e.profile): $($e.name) ($($e.id)); permission(s): $($broad -join ', ')" 'Review the extension in the browser settings. Remove it only if you do not recognize it or no longer need it.' 'Possibly sensitive extension, needs review' 'Low'
                }
            }
            Add-Note 'Only extension metadata and declared permission names were inspected. Browser history, saved passwords, cookies, and page contents were not read.'
            if ($extensions.Count -eq 0) { Add-Note 'No supported Chrome, Edge, or Firefox extension metadata was found, or the relevant browser profiles were unavailable.' }
        }
    }
} catch {
    Add-Note "Module collector error: $($_.Exception.Message)"
    $result = [ordered]@{
        module = $Module
        status = 'error'
        data = $data
        findings = @($script:Findings.ToArray())
        notes = @($script:Notes.ToArray())
        completedAt = (Get-Date).ToString('o')
    }
    ConvertTo-Json -InputObject $result -Depth 10 -Compress
    exit 0
}

$result = [ordered]@{
    module = $Module
    status = 'ok'
    data = $data
    findings = @($script:Findings.ToArray())
    notes = @($script:Notes.ToArray())
    completedAt = (Get-Date).ToString('o')
}
ConvertTo-Json -InputObject $result -Depth 10 -Compress