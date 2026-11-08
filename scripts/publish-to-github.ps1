[CmdletBinding()]
param(
    [string]$RepositoryUrl = "https://github.com/miserymart58-del/system-scanner-cyber-command.git"
)
$ErrorActionPreference = 'Stop'
$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("system-scanner-publish-" + [guid]::NewGuid().ToString('N'))

function Invoke-Git {
    param([Parameter(Mandatory=$true)][string[]]$GitArgs)
    & git @GitArgs
    if ($LASTEXITCODE -ne 0) { throw "Git failed: git $($GitArgs -join ' ')" }
}

try {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "Git for Windows is required."
    }
    Write-Host "Cloning the existing repository and preserving its history..." -ForegroundColor Cyan
    Invoke-Git @('clone', $RepositoryUrl, $TempRoot)

    $branch = (& git -C $TempRoot branch --show-current).Trim()
    if (-not $branch) { throw "Could not determine the cloned default branch." }

    $rootFiles = @(
        'README.md','SECURITY.md','CONTRIBUTING.md','.gitignore','CHANGELOG.md',
        'index.html','server.py','collector.ps1','live.ps1','run.bat','sample-report.json'
    )
    foreach ($name in $rootFiles) {
        $src = Join-Path $SourceRoot $name
        if (Test-Path -LiteralPath $src -PathType Leaf) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $TempRoot $name) -Force
        }
    }
    foreach ($name in @('assets','.github','scripts')) {
        $src = Join-Path $SourceRoot $name
        if (Test-Path -LiteralPath $src -PathType Container) {
            $dest = Join-Path $TempRoot $name
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            Copy-Item -Path (Join-Path $src '*') -Destination $dest -Recurse -Force
        }
    }

    $status = @(& git -C $TempRoot status --porcelain)
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect Git status." }
    if ($status.Count -eq 0) {
        Write-Host "No changes to publish." -ForegroundColor Green
        return
    }
    & git -C $TempRoot status --short
    if ($LASTEXITCODE -ne 0) { throw "Could not display pending changes." }

    $answer = Read-Host "Review the list above. Type PUSH to commit and push"
    if ($answer -cne 'PUSH') { throw "Cancelled; nothing was pushed." }

    Invoke-Git @('-C',$TempRoot,'add','--all')
    Invoke-Git @('-C',$TempRoot,'commit','-m','Add SYSTEM SCANNER V2 Cyber Command')
    Invoke-Git @('-C',$TempRoot,'push','-u','origin',$branch)
    Write-Host "Successfully pushed to $RepositoryUrl" -ForegroundColor Green
}
finally {
    if (Test-Path $TempRoot) {
        Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
