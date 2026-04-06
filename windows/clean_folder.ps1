param(
    [Parameter(Mandatory = $true)]
    [string]$Dir,

    [string]$QuarantineRoot = "C:\Quarantine"
)

function Move-DirectoryToQuarantine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$QuarantineRoot
    )

    Write-Host "`n========== Source Directory: $SourcePath ==========" -ForegroundColor Cyan

    if (-not (Test-Path $SourcePath)) {
        Write-Host "Source directory does not exist: $SourcePath" -ForegroundColor Yellow
        return
    }

    try {
        Write-Host "Taking ownership of source directory: $SourcePath" -ForegroundColor Gray
        takeown /f $SourcePath /r /d y | Out-Null

        Write-Host "Granting Administrators full control on source directory: $SourcePath" -ForegroundColor Gray
        icacls $SourcePath /grant Administrators:F /t /c | Out-Null

        $folderName = Split-Path $SourcePath -Leaf
        $destinationPath = Join-Path $QuarantineRoot $folderName

        if (Test-Path $destinationPath) {
            $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $destinationPath = Join-Path $QuarantineRoot "${folderName}_$stamp"
        }

        Write-Host "Preparing to move directory '$SourcePath' to '$destinationPath'" -ForegroundColor DarkCyan
        $answer = Read-Host "Move entire folder and all contents to quarantine? (Y/N)"

        if ($answer -match '^[Yy]$') {
            Move-Item -Path $SourcePath -Destination $destinationPath -Force -ErrorAction Stop
            Write-Host "Quarantined directory '$SourcePath' to '$destinationPath'" -ForegroundColor Green
        }
        else {
            Write-Host "Skipped directory: $SourcePath" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "Failed while processing source directory: $SourcePath" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

if (-not (Test-Path $QuarantineRoot)) {
    Write-Host "Creating quarantine root: $QuarantineRoot" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $QuarantineRoot -Force | Out-Null
}

Move-DirectoryToQuarantine -SourcePath $Dir -QuarantineRoot $QuarantineRoot