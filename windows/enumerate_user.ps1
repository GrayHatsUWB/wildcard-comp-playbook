$suspiciousExtensions = @(
    ".zip", ".7z", ".rar",
    ".mp3", ".mp4", ".wav", ".flac",
    ".exe", ".bat", ".ps1", ".py", ".sh",
    ".txt", ".pcap", ".pcapng", ".cap",
    ".bin", ".iso"
)

$quarantineRoot = "C:\Quarantine"

if (-not (Test-Path $quarantineRoot)) {
    New-Item -Path $quarantineRoot -ItemType Directory | Out-Null
}

$users = Get-ChildItem "C:\Users" -Directory

foreach ($user in $users) {
    Write-Host "`n========== $($user.Name) ==========" -ForegroundColor Cyan

    $folders = @(
        "Desktop", "Documents", "Downloads", "Music",
        "Videos", "Pictures", "Favorites"
    )

    foreach ($folder in $folders) {
        $fullPath = Join-Path $user.FullName $folder

        if (Test-Path $fullPath) {
            $files = Get-ChildItem -Path $fullPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $suspiciousExtensions -contains $_.Extension.ToLower() } |
                Sort-Object Extension, FullName

            if ($files) {
                Write-Host "`n  [$folder]" -ForegroundColor Yellow

                foreach ($file in $files) {
                    $sizeMB = [math]::Round($file.Length / 1MB, 2)

                    Write-Host "`nFile found:" -ForegroundColor Magenta
                    Write-Host "Path: $($file.FullName)"
                    Write-Host "Ext : $($file.Extension)"
                    Write-Host "Size: $sizeMB MB"
                    Write-Host "Date: $($file.LastWriteTime)"

                    $response = Read-Host "Move this file to quarantine? (Y/N)"

                    if ($response -match '^[Yy]$') {
                        $userQuarantine = Join-Path $quarantineRoot $user.Name
                        if (-not (Test-Path $userQuarantine)) {
                            New-Item -Path $userQuarantine -ItemType Directory | Out-Null
                        }

                        $destination = Join-Path $userQuarantine $file.Name

                        # Avoid overwriting files with the same name
                        if (Test-Path $destination) {
                            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                            $ext = $file.Extension
                            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                            $destination = Join-Path $userQuarantine "${baseName}_$timestamp$ext"
                        }

                        try {
                            Move-Item -Path $file.FullName -Destination $destination -Force
                            Write-Host "Moved to quarantine: $destination" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Failed to move file: $($file.FullName)" -ForegroundColor Red
                            Write-Host $_.Exception.Message -ForegroundColor Red
                        }
                    }
                    else {
                        Write-Host "Skipped: $($file.FullName)" -ForegroundColor DarkGray
                    }
                }
            }
        }
    }
}