$targets = @(
    @{
        ServiceName = "drv5"
        DriverPath  = "C:\Windows\System32\drivers\drv5.sys"
    },
    @{
        ServiceName = "chx"
        DriverPath  = "C:\Windows\System32\drivers\chxusb.sys"
    }
)

foreach ($t in $targets) {
    $service = $t.ServiceName
    $driver  = $t.DriverPath

    Write-Host "`n========== Processing $service ==========" -ForegroundColor Cyan
    Write-Host "Driver path: $driver" -ForegroundColor Gray

    # Try to stop service if it exists
    try {
        $svc = Get-Service -Name $service -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') {
            Write-Host "Stopping service: $service" -ForegroundColor Yellow
            Stop-Service -Name $service -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Host "Service not running or not found: $service" -ForegroundColor DarkYellow
    }

    # Delete service registration
    try {
        Write-Host "Deleting service entry: $service" -ForegroundColor Yellow
        sc.exe delete $service | Out-Null
    }
    catch {
        Write-Host "Could not delete service with sc.exe: $service" -ForegroundColor Red
    }

    # Remove registry key directly if still present
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
    if (Test-Path $regPath) {
        try {
            Write-Host "Removing registry key: $regPath" -ForegroundColor Yellow
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Host "Failed to remove registry key: $regPath" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }

    # Delete driver file
    if (Test-Path $driver) {
        try {
            Write-Host "Taking ownership: $driver" -ForegroundColor Gray
            takeown /f $driver | Out-Null

            Write-Host "Granting Administrators full control: $driver" -ForegroundColor Gray
            icacls $driver /grant Administrators:F /c | Out-Null

            Write-Host "Deleting file: $driver" -ForegroundColor Yellow
            Remove-Item -Path $driver -Force -ErrorAction Stop
        }
        catch {
            Write-Host "Failed to delete file now: $driver" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Write-Host "You may need Safe Mode or a reboot before retrying." -ForegroundColor DarkYellow
        }
    }
    else {
        Write-Host "Driver file already absent: $driver" -ForegroundColor Green
    }

    # Verification
    $fileGone = -not (Test-Path $driver)
    $regGone  = -not (Test-Path $regPath)

    if ($fileGone) {
        Write-Host "Verified file removed: $driver" -ForegroundColor Green
    } else {
        Write-Host "File still present: $driver" -ForegroundColor Red
    }

    if ($regGone) {
        Write-Host "Verified service key removed: $service" -ForegroundColor Green
    } else {
        Write-Host "Service key still present: $service" -ForegroundColor Red
    }
}