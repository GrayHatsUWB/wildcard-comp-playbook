Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Initiating Dynamic Driver Hunt..." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$driverDir = "C:\Windows\System32\drivers\*.sys"
$suspiciousDrivers = @()

Write-Host "[*] Phase 1: Sweeping for Unsigned or Invalid Signatures..." -ForegroundColor Yellow

# Get all .sys files
$allDrivers = Get-ChildItem -Path $driverDir -ErrorAction SilentlyContinue

foreach ($driver in $allDrivers) {
    # Check the digital signature
    $sig = Get-AuthenticodeSignature -FilePath $driver.FullName
    
    # We flag it if it is NOT valid, or if it lacks a signature entirely
    if ($sig.Status -ne 'Valid') {
        $suspiciousDrivers += [PSCustomObject]@{
            FileName = $driver.Name
            Reason   = "Invalid or Missing Signature ($($sig.Status))"
            Created  = $driver.CreationTime
            Path     = $driver.FullName
        }
    } 
    # Optional: Flag valid signatures that aren't Microsoft (can be noisy, but catches BYOVD attacks)
    elseif ($sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
        $suspiciousDrivers += [PSCustomObject]@{
            FileName = $driver.Name
            Reason   = "Third-Party Signature ($($sig.SignerCertificate.Subject.Split(',')[0]))"
            Created  = $driver.CreationTime
            Path     = $driver.FullName
        }
    }
}

if ($suspiciousDrivers.Count -gt 0) {
    Write-Host "[!] Suspicious Signatures Detected:" -ForegroundColor Red
    $suspiciousDrivers | Format-Table -AutoSize
} else {
    Write-Host "[+] All driver signatures appear valid and native." -ForegroundColor Green
}

Write-Host "`n[*] Phase 2: Timeline Analysis (Top 5 Newest Drivers)..." -ForegroundColor Yellow
Write-Host "    (Look for anomalies here even if the signature looks valid)" -ForegroundColor Gray

# Sort by CreationTime to find recently dropped drivers
$allDrivers | Sort-Object CreationTime -Descending | Select-Object Name, CreationTime, LastWriteTime, Length -First 5 | Format-Table -AutoSize

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Driver Hunt Complete." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan