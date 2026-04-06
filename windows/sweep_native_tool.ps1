# Define the most commonly hijacked accessibility and system binaries
$targetBinaries = @(
    "sethc.exe",         # Sticky Keys (Shift 5 times)
    "utilman.exe",       # Ease of Access center (Win+U or lock screen icon)
    "osk.exe",           # On-Screen Keyboard
    "narrator.exe",      # Windows Narrator
    "magnify.exe",       # Magnifier
    "displayswitch.exe"  # Display Switcher (Win+P)
)

$baseRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Initiating Native Tool Hijack Sweep..." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

foreach ($binary in $targetBinaries) {
    $keyPath = Join-Path -Path $baseRegistryPath -ChildPath $binary
    
    # Check if the registry key exists for this binary
    if (Test-Path $keyPath) {
        # Check if the 'Debugger' value is set
        $debuggerValue = Get-ItemProperty -Path $keyPath -Name "Debugger" -ErrorAction SilentlyContinue
        
        if ($debuggerValue) {
            $maliciousTarget = $debuggerValue.Debugger
            Write-Host "[!] CRITICAL: Hijack detected on $binary!" -ForegroundColor Red
            Write-Host "    -> Redirecting to: $maliciousTarget" -ForegroundColor Yellow
            
            try {
                # Erase the backdoor
                Remove-ItemProperty -Path $keyPath -Name "Debugger" -Force -ErrorAction Stop
                Write-Host "    -> [SUCCESS] Malicious Debugger value neutralized." -ForegroundColor Green
            } catch {
                Write-Host "    -> [ERROR] Failed to remove. Check Administrator permissions." -ForegroundColor DarkRed
            }
        } else {
            Write-Host "[+] $binary is clean (Key exists, but no Debugger set)." -ForegroundColor Green
        }
    } else {
        Write-Host "[+] $binary is clean (No IFEO key found)." -ForegroundColor Green
    }
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Sweep Complete." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan