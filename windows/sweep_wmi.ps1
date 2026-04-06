Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Initiating WMI Persistence Sweep..." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$namespace = "ROOT\subscription"

# List of known good/default WMI filters/consumers to ignore
$whitelist = @(
    "SCM Event Log Filter",
    "SCM Event Log Consumer",
    "BVTFilter",
    "KernCap.vbs",
    "NTEventLogEventConsumer",
    "WSMan"
)

try {
    # Grab all the bindings
    $bindings = Get-CimInstance -Namespace $namespace -ClassName __FilterToConsumerBinding -ErrorAction Stop

    $foundSuspicious = $false

    foreach ($binding in $bindings) {
        # Extract the names of the Filter and Consumer from the binding paths
        $filterName = ($binding.Filter -split 'Name="')[1] -replace '"',''
        $consumerName = ($binding.Consumer -split 'Name="')[1] -replace '"',''
        
        # Check if they are in our whitelist
        if (($whitelist -notcontains $filterName) -and ($whitelist -notcontains $consumerName)) {
            $foundSuspicious = $true
            Write-Host "[!] SUSPICIOUS WMI BINDING DETECTED" -ForegroundColor Red
            Write-Host "    -> Filter Name:   $filterName" -ForegroundColor Yellow
            Write-Host "    -> Consumer Name: $consumerName" -ForegroundColor Yellow
            
            # Fetch the actual command/script the consumer is trying to run
            $consumerDetails = Get-CimInstance -Namespace $namespace -Query "SELECT * FROM __EventConsumer WHERE Name='$consumerName'"
            if ($consumerDetails.CommandLineTemplate) {
                Write-Host "    -> Action:        $($consumerDetails.CommandLineTemplate)" -ForegroundColor DarkRed
            } elseif ($consumerDetails.ScriptText) {
                Write-Host "    -> Action:        [VBS/JS Script Block Detected]" -ForegroundColor DarkRed
                Write-Host "       $($consumerDetails.ScriptText)" -ForegroundColor Gray
            }

            Write-Host "    -> To neutralize, run these commands:" -ForegroundColor Green
            Write-Host "       Get-CimInstance -Namespace $namespace -Query `"SELECT * FROM __FilterToConsumerBinding WHERE Filter LIKE '%$filterName%'`" | Remove-CimInstance"
            Write-Host "       Get-CimInstance -Namespace $namespace -Query `"SELECT * FROM __EventFilter WHERE Name='$filterName'`" | Remove-CimInstance"
            Write-Host "       Get-CimInstance -Namespace $namespace -Query `"SELECT * FROM __EventConsumer WHERE Name='$consumerName'`" | Remove-CimInstance"
            Write-Host "---------------------------------------------" -ForegroundColor Cyan
        }
    }

    if (-not $foundSuspicious) {
        Write-Host "[+] WMI Subscriptions look clean. No unauthorized bindings found." -ForegroundColor Green
    }

} catch {
    Write-Host "[ERROR] Could not query WMI. Make sure you are running as Administrator." -ForegroundColor DarkRed
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Sweep Complete." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan