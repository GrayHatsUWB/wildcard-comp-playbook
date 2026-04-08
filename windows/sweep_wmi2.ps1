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
        # Extract the names directly from the CIM object properties (No string splitting needed!)
        $filterName = $binding.Filter.Name
        $consumerName = $binding.Consumer.Name
        
        # Check if they are in our whitelist (and ensure they aren't blank to prevent false positives)
        if ($filterName -and $consumerName -and ($whitelist -notcontains $filterName) -and ($whitelist -notcontains $consumerName)) {
            $foundSuspicious = $true
            Write-Host "[!] SUSPICIOUS WMI BINDING DETECTED" -ForegroundColor Red
            Write-Host "    -> Filter Name:   $filterName" -ForegroundColor Yellow
            Write-Host "    -> Consumer Name: $consumerName" -ForegroundColor Yellow
            
            # Query the abstract class and filter via PowerShell
            $consumerDetails = Get-CimInstance -Namespace $namespace -ClassName __EventConsumer | Where-Object { $_.Name -eq $consumerName }
            
            if ($consumerDetails.CommandLineTemplate) {
                Write-Host "    -> Action:        $($consumerDetails.CommandLineTemplate)" -ForegroundColor DarkRed
            }
            elseif ($consumerDetails.ScriptText) {
                Write-Host "    -> Action:        [VBS/JS Script Block Detected]" -ForegroundColor DarkRed
                Write-Host "       $($consumerDetails.ScriptText)" -ForegroundColor Gray
            }

            Write-Host "    -> To neutralize, run these commands:" -ForegroundColor Green
            Write-Host "       Get-CimInstance -Namespace $namespace -ClassName __FilterToConsumerBinding | Where-Object { `$_.Filter.Name -match '$filterName' } | Remove-CimInstance"
            Write-Host "       Get-CimInstance -Namespace $namespace -Query `"SELECT * FROM __EventFilter WHERE Name='$filterName'`" | Remove-CimInstance"
            Write-Host "       Get-CimInstance -Namespace $namespace -ClassName __EventConsumer | Where-Object { `$_.Name -eq '$consumerName' } | Remove-CimInstance"
            Write-Host "---------------------------------------------" -ForegroundColor Cyan
        }
    }

    if (-not $foundSuspicious) {
        Write-Host "[+] WMI Subscriptions look clean. No unauthorized bindings found." -ForegroundColor Green
    }
}
catch {
    Write-Host "[ERROR] Could not query WMI. Make sure you are running as Administrator." -ForegroundColor DarkRed
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Sweep Complete." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
