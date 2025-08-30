# ============================================================
# Suspicious Login Pattern Analyzer - Step 2 (stream parse + summaries)
# Assumes each line in auth.txt is: time,user,computer
# Example:
#   1,U1,C1
#   7,U4,C5
# ============================================================

$ErrorActionPreference = 'Stop'

# --- Config ---
$datasetPath   = ".\auth.txt"
$reportsDir    = ".\Reports"
$readBatch     = 10000          # lines per batch for streaming
$progressEvery = 500000         # print progress every N lines
$MaxLines      = 5000000        # set to $null for FULL file; e.g. 5_000_000 for quicker test

# --- Prep ---
if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }

Write-Host "[*] Reading: $datasetPath"
if (-not (Test-Path $datasetPath)) {
    Write-Host "[-] Dataset file not found. Put auth.txt in this folder."
    exit 1
}

# --- Data structures (memory-conscious) ---
$userCounts = @{}                 # user -> total event count
$userDistinctHosts = @{}          # user -> HashSet of computers
$userComputerCounts = @{}         # "user`0computer" -> count

# --- Stream & parse ---
$lineTotal = 0

# Build the pipeline depending on whether we cap lines
if ($MaxLines) {
    $source = Get-Content $datasetPath -TotalCount $MaxLines -ReadCount $readBatch
} else {
    $source = Get-Content $datasetPath -ReadCount $readBatch
}

$source | ForEach-Object {
    foreach ($line in $_) {
        $lineTrim = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($lineTrim)) { continue }

        # expected: time,user,computer
        $parts = $lineTrim -split ',', 3
        if ($parts.Count -lt 3) { continue }

        # $timeStr = $parts[0]  # kept for future features if we add time-based analysis
        $user     = $parts[1]
        $computer = $parts[2]

        # total events per user
        if (-not $userCounts.ContainsKey($user)) { $userCounts[$user] = 0 }
        $userCounts[$user]++

        # distinct computers per user
        if (-not $userDistinctHosts.ContainsKey($user)) {
            $userDistinctHosts[$user] = [System.Collections.Generic.HashSet[string]]::new()
        }
        $null = $userDistinctHosts[$user].Add($computer)

        # user-computer pair counts
        $key = "$user`0$computer"
        if (-not $userComputerCounts.ContainsKey($key)) { $userComputerCounts[$key] = 0 }
        $userComputerCounts[$key]++

        $lineTotal++
        if (($lineTotal % $progressEvery) -eq 0) {
            Write-Host ("    processed {0:N0} lines..." -f $lineTotal)
        }
    }
}

Write-Host ("[*] Finished. Total lines processed: {0:N0}" -f $lineTotal)

# --- Build summaries ---
$userSummary = foreach ($u in $userCounts.Keys) {
    [PSCustomObject]@{
        User              = $u
        TotalEvents       = $userCounts[$u]
        DistinctComputers = $userDistinctHosts[$u].Count
    }
}

# Top users by number of distinct computers (possible lateral movement)
$topByDistinct = $userSummary |
    Sort-Object -Property @{Expression='DistinctComputers';Descending=$true},
                        @{Expression='TotalEvents';Descending=$true} |
    Select-Object -First 50

# Top users by total events (possible brute/automated use)
$topByEvents = $userSummary |
    Sort-Object -Property @{Expression='TotalEvents';Descending=$true},
                        @{Expression='DistinctComputers';Descending=$true} |
    Select-Object -First 50

# Most active user-computer pairs
$pairSummary = foreach ($k in $userComputerCounts.Keys) {
    $split = $k.Split("`0",2)
    [PSCustomObject]@{
        User     = $split[0]
        Computer = $split[1]
        Events   = $userComputerCounts[$k]
    }
}
$topPairs = $pairSummary |
    Sort-Object -Property @{Expression='Events';Descending=$true} |
    Select-Object -First 100

# --- Save reports ---
$topByDistinct | Export-Csv "$reportsDir\TopUsers_ByDistinctComputers.csv" -NoTypeInformation
$topByEvents   | Export-Csv "$reportsDir\TopUsers_ByEvents.csv" -NoTypeInformation
$topPairs      | Export-Csv "$reportsDir\TopUserComputerPairs.csv" -NoTypeInformation

Write-Host "[*] Reports written:"
Write-Host "    $reportsDir\TopUsers_ByDistinctComputers.csv"
Write-Host "    $reportsDir\TopUsers_ByEvents.csv"
Write-Host "    $reportsDir\TopUserComputerPairs.csv"

# --- On-screen quick view (10 rows each) ---
Write-Host "`n=== Top users by DISTINCT computers (first 10) ==="
$topByDistinct | Select-Object -First 10 | Format-Table

Write-Host "`n=== Top users by TOTAL events (first 10) ==="
$topByEvents | Select-Object -First 10 | Format-Table

Write-Host "`n=== Top user-computer pairs (first 10) ==="
$topPairs | Select-Object -First 10 | Format-Table
