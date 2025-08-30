<# =======================================================================
 Suspicious Login Pattern Analyzer (final + GeoLite2 integration)
 Minimal input per line:              time,user,computer
 Optional richer input per line:      time,user,computer,src_ip,country
 Examples:
   1,U1,C1
   1724971200,U2,C3,203.0.113.4,US

 Outputs:
   Reports\TopUsers_ByDistinctComputers.csv
   Reports\TopUsers_ByEvents.csv
   Reports\TopUserComputerPairs.csv
   Reports\SuspiciousFindings.csv
   Reports\meta.json
======================================================================= #>

[CmdletBinding()]
param(
  [string]$LogPath   = ".\auth.txt",
  [string]$ReportDir = ".\Reports",

  # streaming & progress
  [int]$ReadBatch = 10000,
  [int]$ProgressEvery = 500000,
  [Nullable[int]]$MaxLines = 5000000,

  # detection thresholds (align with dashboard)
  [int]$Thresh_DistinctHosts = 50,
  [int]$Thresh_TotalEvents   = 20000,
  [int]$Thresh_PairEvents    = 25000,

  # optional rules (epoch timestamp & country needed)
  [int]$OddHour_Start = 0,
  [int]$OddHour_End   = 6,
  [int]$ImpTravel_MinGapMinutes = 60,

  # GeoLite2
  [string]$GeoDbPath = ".\GeoLite2-City.mmdb"
)

$ErrorActionPreference = 'Stop'

# ---------- GeoLite2 Prep ----------
if (Test-Path $GeoDbPath) {
    Add-Type -Path "MaxMind.Db.dll"
    Add-Type -Path "MaxMind.GeoIP2.dll"
    $geoReader = New-Object MaxMind.GeoIP2.DatabaseReader($GeoDbPath)

    function Get-CountryFromIP($ip) {
        try {
            $resp = $geoReader.City($ip)
            return $resp.Country.IsoCode
        } catch { return $null }
    }
} else {
    Write-Host "[-] GeoLite2 DB not found: $GeoDbPath (Country enrichment will be skipped)"
    function Get-CountryFromIP($ip) { return $null }
}

# ---------- Prep ----------
if (-not (Test-Path $LogPath)) { Write-Host "[-] Dataset not found: $LogPath"; exit 1 }
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir | Out-Null }

Write-Host "[*] Reading: $LogPath"

# ---------- State ----------
$userCounts         = @{}
$userDistinctHosts  = @{}
$userComputerCounts = @{}

# First-seen IPs
$userFirstIp      = @{}
$pairFirstIp      = @{}

$uniqueUsers     = [System.Collections.Generic.HashSet[string]]::new()
$uniqueComputers = [System.Collections.Generic.HashSet[string]]::new()

# For ImpossibleTravel
$userLastSeen = @{}
$oddHourFindings = New-Object System.Collections.Generic.List[object]
$impTravel       = New-Object System.Collections.Generic.List[object]

# ---------- Stream parse ----------
$lineTotal = 0
$source = if ($MaxLines) {
    Get-Content -Path $LogPath -TotalCount $MaxLines -ReadCount $ReadBatch
} else {
    Get-Content -Path $LogPath -ReadCount $ReadBatch
}

foreach ($batch in $source) {
  foreach ($raw in $batch) {
    $s = $raw.Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { continue }

    $parts = $s -split ',', 5
    if ($parts.Count -lt 3) { continue }

    $timeStr  = $parts[0]
    $user     = $parts[1]
    $computer = $parts[2]
    $srcIp    = if ($parts.Count -ge 4) { $parts[3] } else { $null }

    # Counts
    if (-not $userCounts.ContainsKey($user)) { $userCounts[$user] = 0 }
    $userCounts[$user]++

    if (-not $userDistinctHosts.ContainsKey($user)) {
      $userDistinctHosts[$user] = [System.Collections.Generic.HashSet[string]]::new()
    }
    $null = $userDistinctHosts[$user].Add($computer)

    $pairKey = "$user`0$computer"
    if (-not $userComputerCounts.ContainsKey($pairKey)) { $userComputerCounts[$pairKey] = 0 }
    $userComputerCounts[$pairKey]++

    $null = $uniqueUsers.Add($user)
    $null = $uniqueComputers.Add($computer)

    if ($srcIp -and -not $userFirstIp.ContainsKey($user)) { $userFirstIp[$user] = $srcIp }
    if ($srcIp -and -not $pairFirstIp.ContainsKey($pairKey)) { $pairFirstIp[$pairKey] = $srcIp }

    # Optional rules: odd-hour & impossible travel
    $ts = $null
    $epoch = 0L
    if ([long]::TryParse($timeStr, [ref]$epoch)) {
      try { $ts = [DateTimeOffset]::FromUnixTimeSeconds($epoch).ToLocalTime().DateTime } catch {}
    }

    if ($ts) {
      if ($ts.Hour -ge $OddHour_Start -and $ts.Hour -lt $OddHour_End) {
        if ($oddHourFindings.Count -lt 5000) {
          $oddHourFindings.Add([PSCustomObject]@{
            Rule    = 'OddHour'
            User    = $user
            Computer= $computer
            TimeISO = $ts.ToString("s")
            IP      = $srcIp
            Country = if ($srcIp) { Get-CountryFromIP $srcIp } else { $null }
          })
        }
      }

      $country = if ($srcIp) { Get-CountryFromIP $srcIp } else { $null }
      if ($country) {
        if (-not $userLastSeen.ContainsKey($user)) {
          $userLastSeen[$user] = @{ ts = $ts; country = $country }
        } else {
          $prev = $userLastSeen[$user]
          $deltaMin = [math]::Abs((New-TimeSpan -Start $prev.ts -End $ts).TotalMinutes)
          if ($prev.country -ne $country -and $deltaMin -le $ImpTravel_MinGapMinutes) {
            if ($impTravel.Count -lt 5000) {
              $impTravel.Add([PSCustomObject]@{
                Rule        = 'ImpossibleTravel'
                User        = $user
                PrevTimeISO = $prev.ts.ToString("s")
                PrevCountry = $prev.country
                CurrTimeISO = $ts.ToString("s")
                CurrCountry = $country
                GapMinutes  = [int][math]::Round($deltaMin)
                Computer    = $computer
                IP          = $srcIp
              })
            }
          }
          $userLastSeen[$user] = @{ ts = $ts; country = $country }
        }
      }
    }

    $lineTotal++
    if (($lineTotal % $ProgressEvery) -eq 0) {
      Write-Host ("    processed {0:N0} lines..." -f $lineTotal)
    }
  }
}

Write-Host ("[*] Finished. Total lines processed: {0:N0}" -f $lineTotal)

# ---------- Summaries ----------
$userSummary = foreach ($u in $userCounts.Keys) {
  [PSCustomObject]@{
    User              = $u
    TotalEvents       = $userCounts[$u]
    DistinctComputers = $userDistinctHosts[$u].Count
  }
}

$topByDistinct = $userSummary | Sort-Object DistinctComputers -Descending | Select-Object -First 50
$topByEvents   = $userSummary | Sort-Object TotalEvents -Descending | Select-Object -First 50

$pairSummary = foreach ($k in $userComputerCounts.Keys) {
  $split = $k.Split("`0",2)
  [PSCustomObject]@{
    User     = $split[0]
    Computer = $split[1]
    Events   = $userComputerCounts[$k]
    IP       = $pairFirstIp[$k]
    Country  = if ($pairFirstIp[$k]) { Get-CountryFromIP $pairFirstIp[$k] } else { $null }
  }
}

$topPairs = $pairSummary | Sort-Object Events -Descending | Select-Object -First 100

# ---------- Save Reports ----------
$topByDistinct | Export-Csv (Join-Path $ReportDir 'TopUsers_ByDistinctComputers.csv') -NoTypeInformation
$topByEvents   | Export-Csv (Join-Path $ReportDir 'TopUsers_ByEvents.csv') -NoTypeInformation
$topPairs      | Export-Csv (Join-Path $ReportDir 'TopUserComputerPairs.csv') -NoTypeInformation

# ---------- Suspicious Findings ----------
$findings = New-Object System.Collections.Generic.List[object]

$userSummary | Where-Object { $_.DistinctComputers -gt $Thresh_DistinctHosts } | ForEach-Object {
  $ip = $userFirstIp[$_.User]
  $cty = if ($ip) { Get-CountryFromIP $ip } else { $null }
  $findings.Add([PSCustomObject]@{ Rule='DistinctHosts'; User=$_.User; DistinctComputers=$_.DistinctComputers; TotalEvents=$_.TotalEvents; IP=$ip; Country=$cty })
}

$userSummary | Where-Object { $_.TotalEvents -gt $Thresh_TotalEvents } | ForEach-Object {
  $ip = $userFirstIp[$_.User]
  $cty = if ($ip) { Get-CountryFromIP $ip } else { $null }
  $findings.Add([PSCustomObject]@{ Rule='TotalEvents'; User=$_.User; TotalEvents=$_.TotalEvents; IP=$ip; Country=$cty })
}

$pairSummary | Where-Object { $_.Events -gt $Thresh_PairEvents } | ForEach-Object {
  $findings.Add($_)
}

foreach ($x in $oddHourFindings) { $findings.Add($x) }
foreach ($x in $impTravel)       { $findings.Add($x) }

$suspPath = Join-Path $ReportDir 'SuspiciousFindings.csv'
if ($findings.Count -gt 0) {
  $findings | Export-Csv $suspPath -NoTypeInformation
} else { "" | Out-File $suspPath -Encoding UTF8 }

# ---------- meta.json ----------
$meta = [ordered]@{
  generated_at_local = (Get-Date).ToString("s")
  processed_lines    = $lineTotal
  unique_users       = $uniqueUsers.Count
  unique_computers   = $uniqueComputers.Count
  thresholds         = @{ distinct_hosts=$Thresh_DistinctHosts; total_events=$Thresh_TotalEvents; pair_events=$Thresh_PairEvents; odd_hour_range="$OddHour_Start-$OddHour_End"; imp_travel_gap_mins=$ImpTravel_MinGapMinutes }
}
$meta | ConvertTo-Json -Depth 5 | Out-File (Join-Path $ReportDir 'meta.json') -Encoding UTF8

Write-Host "[*] Reports written to $ReportDir"
