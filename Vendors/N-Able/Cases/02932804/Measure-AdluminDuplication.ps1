<#
.SYNOPSIS
    Measure Adlumin ingest duplication and latency over a window, read-only.

.DESCRIPTION
    The instrument behind N5h and N5i. Answers one question with a known
    denominator: how many times is each event delivered, and how late is the
    first copy?

    Every trap in docs/adlumin-api.md that can produce a wrong number here is
    guarded, and each guard is commented with what it prevents. Read that file
    before changing anything.

    Deterministic: re-running a window returns the same figures. N5h's window
    was re-run seven days later and matched in every column, which is both the
    proof that the platform does not de-duplicate after the fact and the answer
    to any challenge on method. Prefer re-running a stored window to arguing.

    Windows must be LONG. start/end filter on timewritten while events are
    bucketed by the device clock, so a window shorter than the copy spread
    (~5 min here) truncates groups and UNDER-reports copies - trap 6.

    VENDOR-FACING COMPANION: network/mikrotik/adlumin-measurement-method.md is
    the document sent to N-able with this script. It explains the method, every
    guard below and the wrong number each one prevents, the limits we state up
    front, and the exact commands that reproduce each figure quoted to them.
    If a guard changes here, change it there too - they hold a copy.

    Read-only: issues GETs only. See docs/adlumin-api.md - the API key is NOT
    read-only at the platform, so "GETs only" is a discipline, not a control.

.PARAMETER StartUtc
    Window start, 'yyyy-MM-dd-HH:mm:ss', UTC. NZST is UTC+12 (+13 in daylight
    time); a local-time window silently returns the wrong half-day or nothing.

.PARAMETER Query
    Bare token, never quoted, never an IP. Default ADLUMINHEARTBEAT, which has
    an exact denominator: one heartbeat per device per five minutes.

.PARAMETER ExpectedHosts
    The devices that SHOULD be sending heartbeats, asserted rather than observed,
    and used only when Query is ADLUMINHEARTBEAT. Counting the hosts that turn up
    would let a device that stopped sending shrink the expected total to match
    itself, reporting a clean bill of health for the exact fault the denominator
    exists to catch. A device named here with no events is named in a warning.

.EXAMPLE
    # A complete NZST calendar day, bucketed by each device's own clock
    .\Measure-AdluminDuplication.ps1 -StartUtc 2026-08-31-12:00:00 -EndUtc 2026-09-01-12:00:00 -ByHour

.EXAMPLE
    # The independent-vendor control: UniFi through the same collector
    .\Measure-AdluminDuplication.ps1 -StartUtc 2026-09-01-06:00:00 -EndUtc 2026-09-01-07:00:00 -Query Ubiquiti

.NOTES
    Credential resolution, same pattern as Backup-UniFi.ps1's -Password:

      1. SecretStore, entry names 'adlumin-api-key' and 'adlumin-tenant-id' --
         the primary path on the capture host. Requires the vault registered
         once and unlocked for the session:

             Unlock-SecretStore
             .\Measure-AdluminDuplication.ps1 -StartUtc ... -EndUtc ...

      2. $env:ADLUMIN_API_KEY / $env:ADLUMIN_TENANT_ID -- fallback for a host
         that has not registered SecretStore yet, or a one-off run elsewhere.

    One-time setup for the SecretStore path, on this host, as hugh-capture:

        Set-Secret -Name 'adlumin-api-key' -Secret '...'
        Set-Secret -Name 'adlumin-tenant-id' -Secret '...'

    The values are the same ones held in IT Glue as adlumin-api-key and
    adlumin-tenant-id (docs/adlumin-api.md). SecretStore's own vault
    password protects them at rest; that vault password is not itself
    stored anywhere.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d{4}-\d{2}-\d{2}-\d{2}:\d{2}:\d{2}$')][string]$StartUtc,
    [Parameter(Mandatory)][ValidatePattern('^\d{4}-\d{2}-\d{2}-\d{2}:\d{2}:\d{2}$')][string]$EndUtc,
    [string]$Query = 'ADLUMINHEARTBEAT',
    [switch]$ByHour,
    [switch]$ShowGroups,
    [string[]]$ExpectedHosts = @('CCL-RT-01','CCL-RT-02','CCL-RT-03','CCL-S-Dude'),
    [int]$MaxPages = 400
)

$ErrorActionPreference = 'Stop'

# The token is atomic: a partial word is a guaranteed false negative, and an IP
# address matches nothing at all - query='172.30.1.49' returns "No records found"
# on records that all carry it. Refuse the shapes that cannot work.
if ($Query -match '^\d{1,3}(\.\d{1,3}){3}$') {
    throw "'$Query' is an IP address. IPs are not searchable tokens on this API - even the collector's own address returns No records found. Tally forwarder_app_ip client-side instead."
}
if ($Query -match '["'']') {
    throw 'Do not quote the query - it explodes the result set rather than narrowing it. Narrow with the window.'
}

# Resolution order: SecretStore, then the env vars. SecretStore is preferred on
# the capture host (encrypted at rest, behind a vault password); the env vars
# stay as a fallback for a host with no vault registered. See NOTES for setup.
$key = $null; $tenant = $null
if (Get-Command Get-Secret -ErrorAction SilentlyContinue) {
    try {
        $key    = Get-Secret -Name 'adlumin-api-key'   -AsPlainText -ErrorAction Stop
        $tenant = Get-Secret -Name 'adlumin-tenant-id' -AsPlainText -ErrorAction Stop
    }
    catch {
        # Not fatal - no vault registered, vault locked, or the entries do not
        # exist yet all land here, and the env-var fallback below covers them.
        $key = $null; $tenant = $null
    }
}
# Process scope FIRST, then the User registry scope. Reading only 'User' means a
# plain `$env:ADLUMIN_API_KEY = '...'` in the caller's shell is silently ignored,
# which is the obvious thing for anyone running this on a host that is not ours
# to try. Both are checked so either works.
if (-not $key)    { $key    = $env:ADLUMIN_API_KEY }
if (-not $tenant) { $tenant = $env:ADLUMIN_TENANT_ID }
if (-not $key)    { $key    = [Environment]::GetEnvironmentVariable('ADLUMIN_API_KEY','User') }
if (-not $tenant) { $tenant = [Environment]::GetEnvironmentVariable('ADLUMIN_TENANT_ID','User') }
if (-not $key -or -not $tenant) {
    throw 'No Adlumin credentials. Expected SecretStore entries adlumin-api-key / adlumin-tenant-id (run Unlock-SecretStore first), or ADLUMIN_API_KEY / ADLUMIN_TENANT_ID as USER environment variables. A process started before those were set does not inherit them.'
}

$base = "https://api.adlumin.com/v1/network_data?tenant_id=$tenant&start=$StartUtc&end=$EndUtc"
if ($Query) { $base += '&query=' + [uri]::EscapeDataString($Query) }

$records = [System.Collections.Generic.List[object]]::new()
$scrollId = $null; $total = $null; $pages = 0; $partial = $false

while ($true) {
    $uri = $base
    if ($scrollId) { $uri += '&scroll_id=' + [uri]::EscapeDataString($scrollId) }

    # An undocumented rate limit exists; a 429 is a wait, not a failure.
    $response = $null
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try { $response = Invoke-RestMethod -Uri $uri -Headers @{'x-api-key'=$key} -TimeoutSec 180 -ErrorAction Stop; break }
        catch { if ($attempt -eq 5) { $partial = $true } else { Start-Sleep -Seconds (4*$attempt) } }
    }
    if (-not $response) { Write-Warning "Page $($pages+1) failed after 5 attempts - results below are a PARTIAL sample."; break }

    if ($response.PSObject.Properties.Name -contains 'failed' -and $response.failed) {
        Write-Host "API: $($response.failed)"
        Write-Warning 'An empty result is unproven until a positive control says otherwise (S13b).'
        return
    }
    if ($null -eq $total) { $total = [int]$response.total_records }
    foreach ($rec in @($response.records)) { $records.Add($rec) }
    $pages++
    $scrollId = $response.scroll_id

    # BOTH conditions. When total < page size the API keeps issuing a scroll_id and
    # returns the same full set again, so a null-check alone never fires and the loop
    # multiplies its own results - once reported 45x amplification against a true 5.8x.
    if (-not $scrollId -or $records.Count -ge $total -or $pages -ge $MaxPages) { break }
    Start-Sleep -Milliseconds 250
}

if ($records.Count -eq 0) { Write-Host 'No records.'; return }

# record_id is unique PER DELIVERED COPY. So on real duplication distinct == rows,
# and on a paging fault distinct << rows. One line, and it separates the two.
$distinctIds = ($records | Select-Object -ExpandProperty record_id -Unique).Count
Write-Host ("WINDOW {0} -> {1} UTC   query='{2}'" -f $StartUtc, $EndUtc, $Query)
Write-Host ("total_records={0}  collected={1}  pages={2}  distinct record_id={3}" -f $total, $records.Count, $pages, $distinctIds)
if ($distinctIds -lt $records.Count * 0.9) {
    Write-Warning 'PAGING FAULT: distinct record_id is far below row count. Every number below is wrong. Fix the scroll guard.'
    return
}
if ($partial) { Write-Warning 'Partial sample - at least one page was never retrieved.' }

$parsed = foreach ($rec in $records) {
    $rawMessage = [string]$rec.message_raw

    # The device's own clock, inside message_raw, is the only trustworthy timestamp.
    $deviceStamp = $null; $rawHost = $null
    if ($rawMessage -match '^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s') { $deviceStamp = $matches[1]; $rawHost = $matches[2] }
    if (-not $deviceStamp) { continue }

    $body = $rawMessage
    if ($rawMessage -match '\|([^|]*)$') { $body = $matches[1] }

    # adlumin_date_time_processed changed format between 2026-08-23 and 2026-09-02:
    # it is now 'MM/dd/yyyy HH:mm:ss', naive local, with no offset marker. Parsing
    # that as a date under the invariant culture swaps day and month silently and
    # produced lags of -17 708 988 seconds. Prefer the deserialised object.
    $processed = $null
    $value = $rec.adlumin_date_time_processed
    if ($value -is [datetime]) { $processed = $value }
    elseif ($value -is [datetimeoffset]) { $processed = $value.DateTime }
    elseif ($value) {
        foreach ($fmt in @('MM/dd/yyyy HH:mm:ss','yyyy-MM-ddTHH:mm:ss.fffzzz','yyyy-MM-ddTHH:mm:sszzz')) {
            try { $processed = [datetime]::ParseExact([string]$value, $fmt, [Globalization.CultureInfo]::InvariantCulture); break } catch {}
        }
    }

    # Syslog carries no year. Take it from the processed timestamp, and step back a
    # year if that lands in the future - which is what a 31 Dec / 1 Jan window does.
    $deviceTime = $null
    $year = if ($processed) { $processed.Year } else { (Get-Date).Year }
    foreach ($fmt in @('MMM  d HH:mm:ss yyyy','MMM d HH:mm:ss yyyy')) {
        try { $deviceTime = [datetime]::ParseExact("$deviceStamp $year", $fmt, [Globalization.CultureInfo]::InvariantCulture); break } catch {}
    }
    if ($deviceTime -and $processed -and $deviceTime -gt $processed.AddDays(1)) { $deviceTime = $deviceTime.AddYears(-1) }

    $lag = $null
    if ($deviceTime -and $processed) { $lag = [math]::Round(($processed - $deviceTime).TotalSeconds) }

    [pscustomobject]@{
        # cef_parsed_event_hash is not a hash and record_id is per-copy, so neither can
        # dedup. Device clock + host + message text is the only sound key.
        Key        = "$deviceStamp|$rawHost|$(($body -replace '\s+',' ').Trim())"
        DeviceTime = $deviceTime
        Hour       = if ($deviceTime) { $deviceTime.ToString('MM-dd HH') } else { 'unknown' }
        # dvchost is always null via the API; device_hostname is the correct selector.
        Host       = if ($rec.device_hostname) { $rec.device_hostname } else { $rawHost }
        RecordId   = $rec.record_id
        Processed  = $processed
        LagSec     = $lag
        Forwarder  = $rec.forwarder_app_ip
        Collector  = $rec.adlumin_collector_version
    }
}

# Force an array: a foreach expression yields $null for none and a bare object for
# one, and .Count on either is not what the guard below needs to read.
$parsed = @($parsed)

# Rows whose device clock will not parse are dropped above, silently, and every
# figure below is then computed on a subset while still printing confidently.
# That is exactly N8b: BSD syslog pads a single-digit day with a SECOND space
# ('Sep  8'), the pattern list missed it, and the N-central check reported four
# healthy devices as dead for 54 hours. Make the drop impossible to miss, and
# make "fetched rows, parsed none" its own hard stop rather than an empty table.
$dropped = $records.Count - $parsed.Count
if ($parsed.Count -eq 0) {
    Write-Warning ("PARSED NOTHING: {0} rows fetched, 0 parsed. The device-clock pattern matched no record. Check the BSD double-space day form ('Sep  8', not 'Sep 8') - see docs/adlumin-api.md trap 4. No figures are reported because none would be sound." -f $records.Count)
    return
}
if ($dropped -gt 0) {
    Write-Warning ("{0} of {1} rows ({2:N1} %) were dropped before analysis - their device clock did not parse. Every figure below is computed on the {3} that did, so copy counts are a LOWER bound. Fix the parse before quoting these numbers." -f `
        $dropped, $records.Count, (100 * $dropped / $records.Count), $parsed.Count)
}

# Ingestion latency is device time -> processed time and is therefore always
# positive. A negative lag is a parsing bug, never a measurement.
$negative = @($parsed | Where-Object { $null -ne $_.LagSec -and $_.LagSec -lt 0 })
if ($negative.Count) {
    Write-Warning ("{0} rows have a NEGATIVE lag (min {1}s). That is a timestamp parsing bug, not a measurement - see docs/adlumin-api.md trap 4." -f `
        $negative.Count, ($negative | Measure-Object LagSec -Minimum).Minimum)
}

function Get-Pct { param($Sorted, $Q) $Sorted[[math]::Min($Sorted.Count-1, [math]::Floor($Sorted.Count*$Q))] }

# One entry per distinct event, carrying its copy count and its FIRST copy's lag -
# the earliest the platform could have known anything.
$events = $parsed | Group-Object Key | ForEach-Object {
    $lags = @($_.Group | Where-Object { $null -ne $_.LagSec } | ForEach-Object { $_.LagSec } | Sort-Object)
    [pscustomobject]@{
        Hour     = $_.Group[0].Hour
        Host     = $_.Group[0].Host
        Copies   = $_.Count
        FirstLag = if ($lags.Count) { $lags[0] } else { $null }
    }
}
$copyCounts = @($events | ForEach-Object { $_.Copies } | Sort-Object)

Write-Host ''
Write-Host ('ROWS {0}   DISTINCT EVENTS {1}   COPIES mean {2}  median {3}  max {4}' -f `
    $parsed.Count, $events.Count,
    [math]::Round(($events | Measure-Object Copies -Average).Average, 2),
    $copyCounts[[math]::Floor($copyCounts.Count/2)],
    ($events | Measure-Object Copies -Maximum).Maximum)

if ($Query -eq 'ADLUMINHEARTBEAT') {
    # The denominator is exact: one heartbeat per device per five minutes.
    #
    # It must be ASSERTED, not observed. Counting the hosts that appear makes the
    # expected total shrink to match whatever turned up, so a device that stopped
    # sending entirely scores a clean "864 expected, 864 present" - the one failure
    # this line exists to catch is the one it could not see. -ExpectedHosts names
    # them instead, and a missing device is reported by name.
    $seen    = @($events | Select-Object -ExpandProperty Host -Unique)
    $missing = @($ExpectedHosts | Where-Object { $_ -notin $seen })
    $extra   = @($seen | Where-Object { $_ -notin $ExpectedHosts })
    $hours = ([datetime]::ParseExact($EndUtc,'yyyy-MM-dd-HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture) -
              [datetime]::ParseExact($StartUtc,'yyyy-MM-dd-HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)).TotalHours
    Write-Host ('DENOMINATOR: {0} devices x 12/hour x {1} h = {2} expected, {3} present' -f `
        $ExpectedHosts.Count, [math]::Round($hours,2), [math]::Round($ExpectedHosts.Count*12*$hours), $events.Count)
    Write-Host '             A shortfall here is EVENT LOSS, a different and worse fault than duplication.'
    # The window filters on timewritten but events are bucketed by the device clock,
    # so copies of an event just outside the window land inside it. Expect a small
    # overshoot at both edges; it is an edge effect, not extra events.
    Write-Host '             Events are bucketed by DEVICE clock and the window filters on timewritten,'
    Write-Host '             so a few events from just outside the window land inside it. Overshoot at'
    Write-Host '             the edges is expected; a SHORTFALL is not.'
    if ($missing.Count) {
        Write-Warning ("SILENT DEVICE(S): {0} sent no heartbeat at all in this window. The expected count above is asserted, not observed, which is the only reason this is visible." -f ($missing -join ', '))
    }
    if ($extra.Count) {
        Write-Warning ("Hosts present but not in -ExpectedHosts: {0}. The denominator does not account for them." -f ($extra -join ', '))
    }
}

Write-Host ''
Write-Host 'PER HOST:'
$events | Group-Object Host | Sort-Object Name | ForEach-Object {
    $lags = @($_.Group | Where-Object { $null -ne $_.FirstLag } | ForEach-Object { $_.FirstLag } | Sort-Object)
    $rows = ($_.Group | Measure-Object Copies -Sum).Sum
    Write-Host ('  {0,-16} distinct {1,5}   rows {2,6}   copies {3,5}   median first-copy lag {4}' -f `
        $_.Name, $_.Count, $rows, [math]::Round($rows / $_.Count, 2),
        $(if ($lags.Count) { "$(Get-Pct $lags 0.5)s" } else { 'n/a' }))
}

if ($ByHour) {
    Write-Host ''
    Write-Host 'BY DEVICE-CLOCK HOUR (local to the device - this is the diurnal curve):'
    Write-Host ('  {0,-10} {1,8} {2,7} {3,8} {4,10} {5,9} {6,9}' -f 'hour','distinct','rows','copies','median','p90','max')
    $events | Group-Object Hour | Sort-Object Name | ForEach-Object {
        $lags = @($_.Group | Where-Object { $null -ne $_.FirstLag } | ForEach-Object { $_.FirstLag } | Sort-Object)
        Write-Host ('  {0,-10} {1,8} {2,7} {3,8} {4,10} {5,9} {6,9}' -f `
            $_.Name, $_.Count, ($_.Group | Measure-Object Copies -Sum).Sum,
            [math]::Round(($_.Group | Measure-Object Copies -Average).Average, 2),
            $(if ($lags.Count) { "$(Get-Pct $lags 0.5)s" } else { 'n/a' }),
            $(if ($lags.Count) { "$(Get-Pct $lags 0.9)s" } else { 'n/a' }),
            $(if ($lags.Count) { "$($lags[-1])s" } else { 'n/a' }))
    }
}

$allLags = @($events | Where-Object { $null -ne $_.FirstLag } | ForEach-Object { $_.FirstLag } | Sort-Object)
if ($allLags.Count) {
    Write-Host ''
    Write-Host ('FIRST-COPY LAG (device clock -> processed), n={0}: min {1}s  median {2}s  p90 {3}s  p99 {4}s  max {5}s' -f `
        $allLags.Count, $allLags[0], (Get-Pct $allLags 0.5), (Get-Pct $allLags 0.9), (Get-Pct $allLags 0.99), $allLags[-1])
    Write-Host '  First copy only, so this is a LOWER bound on how late the feed is. Quote it with the hour it covers.'
}

Write-Host ''
Write-Host 'FORWARDER / COLLECTOR VERSION (tallied client-side - an IP cannot be queried):'
$parsed | Group-Object Forwarder, Collector | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ('  {0,-40} {1} rows' -f $_.Name, $_.Count)
}

if ($ShowGroups) {
    Write-Host ''
    Write-Host 'MOST-COPIED EVENTS:'
    $parsed | Group-Object Key | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
        Write-Host ('  x{0,-3} {1}' -f $_.Count, $_.Group[0].Key)
        Write-Host ('        record_ids: {0}' -f (($_.Group.RecordId | ForEach-Object { $_.Substring(0,8) }) -join ' '))
        Write-Host ('        processed : {0}' -f (($_.Group | Sort-Object Processed | ForEach-Object { $_.Processed.ToString('HH:mm:ss') }) -join ' '))
    }
}

Write-Host ''
Write-Host 'MOST RECENT DUPLICATED EVENT (freshest evidence in this window):'
$lastDup = $parsed | Group-Object Key | Where-Object { $_.Count -gt 1 } |
    Sort-Object { $_.Group[0].DeviceTime } -Descending | Select-Object -First 1
if (-not $lastDup) {
    Write-Host '  None - every event in this window was delivered exactly once.'
}
else {
    Write-Host ('  x{0} {1}' -f $lastDup.Count, $lastDup.Group[0].Key)
    $lastDup.Group | Sort-Object Processed | ForEach-Object {
        Write-Host ('    record_id {0}   processed {1}   lag {2}s' -f `
            $_.RecordId, $_.Processed.ToString('HH:mm:ss'), $_.LagSec)
    }

    # adlumin_date_time_processed is naive LOCAL (trap 4), same clock the portal's own
    # "Event Time" column shows - so these need no timezone conversion to be pasted in.
    # $Query is reused as-is because the top-of-script guard already refused an IP or a
    # quoted form; a bare token is the only shape that narrows rather than explodes
    # (trap 2) or returns nothing (trap 2's IP case).
    $copyTimes = $lastDup.Group.Processed | Sort-Object
    $padStart  = $copyTimes[0].AddSeconds(-60)
    $padEnd    = $copyTimes[-1].AddSeconds(60)
    Write-Host ''
    Write-Host '  TO FIND THIS SAME EVENT IN THE ADLUMIN PORTAL:'
    Write-Host ("    Search term : {0}   (bare token only - quoting or an IP returns nothing, docs/adlumin-api.md trap 2)" -f $Query)
    Write-Host ("    Time range  : {0} -> {1}   (local - same clock as the portal's Event Time column)" -f `
        $padStart.ToString('yyyy-MM-dd HH:mm:ss'), $padEnd.ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Host ("    Then filter to device/host = {0} and look for {1} rows with identical message text" -f `
        $lastDup.Group[0].Host, $lastDup.Count)
}
