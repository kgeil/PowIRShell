function Get-M365UnifiedAuditLog {
<#
.Synopsis
  Retrieves Microsoft 365 Unified Audit Log (UAL) events directly from your tenant and
  writes them to JSON files in the same format that Get-M365CompromiseInfo expects, so
  you don't have to run a separate tool (e.g. the Invictus Extractor Suite) first.

.Description
  Wraps Search-UnifiedAuditLog (Exchange Online / Purview) with paging via
  -SessionCommand ReturnLargeSet, so results larger than a single 5,000-record page are
  still retrieved. Each raw Search-UnifiedAuditLog record wraps the actual event in a
  JSON-encoded AuditData property; this function expands AuditData for every record and
  writes the expanded events to a single-line (compressed) JSON array file in -OutputDir.
  That's the same on-disk shape produced by the Invictus Extractor Suite, so you can pass
  -OutputDir straight into Get-M365CompromiseInfo's -searchdir parameter with no changes
  to the rest of the pipeline.

  Requires the ExchangeOnlineManagement module and an active Connect-ExchangeOnline
  session with a role that can read audit logs (e.g. Compliance Administrator, Security
  Reader, Global Reader, or View-Only Audit Logs). This function does not connect for
  you -- run Connect-ExchangeOnline yourself first, so you control which account/MFA
  flow is used.

  Microsoft's Search-UnifiedAuditLog session paging is documented to return a maximum of
  50,000 records per SessionId. If you hit that ceiling (or the -MaxRecords safety cap),
  narrow -StartDate/-EndDate and call this function again to fill in the rest of the
  window -- it's still the simplest supported way to pull UAL data from PowerShell as of
  this writing; for very large or recurring extractions, Microsoft points to the
  Office 365 Management Activity API instead.

.Parameter StartDate
  Start of the search window (UTC recommended). Passed directly to Search-UnifiedAuditLog.

.Parameter EndDate
  End of the search window (UTC recommended). Passed directly to Search-UnifiedAuditLog.

.Parameter OutputDir
  Directory to write the expanded JSON event file to. Created if it doesn't exist. Pass
  this same directory as -searchdir to Get-M365CompromiseInfo.

.Parameter UserIds
  Optional. One or more UPNs to restrict the search to.

.Parameter Operations
  Optional. One or more Operation names to restrict the search to (e.g. UserLoggedIn,
  MailItemsAccessed). Omit to retrieve all operations.

.Parameter RecordType
  Optional. Restrict to a specific UAL RecordType (e.g. ExchangeItem,
  AzureActiveDirectoryStsLogon). See Microsoft's Office 365 Management Activity API
  schema docs for the full list.

.Parameter ResultSize
  Records per page passed to Search-UnifiedAuditLog. Default and Microsoft's max is 5000.

.Parameter MaxRecords
  Safety cap on total records retrieved across all pages in this call. Default 50000,
  which is Microsoft's documented ceiling for a single paged session.

.Example
  # Simplest form: pull one specific day's worth of events by explicit start/end date
  Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
  Get-M365UnifiedAuditLog -StartDate '09/01/2026' -EndDate '09/02/2026' -OutputDir C:\temp\365Comp\UAL

.Example
  Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
  Get-M365UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
      -OutputDir C:\temp\365Comp\UAL

  Get-M365CompromiseInfo -searchdir C:\temp\365Comp\UAL\ -outputDir C:\temp\365Comp\ `
      -ipinfoLookup -ipinfoAPIKey '<IpInfoKeyHere>'

.Example
  # Narrow to logon events for one user
  Get-M365UnifiedAuditLog -StartDate '2026-09-01' -EndDate '2026-09-08' `
      -UserIds 'jdoe@contoso.com' -Operations UserLoggedIn,UserLoginFailed `
      -OutputDir C:\temp\365Comp\UAL

.Inputs
  None. All parameters are explicit; the function calls Search-UnifiedAuditLog itself.

.Outputs
  A single compressed JSON array file written to -OutputDir, plus the expanded event
  objects returned to the pipeline.

.Notes
  Requires: ExchangeOnlineManagement module (Install-Module ExchangeOnlineManagement
  -Scope CurrentUser) and an active Connect-ExchangeOnline session.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true)]
        [string]$OutputDir,

        [string[]]$UserIds,

        [string[]]$Operations,

        [string]$RecordType,

        [ValidateRange(1, 5000)]
        [int]$ResultSize = 5000,

        [int]$MaxRecords = 50000
    )

    $ErrorActionPreference = "Stop"

    if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
        Write-Host "Search-UnifiedAuditLog isn't available. Install and import ExchangeOnlineManagement:" -ForegroundColor Red
        Write-Host "  Install-Module ExchangeOnlineManagement -Scope CurrentUser" -ForegroundColor Yellow
        Write-Host "  Connect-ExchangeOnline -UserPrincipalName <you@yourtenant.com>" -ForegroundColor Yellow
        return
    }

    try {
        Get-ConnectionInformation -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "No active Exchange Online session found. Run Connect-ExchangeOnline first, then try again." -ForegroundColor Red
        return
    }

    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }

    $sessionId = "M365UAL_" + (Get-Date -Format "yyyyMMddHHmmss")
    $allRecords = New-Object System.Collections.Generic.List[object]
    $page = 1

    Write-Host "Searching Unified Audit Log from $StartDate to $EndDate..." -ForegroundColor Green

    do {
        $searchParams = @{
            StartDate      = $StartDate
            EndDate        = $EndDate
            ResultSize     = $ResultSize
            SessionId      = $sessionId
            SessionCommand = "ReturnLargeSet"
        }
        if ($UserIds)    { $searchParams["UserIds"] = $UserIds }
        if ($Operations) { $searchParams["Operations"] = $Operations }
        if ($RecordType) { $searchParams["RecordType"] = $RecordType }

        Write-Verbose "Requesting page $page (session $sessionId)..."
        $results = Search-UnifiedAuditLog @searchParams

        if (-not $results -or $results.Count -eq 0) { break }

        $allRecords.AddRange($results)
        Write-Host "  Retrieved $($allRecords.Count) records so far..." -ForegroundColor Yellow
        $page++

    } while ($results.Count -eq $ResultSize -and $allRecords.Count -lt $MaxRecords)

    if ($allRecords.Count -ge $MaxRecords) {
        Write-Host "Hit the $MaxRecords record safety cap -- there may be more data in this window." -ForegroundColor Yellow
        Write-Host "Narrow -StartDate/-EndDate and re-run to fill in the rest." -ForegroundColor Yellow
    }

    if ($allRecords.Count -eq 0) {
        Write-Host "No events found for that search." -ForegroundColor Yellow
        return @()
    }

    Write-Host "Retrieved $($allRecords.Count) raw audit records. Expanding AuditData..." -ForegroundColor Green

    $expandedEvents = foreach ($record in $allRecords) {
        try {
            $record.AuditData | ConvertFrom-Json
        } catch {
            Write-Verbose "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)"
        }
    }

    $outFile = Join-Path $OutputDir "UnifiedAuditLog_$(Get-Date -Format 'yyyyMMddHHmmss').json"
    # -Compress keeps this a single line, matching the Invictus Extractor output format
    # that Get-AuditdataFrom365JSON expects (it reads each *.json file line by line).
    @($expandedEvents) | ConvertTo-Json -Depth 20 -Compress | Out-File -FilePath $outFile -Encoding utf8 -Force

    Write-Host "Wrote $($expandedEvents.Count) events to $outFile" -ForegroundColor Green
    Write-Host "Pass -searchdir $OutputDir\ to Get-M365CompromiseInfo to analyze these events." -ForegroundColor Cyan

    return $expandedEvents
}
