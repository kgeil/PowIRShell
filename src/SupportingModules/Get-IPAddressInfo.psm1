function IsPrivateIPAddress($ipAddress) {
  $ip = [IPAddress]::Parse($ipAddress)
  $privateRanges = @(
      [IPAddressRange]::Parse('10.0.0.0/8'),
      [IPAddressRange]::Parse('172.16.0.0/12'),
      [IPAddressRange]::Parse('192.168.0.0/16')
  )
  foreach ($range in $privateRanges) {
      if ($range.Contains($ip)) {
          return $true
      }
  }
  return $false
}

function Get-IPAddress {
  param (
      [string]$ipField
  )

  # Not every UAL record has this property (admin/cmdlet-type records often use a
  # different field entirely, e.g. "ClientIP" instead of "ClientIPAddress"), so
  # callers frequently pass $null here. [regex]::Match() throws on a null input
  # string, and this script runs with $ErrorActionPreference = "Stop", so without
  # this guard a single record missing the field can silently kill the whole run.
  if ([string]::IsNullOrWhiteSpace($ipField)) {
      return $null
  }

  $ipRegex = '\b(?:\d{1,3}\.){3}\d{1,3}\b|:(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))'
  $ipMatch = [regex]::Match($ipField, $ipRegex)
  if ($ipMatch.Success) {
      return $ipMatch.Value
  } else {
      return $null
  }
}
function Get-clean_Ip {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    $iplist
  )

  $cleanIPlist = @()
  $ipv4regex = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
  $ipv6regex = ':(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))'

  foreach ($ip in $iplist) {
    try {
      # Retrieve IPv4 and IPv6 addresses from $iplist with no ports or extra characters
      $ipv4 = [regex]::Match($ip, $ipv4regex).Value
      $ipv6 = [regex]::Match($ip, $ipv6regex).Value

      if ($ipv4) {
        $cleanIPlist += $ipv4
      } elseif ($ipv6) {
        # Remove any extra characters from the IPv6 address
        $cleanIPv6 = $ipv6 -replace '[^\da-fA-F:]', ''
        $cleanIPlist += $cleanIPv6
      }
    } catch {
      # Ignore any errors and continue processing
    }
  }

  return $cleanIPlist
}


  function Get-UniqueIPs {
    param (
      $auditevents
    )
    $allip = $auditevents.ClientIP
    $allip += $auditevents.ActorIPAddress
    # Clean (strip ports/extra characters) BEFORE de-duping, not after: "1.2.3.4:443"
    # and "1.2.3.4:8080" are distinct strings pre-clean but the same address once
    # cleaned, so sorting unique first let cleaned duplicates back into the list.
    $allip = Get-clean_Ip -iplist $allip
    $allip = $allip | Sort-Object -Unique
    Return $allip

  }

  function Test-IPInCIDR {
    <#
    .SYNOPSIS
        Tests whether an IPv4 address falls within a single CIDR range.
    .DESCRIPTION
        Pure PowerShell/.NET arithmetic -- no dependency on a third-party IP-range
        module, so it works on a clean machine mid-incident without needing
        anything installed first. IPv6 addresses/ranges are not supported and
        always return $false.
    .PARAMETER IPAddress
        The IPv4 address to test, e.g. '13.80.210.226'.
    .PARAMETER CIDR
        A single CIDR range, e.g. '13.64.0.0/11'.
    .OUTPUTS
        $true if the address falls within the range, otherwise $false.
    .EXAMPLE
        Test-IPInCIDR -IPAddress '13.80.210.226' -CIDR '13.64.0.0/11'
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        [Parameter(Mandatory=$true)]
        [string]$CIDR
    )
    try {
        $cidrParts = $CIDR -split '/'
        if ($cidrParts.Count -ne 2) { return $false }
        $prefixLength = [int]$cidrParts[1]

        $ip = [System.Net.IPAddress]$IPAddress
        $net = [System.Net.IPAddress]$cidrParts[0]
        if ($ip.AddressFamily -ne 'InterNetwork' -or $net.AddressFamily -ne 'InterNetwork') {
            return $false
        }

        $ipBytes = $ip.GetAddressBytes()
        $netBytes = $net.GetAddressBytes()
        $ipInt = ([uint32]$ipBytes[0] -shl 24) -bor ([uint32]$ipBytes[1] -shl 16) -bor ([uint32]$ipBytes[2] -shl 8) -bor [uint32]$ipBytes[3]
        $netInt = ([uint32]$netBytes[0] -shl 24) -bor ([uint32]$netBytes[1] -shl 16) -bor ([uint32]$netBytes[2] -shl 8) -bor [uint32]$netBytes[3]

        if ($prefixLength -eq 0) { return $true }
        $mask = [uint32]::MaxValue -shl (32 - $prefixLength)
        return (($ipInt -band $mask) -eq ($netInt -band $mask))
    } catch {
        return $false
    }
  }

  function Test-IPInAnyCIDR {
    <#
    .SYNOPSIS
        Tests whether an IPv4 address falls within any of a list of CIDR ranges.
    .PARAMETER IPAddress
        The IPv4 address to test.
    .PARAMETER CIDRRanges
        An array of CIDR range strings, e.g. from Get-MicrosoftIPRanges.
    .OUTPUTS
        $true if the address falls within any of the ranges, otherwise $false.
    .EXAMPLE
        Test-IPInAnyCIDR -IPAddress '13.80.210.226' -CIDRRanges (Get-MicrosoftIPRanges)
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        [Parameter(Mandatory=$true)]
        [string[]]$CIDRRanges
    )
    foreach ($cidr in $CIDRRanges) {
        if (Test-IPInCIDR -IPAddress $IPAddress -CIDR $cidr) {
            return $true
        }
    }
    return $false
  }

  function Get-MicrosoftIPRanges {
    <#
    .SYNOPSIS
        Retrieves Microsoft's officially published Office 365 (Worldwide) IP
        address ranges, filtered to first-party M365 service areas, for use
        as an allowlist against UAL client IPs.
    .DESCRIPTION
        Many M365 audit log entries are generated by Microsoft's own backend
        services acting on a user's behalf (Defender Safe Links/Safe Attachments
        scanning, mail transport hops through protection.outlook.com, Substrate,
        etc.) rather than by the end user's actual device. Those show up with a
        Microsoft-owned IP as the ClientIP/ActorIPAddress/ClientIPAddress. This
        function queries Microsoft's Office 365 IP Address and URL web service
        (https://endpoints.office.com) so those IPs can be filtered out before
        spending threat-intel API budget on them or putting them in front of
        you in a gridview.

        CAVEAT: this pulls Microsoft's dedicated Office 365 endpoint feed
        (Exchange/SharePoint/Skype-Teams/Common service areas by default),
        never the broader "AzureCloud" tag from the general Azure Service Tags
        file. AzureCloud also covers customer-leased VMs, and attackers
        routinely host infrastructure on Azure -- allowlisting all of
        AzureCloud would create a real blind spot.

        NOTE: this used to pull from the general "Azure IP Ranges and Service
        Tags" download (confirmation.aspx?id=56519) and filter for a tag named
        "Office365". That was a bug -- that feed has no tag named "Office365"
        (it has things like AzureCloud, Dynamics365*, etc., but Office 365
        itself is published through a separate, dedicated web service), so it
        silently returned zero ranges on every run. This talks to that correct
        dedicated service instead: https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service
        Results are cached locally so you're not re-querying on every run; a
        cache older than -MaxCacheAgeDays is refreshed automatically, and a
        stale cache is used (with a warning) if the refresh fails, so a
        network hiccup mid-investigation doesn't dead-end you.
    .PARAMETER ServiceAreas
        Which Office 365 service areas to include. Default is
        @('Exchange','SharePoint','Skype','Common') -- effectively "all of
        Office 365", which is what earlier versions of this function meant by
        the (nonexistent) "Office365" service tag. Narrow it (e.g. just
        @('Exchange')) for a tighter allowlist.
    .PARAMETER CachePath
        Where to cache the downloaded ranges. Defaults to a file next to this
        module (gitignored -- see MicrosoftIPRanges.cache.json in .gitignore).
    .PARAMETER MaxCacheAgeDays
        How old the cache can be before a refresh is attempted. Default 7.
    .OUTPUTS
        An array of CIDR strings (IPv4 only).
    .EXAMPLE
        $msftRanges = Get-MicrosoftIPRanges
    .EXAMPLE
        $msftRanges = Get-MicrosoftIPRanges -ServiceAreas @('Exchange') -MaxCacheAgeDays 14
    #>
    [CmdletBinding()]
    param (
        [string[]]$ServiceAreas = @('Exchange','SharePoint','Skype','Common'),
        [string]$CachePath = (Join-Path $PSScriptRoot 'MicrosoftIPRanges.cache.json'),
        [int]$MaxCacheAgeDays = 7
    )

    $cacheIsFresh = $false
    if (Test-Path $CachePath) {
        $cacheAge = (Get-Date) - (Get-Item $CachePath).LastWriteTime
        if ($cacheAge.TotalDays -le $MaxCacheAgeDays) {
            $cacheIsFresh = $true
        }
    }

    $endpointData = $null
    if (-not $cacheIsFresh) {
        try {
            Write-Host "Fetching current Office 365 IP address ranges..." -ForegroundColor Yellow
            $clientRequestId = [guid]::NewGuid().ToString()
            $endpointData = Invoke-RestMethod -Uri "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$clientRequestId" -ErrorAction Stop
            $endpointData | ConvertTo-Json -Depth 10 | Set-Content -Path $CachePath -Encoding UTF8 -Force
            Write-Host "Office 365 IP ranges refreshed and cached to $CachePath" -ForegroundColor Green
        } catch {
            Write-Host "Could not refresh Office 365 IP ranges: $($_.Exception.Message)" -ForegroundColor Yellow
            if (Test-Path $CachePath) {
                Write-Host "Falling back to cached copy from $((Get-Item $CachePath).LastWriteTime)" -ForegroundColor Yellow
                $endpointData = Get-Content $CachePath -Raw | ConvertFrom-Json
            } else {
                Write-Host "No cached copy available -- Microsoft IP allowlisting will be skipped for this run." -ForegroundColor Red
                return @()
            }
        }
    } else {
        $endpointData = Get-Content $CachePath -Raw | ConvertFrom-Json
    }

    $cidrRanges = @()
    foreach ($entry in $endpointData) {
        if ($entry.serviceArea -in $ServiceAreas -and $entry.ips) {
            $cidrRanges += ($entry.ips | Where-Object { $_ -notmatch ':' }) # IPv4 only
        }
    }
    $cidrRanges = $cidrRanges | Sort-Object -Unique
    Write-Host "Loaded $($cidrRanges.Count) Microsoft IPv4 CIDR ranges for allowlisting (service areas: $($ServiceAreas -join ', '))" -ForegroundColor Green
    return $cidrRanges
  }

  function Get-IPInfoLookup {
    <#
    .Synopsis
      *API KEY REQUIRED* This script checks a list of IP addresses against IPinfo.io, and returns city, country, and ASN

    .Parameter IPListPath
      Path to a text file list of IP addresses separated by a carriage return.
      This function can also be used in other scripts by passing
      an array of IP addresses as the $iplistarray parameter

    .Parameter ipListArray
      An array of IP addresses passed into the function

    .Parameter ipinfoAPIKey
      API key for IP info https://ipinfo.io/
    #>
    [CmdletBinding()]
    param (
      [string]$IPListPath,
      [string]$ipinfoAPIKey,
      [string]$outputdir,
      [array]$ipListArray
    )

    if (-not $ipinfoAPIKey) {
      throw "No IPinfo API key provided. Pass -ipinfoAPIKey (sign up at https://ipinfo.io/)."
    }

    if ($ipListArray) {
      $ips = $ipListArray
    }
    elseif ($IPListPath) {
      $ips = Get-Content $IPListPath
    }
    else {
      throw "No IP addresses specified"
    }

    # Filter out blank/malformed entries so one bad line doesn't derail the whole batch
    $rawCount = @($ips).Count
    $ips = Get-clean_Ip -iplist $ips
    $skipped = $rawCount - $ips.Count
    if ($skipped -gt 0) {
      Write-Host "Skipped $skipped invalid/unparseable entr$(if ($skipped -eq 1) { 'y' } else { 'ies' }) from the input list" -ForegroundColor Yellow
    }

    Write-Host "There are $($ips.Count) IP addresses to check" -ForegroundColor Green
    $lookupfailure = 0
    $noOrg = 0
    $bogon = 0
    $ipinfourl = "http://ipinfo.io/"
    $ipInfoArray = @()
    $failures = @()

    foreach ($ip in $ips) {
      $entireURL = "$ipinfourl$ip"+"?"+"token="+$ipinfoAPIKey

      try {
        $result = Invoke-RestMethod -Uri $entireURL
      }
      catch {
        # IPinfo rate-limits (HTTP 429); give it one retry before logging a failure
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($statusCode -eq 429) {
          Write-Host "Rate limited on $ip, waiting 5s and retrying once..." -ForegroundColor Yellow
          Start-Sleep -Seconds 5
          try {
            $result = Invoke-RestMethod -Uri $entireURL
          }
          catch {
            $errorlog = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
            $errorlog | Out-File -Append $outputDir\ipinfoerrors.txt -Force -Encoding UTF8
            Write-Host $error[0].Exception -ForegroundColor Red
            Write-Host "Continuing..."
            $lookupfailure++
            $failures += [PSCustomObject]@{ Item = $ip; Reason = "rate limited, retry failed: $($_.Exception.Message)" }
            continue
          }
        }
        else {
          #Write-Host "There was an error retrieving information for $ip" -ForegroundColor Red
          $errorlog = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
          $errorlog | Out-File -Append $outputDir\ipinfoerrors.txt -Force -Encoding UTF8
          Write-Host $error[0].Exception -ForegroundColor Red
          Write-Host "Continuing..."
          $lookupfailure++
          $failures += [PSCustomObject]@{ Item = $ip; Reason = $_.Exception.Message }
          continue
        }
      }

      # write error to a log file
      # if ($result.StatusCode -ne 200) {
      #   $errorLog = "$ip, $($result.StatusCode)"
      #   $errorLog | Out-File -Append $outputDir\ipinfoerrors.txt -Force -Encoding UTF8
      #   $lookupfailure++
      #   continue
      # }

      if ($result -match "bogon") {
        # write to error log
        $errorLog = "$ip  bogon [RFC1918]"
        $errorLog | Out-File -Append $outputDir\ipinfoerrors.txt -Force -Encoding UTF8
        $bogon++
        continue
      }

      $arrayItems = [PSCustomObject]@{
        'IP' = $result.ip
        'City' = $result.city
        'State' = $result.region
        'Country' = $result.country
        'Org' = $result.org
      }

      # replace commas in org field with dashes, using a try/catch block so that if commas are not found, the user doesn't see an error
      try {
        $arrayItems.Org = $arrayItems.Org -replace ",","-"
      }
      catch {}

      # test org field for null value, if null, replace with "No Org"
      if (-not $arrayItems.Org) {
        $arrayItems.Org = "No-Org"
        $noOrg++
      }

      $ipInfoArray += $arrayItems
    }

    Write-Host "There were $noOrg records without ASN results" -ForegroundColor Green
    Write-host "There were $bogon records with RFC1918 IP addresses" -ForegroundColor Green
    if ($failures.Count -gt 0) {
      Write-Host "Failed lookups ($($failures.Count)):" -ForegroundColor Red
      $failures | ForEach-Object { Write-Host "  $($_.Item): $($_.Reason)" -ForegroundColor Red }
    }

    $ipInfoArray | Export-Csv -Path $outputDir\ipinforesults.csv -NoTypeInformation
    Return $ipInfoArray
  }



  function Get-IPQSLookup {
    <#
    .Synopsis
      *API KEY REQUIRED* This script checks a list of IP addresses against IPQS:  https://www.ipqualityscore.com/, and valuable information
    .Description
    Ipqualityscore.com is a highly regarded source of IP threat intelligence. This script has two
    optional parameters, $IPListPath and $ipListArray. If $IPListPath is specified, the script will read
    IP addresses from a text file, one per line. If $ipListArray is specified, the script will use an
    array of IP addresses passed into the function. The script will then query ipqualityscore.com and return
    the following information for each IP address: fraud_score, country_code, region, city, ISP, ASN, organization.
    The script will write the results to a file named ipQSresults.txt in the directory specified by the outputdir
    parameter. The file will be overwritten if it already exists.
    .Parameter IPListPath
      path to a list of IP addresses separated by a carriage return.
    .Parameter ipQSAPIKey
      API Key for IPQualityScore Sign up for a free account here: https://www.ipqualityscore.com/
    .Parameter outputdir
      Path to the directory where the output file will be written. File name will be ipQSresults.txt
    .Parameter ipListArray
      An array of IP addresses passed into the function
    .Inputs
      Either a text file containing a list of IP addresses, or an array of IP addresses
    .Outputs
      Outputs are written to the directory specified with thte outputdir parameter.  Two text outputs are created:
      1. A CSV file containing the results of the IPQS lookup named ipQSresults.csv, and:
      2. An error log file named ipqs_errors.txt
    #>

      [CmdletBinding()]
      param (
        [Parameter(Mandatory=$true)]
        [string]$ipQSAPIKey,
        [Parameter(Mandatory=$true)]
        [string]$outputdir,
        [string]$IPListPath,
        [array]$ipListArray
      )

      if ($ipListArray) {
        $ips = $ipListArray
      }
      elseif ($IPListPath) {
        $ips = Get-Content $IPListPath
      }
      else {
        throw "No IP addresses specified"
      }

      # Filter out blank/malformed entries so one bad line doesn't derail the whole batch
      $rawCount = @($ips).Count
      $ips = Get-clean_Ip -iplist $ips
      $skipped = $rawCount - $ips.Count
      if ($skipped -gt 0) {
        Write-Host "Skipped $skipped invalid/unparseable entr$(if ($skipped -eq 1) { 'y' } else { 'ies' }) from the input list" -ForegroundColor Yellow
      }

      Write-Host "There are $($ips.Count) IP addresses to check" -ForegroundColor Green
      $lookupfailure = 0
      $ipQSurl = "https://www.ipqualityscore.com/api/json/ip/"
      $exportarray = @()
      $failures = @()

      foreach ($ip in $ips) {
        #$entireUrl = "$ipQSurl$ipQSAPIKey/$ip?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true"
        $entireURL = "$ipQSurl"+"$ipQSAPIKey"+"/"+"$ip"+"?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true"
        Write-Verbose $entireUrl

        try {
          $result = Invoke-RestMethod -Uri $entireUrl
        }
        catch {
          # IPQS rate-limits (HTTP 429); give it one retry before logging a failure
          $statusCode = $null
          try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
          if ($statusCode -eq 429) {
            Write-Host "Rate limited on $ip, waiting 5s and retrying once..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            try {
              $result = Invoke-RestMethod -Uri $entireUrl
            }
            catch {
              $errorMessage = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
              Write-Error $errorMessage
              $errorMessage | Out-File -Append $outputDir\ipqs_errors.txt -Encoding UTF8
              $lookupfailure++
              $failures += [PSCustomObject]@{ Item = $ip; Reason = "rate limited, retry failed: $($_.Exception.Message)" }
              continue
            }
          }
          else {
            $errorMessage = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
            Write-Error $errorMessage
            $errorMessage | Out-File -Append $outputDir\ipqs_errors.txt -Encoding UTF8
            $lookupfailure++
            $failures += [PSCustomObject]@{ Item = $ip; Reason = $_.Exception.Message }
            continue
          }
        }

        if ($result -and $result.success -eq $false) {
          $errorMessage = "$ip, $($result.message)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputDir\ipqs_errors.txt -Encoding UTF8
          $lookupfailure++
          $failures += [PSCustomObject]@{ Item = $ip; Reason = $result.message }
          continue
        }
        elseif ($result -and $result.ISP -eq "Private IP Address") {
          $errorMessage = "$ip, $($result.ISP)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputDir\ipqs_errors.txt -Encoding UTF8
          $lookupfailure++
          $failures += [PSCustomObject]@{ Item = $ip; Reason = "Private IP Address" }
          continue
        }

        $ipinfo = [PSCustomObject]@{
          "ip"            = $ip
          "fraud_score"   = $result.fraud_score
          "country_code"  = $result.country_code
          "region"        = $result.region
          "city"          = $result.city
          "ISP"           = $result.ISP
          "ASN"           = $result.ASN
          "is_crawler"    = $result.is_crawler
          "timezone"      = $result.timezone
          "mobile"        = $result.mobile
          "hostresult"    = $result.host
          "proxy"         = $result.proxy
          "vpn"           = $result.vpn
          "tor"           = $result.tor
          "active_vpn"    = $result.active_vpn
          "active_tor"    = $result.active_tor
          "recent_abuse"  = $result.recent_abuse
          "bot_status"    = $result.bot_status
        }

        $exportarray += $ipinfo
      }
      Write-Host "There were $lookupfailure lookup failures out of $($ips.Count)" -ForegroundColor Yellow
      if ($failures.Count -gt 0) {
        Write-Host "Failed lookups ($($failures.Count)):" -ForegroundColor Red
        $failures | ForEach-Object { Write-Host "  $($_.Item): $($_.Reason)" -ForegroundColor Red }
      }
      $exportarray | Export-Csv -Path $outputDir\ipQSresults.csv -NoTypeInformation
      Write-Host "Results written to $outputdir\ipQSresults.csv" -ForegroundColor Green
      return $exportarray
    }

    function Get-Scamalytics_lookup {
      <#

      .Synopsis
        This script checks a list of IP addresses separated by a carriage return against the scamalytics threat intelligence service.
        You can check 5,000 per month for free.  See here: https://scamalytics.com/ip/api/pricing.
      .Description
        Scamalytics used to be my go-to source for IP intelligence. In Summer 2023, the accuracy of the results was inconsistent.
        Currently, if results are anything other than "low", I recommend checking the IP address against ipqualityscore.com.
        This script has two optional parameters, $IPListPath and $ipListArray. If $IPListPath is specified, the script will read
        IP addresses from a text file, one per line. If $ipListArray is specified, the script will use an array of IP addresses.
        The script will then query scamalytics.com and return the following information for each IP address: IP, risk, score.
        The script will write the results to a file named scamalytics.csv in the directory specified by the outputdir.
        Errors will be written to scamalyticserrors.txt in the same directory.
      .Parameter outputdir
        Path to the directory where the output file will be written. File name will be scamalytics.csv
      .Parameter ipListArray
        An array of IP addresses passed into the function.

        .Parameter IPListPath
        path to a list of IP addresses separated by a carriage return.

        .Parameter scamalyticsAPIKey
        API Key for scamalytics Get one here: https://scamalytics.com/

        #>
        [CmdletBinding()]
      param (
          [Parameter(Mandatory=$true)]
          [string]$scamalyticsAPIKey,
          [Parameter(Mandatory=$true)]
          [string]$outputdir,
          [array]$ipListArray,
          [string]$IPListPath
      )


      if($IPListPath) {$ips = Get-Content $IPListPath}
      if($ipListArray) {$ips = $ipListArray}
      if(!$IPListPath -and !$ipListArray) { throw "No IP list provided." }

      # Filter out blank/malformed entries so one bad line doesn't derail the whole batch
      $rawCount = @($ips).Count
      $ips = Get-clean_Ip -iplist $ips
      $skipped = $rawCount - $ips.Count
      if ($skipped -gt 0) {
        Write-Host "Skipped $skipped invalid/unparseable entr$(if ($skipped -eq 1) { 'y' } else { 'ies' }) from the input list" -ForegroundColor Yellow
      }

      $scamalyticsurl ="https://api11.scamalytics.com/greycastlesecurity/?key=$scamalyticsAPIKey&test=0&ip="
      $exportarray = @()
      $lookupfailure = 0
      $failures = @()
      Write-Host "Checking " $ips.count " IP addresses"
      foreach($ip in $ips){
        Write-Verbose "Checking $ip"

        #use a try/catch block to catch errors
        try{
        $result = Invoke-RestMethod -Uri $scamalyticsurl+$ip
        }
        catch{
          # Scamalytics rate-limits (HTTP 429); give it one retry before logging a failure
          $statusCode = $null
          try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
          if ($statusCode -eq 429) {
            Write-Host "Rate limited on $ip, waiting 5s and retrying once..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            try {
              $result = Invoke-RestMethod -Uri $scamalyticsurl+$ip
            }
            catch {
              $errorMessage = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
              Write-Error $errorMessage
              $errorMessage | Out-File -Append $outputDir\scamalyticserrors.txt -Encoding UTF8
              $lookupfailure++
              $failures += [PSCustomObject]@{ Item = $ip; Reason = "rate limited, retry failed: $($_.Exception.Message)" }
              continue
            }
          }
          else {
            $errorMessage = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
            Write-Error $errorMessage
            $errorMessage | Out-File -Append $outputDir\scamalyticserrors.txt -Encoding UTF8
            $lookupfailure++
            $failures += [PSCustomObject]@{ Item = $ip; Reason = $_.Exception.Message }
            continue
          }
        }
        if ($result.status -eq "error") {
          $errorMessage = "$ip, $($result.error)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputDir\scamalyticserrors.txt -Encoding UTF8
          $lookupfailure++
          $failures += [PSCustomObject]@{ Item = $ip; Reason = $result.error }
          continue
        }
        $arrayItems = [PSCustomObject]@{
          'ip' = $ip
          'risk' = $result.risk
          'score' = $result.score
        }
        $exportarray += $arrayItems
      }
      Write-Host "There were $lookupfailure lookup errors out of " $ips.Count -ForegroundColor Green
      Write-Host "There are now" $exportarray.count "suspect IP addresses" -ForegroundColor Green
      if ($failures.Count -gt 0) {
        Write-Host "Failed lookups ($($failures.Count)):" -ForegroundColor Red
        $failures | ForEach-Object { Write-Host "  $($_.Item): $($_.Reason)" -ForegroundColor Red }
      }
      $exportarray | Export-Csv -Path $outputdir\scamalytics.csv -NoTypeInformation -Encoding UTF8
      Write-Host "Results written to $outputdir\scamalytics.csv" -ForegroundColor Green
      return $exportarray

      }




