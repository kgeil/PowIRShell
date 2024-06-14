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
    $allip = $allip | Sort-Object -Unique
    $allip = Get-clean_Ip -iplist $allip
    Return $allip
    
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
  
    if ($ipListArray) {
      $ips = $ipListArray
    }
    elseif ($IPListPath) {
      $ips = Get-Content $IPListPath
    }
    else {
      throw "No IP addresses specified"
    }
  
    Write-Host "There are $($ips.Count) IP addresses to check" -ForegroundColor Green
    $lookupfailure = 0
    $noOrg = 0
    $bogon = 0
    $ipinfourl = "http://ipinfo.io/"
    $ipInfoArray = @()
  
    foreach ($ip in $ips) {
      $entireURL = "$ipinfourl$ip"+"?"+"token="+$ipinfoAPIKey
  
      try {
        $result = Invoke-RestMethod -Uri $entireURL
      }
      catch {
        #Write-Host "There was an error retrieving information for $ip" -ForegroundColor Red
        $errorlog = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
        $errorlog | Out-File -Append $outputDir\ipinfoerrors.txt -Force -Encoding UTF8  
        Write-Host $error[0].Exception -ForegroundColor Red
        Write-Host "Continuing..."
        $lookupfailure++
        continue
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
        'Region' = $result.region
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
    
      Write-Host "There are $($ips.Count) IP addresses to check" -ForegroundColor Green
      $lookupfailure = 0
      $ipQSurl = "https://www.ipqualityscore.com/api/json/ip/"
      $exportarray = @()
    
      foreach ($ip in $ips) {
        #$entireUrl = "$ipQSurl$ipQSAPIKey/$ip?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true"
        $entireURL = "$ipQSurl"+"$ipQSAPIKey"+"/"+"$ip"+"?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true"
        Write-Verbose $entireUrl
    
        try {
          $result = Invoke-RestMethod -Uri $entireUrl
        }
        catch {
          $errorMessage = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputDir\ipqs_errors.txt -Encoding UTF8
          $lookupfailure++
          continue
        }
    
        if ($result -and $result.success -eq $false) {
          $errorMessage = "$ip, $($result.message)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputDir\ipqs_errors.txt -Encoding UTF8
          $lookupfailure++
          continue
        }
        elseif ($result -and $result.ISP -eq "Private IP Address") {
          $errorMessage = "$ip, $($result.ISP)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputDir\ipqs_errors.txt -Encoding UTF8
          $lookupfailure++
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
      $exportarray | Export-Csv -Path $outputDir\ipQSresults.csv -NoTypeInformation
      Write-Host "Results written to $outputdir\ipQSresults.csv" -ForegroundColor Green
      Write-Host "There were $lookupfailure lookup failures out of $($ips.Count)" -ForegroundColor Yellow
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
      if(!$IPListPath -and !$ipListArray) {Write-Host "No IP list provided.  Exiting."; break}
      $scamalyticsurl ="https://api11.scamalytics.com/greycastlesecurity/?key=$scamalyticsAPIKey&test=0&ip="
      $exportarray = @()
      $lookupfailure = 0
      Write-Host "Checking " $ips.count " IP addresses"
      foreach($ip in $ips){
        Write-Verbose "Checking $ip"
      
        #use a try/catch block to catch errors
        try{
        $result = Invoke-RestMethod -Uri $scamalyticsurl+$ip
        }
        catch{
          $errorMessage = "There was an error retrieving information for "+ "$ip $($_.Exception.Message)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputDir\scamalyticserrors.txt -Encoding UTF8
          $lookupfailure++
          continue
        }
        if ($result.status -eq "error") {
          $errorMessage = "$ip, $($result.error)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputDir\scamalyticserrors.txt -Encoding UTF8
          $lookupfailure++
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
      $exportarray | Export-Csv -Path $outputdir\scamalytics.csv -NoTypeInformation -Encoding UTF8
      Write-Host "Results written to $outputdir\scamalytics.csv" -ForegroundColor Green
      return $exportarray
      
      } 
      
      



