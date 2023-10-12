param (
    [string]$HostListPath,
    [string]$dnsServer="1.1.1.1",
    [string]$outputdir 

)

<#

.Synopsis 
  Takes a list of hostnames and retrieves their IP address

  .Parameter HostListPath
  path to a list of hostnames separated by a carriage return.


  #>
  #TODO: deal with hosts that resolve to multiple addresses, like pin.ceros.map.fastly.net
  $namesToCheck = Get-Content $HostListPath

  foreach($hostToCheck in $namesToCheck){
  try {
      $result = Resolve-DnsName $hostToCheck -ErrorAction Stop
  }
  catch {
  Write-Host "DEBUG: failed to resolve "$hostToCheck -ForegroundColor Yellow
      $qtype = 'A' # we need to use querytype later, so this just getst this out of the way now.
      $result = [PSCustomObject]@{
      'QueryType' = $qtype
      'Name' = $hostToCheck
      'IPAddress' = '0.0.0.0'
      }
  }
  foreach($r in $result){
      if($r.QueryType -in @('A','AAAA')  ){
        Write-Host $r.Name,$r.IPAddress
        $lineToWrite = $r.Name+','+$r.IPAddress
        $lineToWrite | Out-File -Append $outputdir\resolvedhosts.txt -Force -Encoding utf8  
      }

  }

  }