function Get-clean_Ip($iplist){
  [CmdletBinding()]
  $cleanIPlist = @()
  $4Over6regex = "\:\:ffff\:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
  foreach($ip in $iplist){
    try{ 
      #TODO: Consider justing using 3 really good regexes
      #instead of this -replace thing.
      $ip = $ip -replace ":\d{4,6}$",""
      $ip = $ip -replace "[\[\]]"
        if ($ip -notmatch $4Over6regex){
          $cleanIPlist += $ip
          }
    }
    catch{

    }
  }

Return $cleanIPlist
}
function Get-IplistFrom365JSON (){
  [CmdletBinding()]
  param($searchdir)
  
  $ErrorActionPreference = "Stop"
  # Just making sure the directory is set properly
  if ($searchdir -match "^.*\\$"){
    #$jsonpath = "$searchdir*.json"
    $searchdir = $searchdir -replace "\\$",""
    $jsonfiles=@()
    $jsonfiles = Get-ChildItem -Path $searchdir
    Write-Verbose "There are  $($jsonfiles.count)  JSON files to process"
    if($jsonfiles.count -eq 0){
     Write-Verbose "No JSON files found, exiting"
     #Exit
    }
  }

  try{
    Write-Host "Debug: Retrieving logs from $searchdir "
    Write-Host 'DEBUG: invoking Get-Content '$searchdir
  $auditevents = (Get-Content $searchdir\*.json | ConvertFrom-Json)
  Write-Host "There are " $auditevents.count " Events" -ForegroundColor Yellow
  }
  catch{
    #[Microsoft.PowerShell.Commands.GetContentCommand, ItemNotFound]
    Write-Host -ForegroundColor Red "There was a problem retrieving json files from the selected directory: " $searchdir
    Write-Host -ForegroundColor Yellow "The script does not recursively search for JSON files"
    break
  }
  
  $allip = $auditevents.ClientIP | Sort-Object -Unique
  $allip += $auditevents.ActorIPAddress | Sort-Object -Unique
  $allip = $allip | Sort-Object -Unique
  Write-Host "There are" $allip.count " Unique IP Addresses" -ForegroundColor Green
  Write-Host "cleaning up output before presenting" -ForegroundColor Green
  
  $cleanIPs = Get-clean_Ip -iplist $allip
  Return $cleanIPs
}

function Get-IPInfoLookup{
   <#
  .Synopsis 
    This script checks a list of IP addresses against IPinfo.io, and returns city, country, and ASN
  
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
      $ipListArray 
  
  )
  <#
  
  .Synopsis 
    This script checks a list of IP addresses against IPinfo.io, and returns city, country, and ASN
  
    .Parameter IPListPath
    path to a list of IP addresses separated by a carriage return.
  
    .Parameter ipinfoAPIKey
    API key for IP info https://ipinfo.io/
    #>
  
  $ipInfoArray = @()  
  $headerRow = "IP,City,Country,Org"
  $headerRow | out-file $outputDir\ipinforesults.txt -Force -Encoding UTF8
  if ($IPListPath){
  $ips = Get-Content $IPListPath
  }
  else {$ips = $ipListArray}
  if($ips.count -eq 0){
    Write-Host "You must provide a list of IP addresses. Exiting..."
  }

  write-host "Checking " $ips.count " addresses" -ForegroundColor Green
  
  $ipinfourl ="http://ipinfo.io/"
  foreach($ip in $ips){
    $entireURL = "$ipinfourl$ip"+"?"+"token="+$ipinfoAPIKey
    #write-host "Debug Entire URL = " $entireURL
    $result = Invoke-WebRequest $entireUrl -UseBasicParsing
    #write-host "Debug " $result
    $content = ConvertFrom-Json $result.Content
    $city = $content.city
    $country = $content.country
    try{
      #write-host "Debug: replacing commas in " $content.org
      $org = ($content.org).replace(',','-')
      
    }
    catch{
  
      $org = $content.org
      #write-host "catch block!! " $org
      $noOrg ++
    }
    $arrayItems = [PSCustomObject]@{
      'IP' = $ip
      'City' = $city
      'Country' = $country
      'Org' = $org

    }


    $linetoadd = "$ip,$city,$country,$org"
    $linetoadd | Out-File -Append $outputDir\ipinforesults.txt -Force -Encoding UTF8
    $ipInfoArray += $arrayItems
  } 
  Write-host "There were " $noOrg.count " records without ASN results" -ForegroundColor Green
  
  #region ***********TODO*********
    
    <#
    Todo #1:
      
      Catch the following error:
      Invoke-WebRequest : {
      "status": 404,
      "error": {
        "title": "Wrong ip",
        "message": "Please provide a valid IP address"
      }
    }
    At C:\Scripts\PowerSIEM\ipinfo.ps1:33 char:13
    +   $result = Invoke-WebRequest $entireUrl -UseBasicParsing
    +             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebException
        + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand
      
      ** Write a function to take the user provided IP list, verify valid IPs with regex, and create the lookup
      array from that. This will do away with most 404 errors.
      
  
    #>
  #endregion ******TODO********
  Return $ipInfoArray
  }