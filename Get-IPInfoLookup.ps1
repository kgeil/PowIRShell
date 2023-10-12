param (
    [string]$IPListPath,
    [string]$ipinfoAPIKey,
    [string]$outputdir 

)

<#

.Synopsis 
  This script checks a list of IP addresses against IPinfo.io, and returns city, country, and ASN

  .Parameter IPListPath
  path to a list of IP addresses separated by a carriage return.

  .Parameter scamalyticsAPIKey
  API Key for scamalytics
  #>

  
$headerRow = "IP,City,Country,Org"
$headerRow | out-file $outputDir\ipinforesults.txt -Force -Encoding UTF8
$ips = Get-Content $IPListPath

write-host "Checking " $ips.count " addresses" -ForegroundColor Green

$ipinfourl ="http://ipinfo.io/"
$exportarray = @()
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
  $linetoadd = "$ip,$city,$country,$org"
  #Write-Host $linetoadd
  $linetoadd | Out-File -Append $outputDir\ipinforesults.txt -Force -Encoding UTF8

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