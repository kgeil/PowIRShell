<#

.Synopsis 
  This script checks a list of IP addresses against IPQS:  https://www.ipqualityscore.com/, and valuable information

  .Parameter IPListPath
  path to a list of IP addresses separated by a carriage return.

  .Parameter ipQSAPIKey
  API Key for IPQualityScore

  #>

  param (
    [string]$IPListPath,
    [string]$ipQSAPIKey,
    [string]$outputdir 

)

$headerRow = "IP,fraud_score,country_code,region,city,ISP,ASN,organization,is_crawler,timezone,mobile,host,proxy,vpn,tor,active_vpn,active_tor,recent_abuse,bot_status"
$headerRow | out-file $outputDir\ipQSresults.txt -Force -Encoding UTF8

$ips = Get-Content $IPListPath
#Sample query:$result = Invoke-WebRequest "https://www.ipqualityscore.com/api/json/ip/<IPQS-APIKey>/87.249.138.28?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true" -UseBasicParsing
$ipQSurl ="https://www.ipqualityscore.com/api/json/ip/"
$exportarray = @()
foreach($ip in $ips){
  $entireURL = "$ipQSurl"+"$ipQSAPIKey"+"/"+"$ip"+"?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true"
  write-host "DEBUG: " $entireURL
    $result = Invoke-WebRequest $entireUrl+$ip -UseBasicParsing
    $content = ConvertFrom-Json $result.Content

    $fraud_score	 = $content.fraud_score
    $country_code	 = $content.country_code
    $region	 = $content.region
    $city	 = $content.city
    $ISP	 = $content.ISP
      try{$ISP = $ISP.replace(',','-')}
      catch{}
    $ASN	 = $content.ASN
      try{$ASN = $ASN.replace(',','-')}
      catch{}
    $organization	 = $content.organization
      try{$organization = $organization.replace(',','-')}
      catch{}    
    $is_crawler	 = $content.is_crawler
    $timezone	 = $content.timezone
    $mobile	 = $content.mobile
    $hostresult	 = $content.host
    $proxy	 = $content.proxy
    $vpn	 = $content.vpn
    $tor	 = $content.tor
    $active_vpn	 = $content.active_vpn
    $active_tor	 = $content.active_tor
    $recent_abuse	 = $content.recent_abuse
    $bot_status	 = $content.bot_status


$linetoadd = "$ip,$fraud_score,$country_code,$region,$city,$ISP,$ASN,$organization,$is_crawler,$timezone,$mobile,$hostresult,$proxy,$vpn,$tor,$active_vpn,$active_tor,$recent_abuse,$bot_status"
Write-Host $linetoadd
$linetoadd | Out-File -Append $outputDir\ipQSresults.txt -Encoding UTF8

} 