param (
    [string]$IPListPath,
    [string]$scamalyticsAPIKey,
    [string]$outputdir 

)

<#

.Synopsis 
  This script checks a list of IP addresses separated by a carriage return against the scamalytics threat intelligence service.
  You can check 5,000 per month for free.  See here: https://scamalytics.com/ip/api/pricing

  .Parameter IPListPath
  path to a list of IP addresses separated by a carriage return.

  .Parameter scamalyticsAPIKey
  API Key for scamalytics Get one here: https://scamalytics.com/

  #>
$ips = Get-Content $IPListPath


$scamalyticsurl ="https://api11.scamalytics.com/greycastlesecurity/?key=$scamalyticsAPIKey&test=0&ip="
$exportarray = @()
foreach($ip in $ips){
$result = Invoke-WebRequest $scamalyticsurl+$ip -UseBasicParsing
$content = ConvertFrom-Json $result.Content
$risk = $content.risk
$score = $content.score

$linetoadd = "$ip,$risk,$score"
Write-Host $linetoadd
$linetoadd | Out-File -Append $outputDir\Scamalyticsresults.txt -Force 

} 

