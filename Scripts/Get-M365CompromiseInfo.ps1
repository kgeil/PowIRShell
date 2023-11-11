
<#

.Synopsis 
  This script parses Microsoft365 unified audit logs (UAL) in JSON format. If a list of suspicious IP addreses
  is provided with the badiplist parameter, the script will parse the UAL for events originating from those IP addresses, 
  and export pertinent forensic information.  
  **NB: Unless you use the badiplist parameter, an API key for at least one of these services:
  IP QualityScore, IPInfo.io, or Scamalytics.com.
  **NB: This script has only been tested with the JSON Output from the Invictus Extractor found here:
  https://github.com/invictus-ir/Microsoft-Extractor-Suite. It should work with M365 logs in JSON format
  regardless of how they are extracted.  If a list of suspicious IP addresses is not provided, you will need to get 
  API keys through at least one of the following services: IPinfo.io, IPQualityScore.com, or Scamalytics.com.  

  .Description
  This script parses Microsoft365 Unified Audit Logs (UAL)  (JSON FORMAT ONLY).  If a list of bad IP addresses is provided with the
  badiplist parameter, the script will parse the UAL for events originating from those IP addresses, and export pertinent 
  information to a CSV file. If you have a subscription for IPQualityScore, simply provide it in the ipqsAPIKey parameter, and
  the script will query IPQualityScore for each IP address in the UAL, and will consider any IP address with a fraud score of 75 or
  or higher to be malicious.

  If you need to use the free IPQualityScore API, The best approach is to use the ipinfolookup switch parameter, which will
  run your IP addresses through the IPInfo.io API, and present a gridview to the user in which you should check the information,
  select suspicious entries (Based on geography or ASN) using the control key, and click OK, after which the script will either use that 
  list as the suspect IP list, or if you select the ipqslookup switch parameter, it will pass the list to the Get-IPQSLookup 
  function, again, regarding any IP address with a fraud score of 75 or higher to be malicious.  
  Please see individual function help for these by invoking: get-help Get-IPQSLookup -showwindow. 

       If the geoIPlookupFirst switch parameter is specified, the script will retrieve all IP addresses from the M365 JSON files,
  and run them through the IPInfo.io API, then present a grid-view to the user in which you should check the information,
  and select suspicious entries.  This creates a suspectIP list, which is passed to the next IP threat
  intelligence lookup function, either Get-IPQSLookup, or Get-ScamalyticsInfo, or both, if specified. 
    If you don't have a paid suscription to IPQualityScore, My recommendation is to try to start with geoIPLookupFirst, 
  and try to get the number of IPs down to 199 or fewer, then specify the IPQSLookup switch parameter.
  The suspectIP list will be passed to the Get-IPQSLookup function. The script creates a badip list containing any IP
  with an IPQS fraud score of 75 or greater. This list will then be used to parse the UAL for events associated
  with the IP addresses in the badIP list.  The scamalyticsLookup function can be used as well, although
  it's not as useful as IPQS. The scamalyticsLookup function creates the badIP list with any address
  with a scamalyitcs risk score of anything other than "low".

  The script will output three CSV files: MaliciousActivities.csv, MaliciousLogons.csv, and MaliciousFileOps.csv.
  MaliciousActivities.csv will contain all events from the UAL that originated from the IP addresses in the badIPList.
  MaliciousLogons.csv will contain all logon events from the UAL that originated from the IP addresses in the badIPList.
  MaliciousFileOps.csv will contain all file operations from the UAL that originated from the IP addresses in the badIPList.
  A future iteration of this script will put them all in an excel spreadsheet.
  

  .Parameter Searchdir
  Secifies the directory containing stored json files.  The Invictus suite will create multiple json files. 
  ** NB Currently, you need to include the trailing slash at the end of the dir.  I'll fix this...

  .Parameter Outputpath
  Specifies path for exported event data. Output will be a file named MaliciousActivities.csv in the specified
  directory.

  .Parameter geo_ASNlookupFirst
  *API KEY FOR IPinfo.io REQUIRED* This is a switch that will retrieve all IP addresses from the M365 
  JSON files, and run them through the IPInfo.io API, then present
  a grid-view to the user in which you should check the information,
  select suspicious entries using the control key, and click OK, after which 
  the script will either use that list as the suspect IP list, 
  or pass it along to the next IP lookup function, either Get-IPQSLookup,
  or Get-ScamalyticsInfo.  Please see individual function help for these by 
  invoking: get-help Get-IPQSLookup -showwindow after the module is imported
  
  .Parameter IPQSLookup
  *IPQualityScore API KEY REQUIRED* Switch parameter that passes IP
  Addresses through the IP QUality Score database. This is the 
  best ip threatintel I have used (as of 10/21/2023), but the free
  API is limited to 200, and the commercial service is pretty
  expensive for my needs.  If you want to limit lookups, use the
  geo_ASNlookupFirst switch parameter as well.

  .Parameter ScamalyticsLookup
  *SCAMALYTICS API KEY REQUIRED* Switch parameter which passes IPAddresses through the scamalytics IP 
  lookup service.  Their datahas been unreliable as of August 2023, but it was once my favorite
  source.  I'm including this because I hope they get their problemssorted.

  .Parameter badIPList
  Carriage-return separated list of IP addresses deemed to be bad.  Eventually, this script will produce this list, but for now,
  just use your PowerShell Kung-Fu to create it.  For example: Once you have the JSON logs, open a 
  PowerShell console and invoke: $AuditData = Get-Content *.json | ConvertFrom-Json  # This will create an array 
  containing the M365 logs.  Next, invoke:
  $AuditData.ClientIP | Sort-Object -Unique | out-file C:\Temp\AllIP.txt -Encoding utf8 
  This will create a file containing all IP addresses. **Look at the file and clean it up!  This repository has three 
  scripts for IP analysis:
  Get-IPInfoLookup.ps1, Get-IPQSLookup.pst, and Get-Scamalytics_lookup.ps1.  If you're looking to maximize your
  IPQS free license, using Get-IPInfoLookup.ps1 and manually reviewing the output should help narrow down the 
  list of potential bad IP addresses.  Scamalytics has a generous free tier, but the data as of summer 2023 has been 
  a bit inconsistent and untrustworthy.  Hopefully Scamalytics will shine bright again soon!  

  
  .Example
  C:\Scripts\PowIRShell\Get-M365CompromiseInfo.ps1 -searchdir C:\Scripts\PowIRShell\Test_data\M365Output\UnifiedAuditLog\20231012092146\ -outputDir C:\Temp\365Results -ipinfoLookup -ipinfoAPIKey <ipinfoAPIKey> -IPQSLookup -ipqsAPIKey "<IPQSAPIKey>" -ScamalyticsLookup -scamalyticsAPIKey "<ScamalyticsAPIKey>" -Verbose

  .Inputs
  UAL (Unified Audit Logs) from Microsoft 365 tenant.  Use Invictus Extractor for this:
  https://github.com/invictus-ir/Microsoft-Extractor-Suite

  .Outputs
  CSV files containing evnts of interest from the forensic perspective: MaliciousActivities.csv, MaliciousLogons.csv, 
  and MaliciousFileOps.csv.

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$searchdir,
    [Parameter(Mandatory = $true)]
    [string]$outputDir,
    #[array]$ipListArray,
    [string]$badIPList,
    [switch]$ipinfoLookup,
    [switch]$IPQSLookup,
    [switch]$ScamalyticsLookup,
    [switch]$allLookups, # requires three API keys: ipinfo, ipqs, and scamalytics.
    [string]$ipinfoAPIKey,
    [string]$ipqsAPIKey,
    [string]$scamalyticsAPIKey
)
$ErrorActionPreference = "Stop"
function Confirm-apikeys{

    if ($ScamalyticsLookup){
        if(!$scamalyticsAPIKey){
            Write-Host "Scamalytics API key required when using scamalyticsLookup  Exiting." -ForegroundColor Red
            Write-Host "Go get one: https://scamalytics.com/ip/api/enquiry?monthly_api_calls=5000" -ForegroundColor Yellow
            break
        }
    }
    
    if ($ipinfoLookup){
        if(!$ipinfoAPIKey){
            Write-Host "ipinfo API key required when using ipinfoLookup  Exiting." -ForegroundColor Red
            Write-Host "Go get one: https://ipinfo.io/signup" -ForegroundColor Yellow
            break
        }
    }
    
    if ($IPQSLookup){
        if(!$ipqsAPIKey){
            Write-Host "IPQS API key required when using IPQSLookup  Exiting." -ForegroundColor Red
            Write-Host "Go get one: https://www.ipqualityscore.com/create-account" -ForegroundColor Yellow
            break
        }
    }
}
Confirm-apikeys #function to ensure that API keys are provided if needed.
Function Update-Progress($currentCount, $totalCount, $activity, $status) {
    $percentComplete = ($currentCount / $totalCount) * 100
    Write-Progress -Activity $activity -Status "$currentCount out of $totalCount $status have been processed" -PercentComplete $percentComplete
}
if (Get-Module -Name "M365CompromiseInfo") {
    Write-Host "Module M365CompromiseInfo is installed. Continuing..."
} else {
    Write-Host "Module M365CompromiseInfo is not installed." -ForegroundColor Yellow
    Write-Host " * Please install the M365CompromiseInfo.psd1 file"
    Write-Host " * By invoking import-module Path/To/Module/M365CompromiseInfo.psd1"
    Write-Host " * It is in the top level directory of the PowIRShell repository"
    Write-Host "Exiting"
    return
}


$Logevents = Get-AuditdataFrom365JSON -searchdir $searchdir
Write-Host There are: $Logevents.count Events -ForegroundColor Green
$tenPercent = "{0:N0}" -f ($Logevents.count/10)
Write-Host "Debug: tenPercent: $tenPercent"
$increment = $tenPercent
$counter = 1


$badip = @()
if($badIPList){$badip = Get-Content $badIPList}
$iplist =  Get-UniqueIPs -auditevents $Logevents # this is not necessary if a badiplist is provided



#debugging to ensure that $iplist is an array containing IP addresses only.
$iplist | out-file $outputdir\iplist.txt -Encoding ascii -Force
$suspectip = @()

function Get-M365CompromiseResults {
    param (
        [array]$Logevents
        ,[array]$badip
        ,[string]$outputDir
    )
    $loginevents = @("UserLoggedIn", "UserLoginFailed")
    $fileEvents = @("FileAccessed","FileAccessedExtended","FileCheckedIn","FileCheckedOut","FileCopied","FileDownloaded","FileModified","FileModifiedExtended","FileMoved","FilePreviewed","FileRecycled","FileRenamed","FileSyncDownloadedFull","FileSyncUploadedFull","FileUploaded")
    $maliciousFileops=@()
    $maliciousLogins=@()
    [array]$maliciousActivities=@()
    Write-Host "Starting to check logs for malicious activity..." -ForegroundColor Green


    Foreach($evt in $Logevents){
        if((Get-IPAddress -ipField $evt.ClientIP) -in $badip -or (Get-IPAddress -ipField $evt.ActorIPAddress) -in $badip){
            Write-Host "Debug: IP IN BADIP: $($evt.ClientIP)" -ForegroundColor Yellow
            $applicationName = Get-M365ApplicationNameFromAppID  -applicationID $evt.ApplicationId
            if($evt.Operation -in $loginevents ){
                foreach($extendedProperty in $evt.ExtendedProperties){
                    if ($extendedProperty.Name -eq "UserAgent") {
                        $userAgent = $extendedProperty.Value
                        $userAgent = $userAgent.replace(',','-')
                    }
                    if ($extendedProperty.Name -eq "RequestType") {
                        $requestType = $extendedProperty.Value
                    }
                    if ($extendedProperty.Name -eq "ResultStatusDetail") {
                        $ResultStatusDetail = $extendedProperty.Value
                    }
                    if ($extendedProperty.Name -eq "UserAuthenticationMethod") {
                        $userAuthenticationMethod = $extendedProperty.Value
                    }
                } #end foreach in extended property

                $arrayitems = [PSCustomObject]@{
                    'CreationTime' = $evt.CreationTime
                    'UserId' = $evt.UserId
                    'ActorIpAddress' = $evt.ActorIpAddress
                    'ClientIP' = $evt.ClientIP
                    'Operation' = $evt.Operation
                    'AzureADEventType' = $evt.AzureActiveDirectoryEventType
                    'ApplicationId' = $evt.ApplicationId
                    'ApplicationName' = $applicationName
                    'UserAgent' = $userAgent
                    'UserAuthMethod' = $userAuthenticationMethod
                    'RequestType' = $requestType
                    'ResultStatusDetail' = $ResultStatusDetail
                }
                $maliciousLogins += $arrayitems
            } # end if $evt.operation in $loginevents

            elseif($evt.Operation -in $fileEvents ){
                if($evt.userAgent){
                    $userAgent = $evt.UserAgent.replace(",","-")
                }
                $arrayitems= [PSCustomObject]@{
                    'CreationTime' = $evt.CreationTime
                    'UserId' = $evt.UserId
                    'ClientIP' = $evt.ClientIP
                    'Operation' = $evt.Operation
                    'AuthenticationType' = $evt.AuthenticationType
                    'ObjectId' = $evt.ObjectId
                    'Platform' = $evt.Platform
                    'SourceFileName' = $evt.SourceFileName
                    'DeviceDisplayName' = $evt.DeviceDisplayName
                    'UserAgent' = $userAgent
                }
                $maliciousFileops += $arrayitems
                Write-Host "Added object to maliciousFileops array: $arrayitems"
            } #end elseif $evt.operation in $fileEvents
            #region
            else{
                $arrayitems = [PSCustomObject]@{
                    'CreationTime' = $evt.CreationTime
                    'UserId' = $evt.UserId
                    'ActorIpAddress' = $evt.ActorIpAddress
                    'ClientIP' = $evt.ClientIP
                    'Operation' = $evt.Operation
                    'ApplicationId' = $evt.ApplicationId
                    'ApplicationName' = $applicationName
                }


                    $maliciousActivities += $arrayitems
 

            } #end else which populates $maliciousActivities
            #endregion
        }
        #Write-Host "Malicious activities: $maliciousActivities"
        $counter++
        if($counter % $increment -eq 0){
            Update-Progress -currentCount $counter -totalCount $Logevents.count -activity "Processing events" -status "events"
            $tenPercent = $tenPercent + $increment
        }
# #region Progress bar-old
#         if($counter % $increment -eq 0){
#             $percentComplete = ($counter / $Logevents.count) * 100
#             Write-Progress -Activity "Processing events" -Status "$counter out of $($Logevents.count) events have been processed" -PercentComplete $percentComplete
#             $tenPercent = $tenPercent + $increment
#         }
# #endregion
    } #end foreach $evt in $Logevents
    #$maliciousActivities | Export-Csv $outputDir\MaliciousActivities.csv -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "Count of malicious logins: $($maliciousLogins.count)"
    Write-Host "Count of malicious fileops: $($maliciousFileops.count)"
    Write-Host "Count of malicious activities: $($maliciousActivities.count)"
    try {
        if ($maliciouslogins.count -gt 0){
            $maliciousLogins | Export-Csv $outputDir\MaliciousLogons.csv -NoTypeInformation -Encoding UTF8 -Force
        } 
    }
    catch{
        Write-Host "Could not export malicious logins to CSV file" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }
    try {
        if ($maliciousFileops.count -gt 0){
            $maliciousFileops | Export-Csv $outputDir\MaliciousFileOps.csv -NoTypeInformation -Encoding UTF8 -Force
        } 
    }
    catch{
        Write-Host "Could not export malicious fileops to CSV file" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }
    try {
        if ($maliciousActivities.count -gt 0){
            $maliciousActivities | Export-Csv $outputDir\MaliciousActivities.csv -NoTypeInformation -Encoding UTF8 -Force
        } 
    }
    catch{
        Write-Host "Could not export malicious activities to CSV file" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }

    Write-Host "maliciousFileops array contents: $maliciousFileops"
    Write-Host "maliciousLogins array contents: $maliciousLogins"
    Write-Host "maliciousActivities array contents: $maliciousActivities"
}







if($badIPList){
    try{
        $badip = Get-Content $badIPList -ErrorAction Stop
        Write-Host "Bad IP list imported successfully" -ForegroundColor Green
        Write-Host "Debug:  $badip" -ForegroundColor Yellow
    }
    catch{
        Write-Host "*** Could not import bad ip list" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
        Write-Host "Exiting"
        Exit-PSSession

    }
}
if($ScamalyticsLookup -and $IPQSLookup -and $ipinfoLookup){
    $allLookups = $true
            # Code to run when $allLookups is specified
            Write-Host 'Performing IPinfo, IPQS, and Scamalytics lookups...'
            $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
            Write-Host  "Debug: Suspect IPs: " 
            $suspectip | out-file $outputDir\ipinfosuspects.txt
            Write-Host 'Performing Scamalytics lookup'
            $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
            Write-Host "Debug: Suspect IPs: " 
            $suspectip | Out-File $outputDir\scamalyticssuspects.txt
            Write-Host 'Performing IPQS lookup'
            $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge 75).IP
            write-Host "Suspect IPs: " 
            $suspectip | Out-File $outputDir\ipqssuspects.txt
            $badip = $suspectip
            Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}

elseif ($badIPList) {
    Write-Host 'Using bad IP list to parse UAL for malicious activity...'
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir 
}
elseif ($ipinfoLookup -and $IPQSLookup -and !$ScamalyticsLookup) {
    Write-Host 'Performing IPinfo and IPQS lookups...'
    $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge 75).IP
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($ipinfoLookup -and $ScamalyticsLookup -and !$IPQSLookup) {
    Write-Host 'Performing IPinfo and Scamalytics lookups...'
    $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($ipinfoLookup -and !$ScamalyticsLookup -and !$IPQSLookup) {
    Write-Host "Performing IPinfo lookup..."
    $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    Write-Host "Done performing IPinfo lookup!"
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($IPQSLookup -and $ScamalyticsLookup -and !$ipinfoLookup) {
    Write-Host 'Performing Scamalytics and IPQS lookups...'
    $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge 75).IP
    Write-Host 'Done performing Scamalytics and IPQS Lookup!' -ForegroundColor Green
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($ScamalyticsLookup -and !$IPQSLookup -and !$ipinfoLookup) {
    # Code to run when only $ScamalyticsLookup is specified
    Write-Host 'Performing Scamalytics lookup...'
    $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    Write-Host 'Done performing Scamalytics lookup!' -ForegroundColor Green
}
else {
    Write-Host 'No switches specified.  Exiting.' -ForegroundColor Red
    Write-Host "Please specify at least one of the following switches: ipinfoLookup, IPQSLookup, or ScamalyticsLookup, or provide a bad IP list with the badipList argurment" -ForegroundColor Yellow
    Exit-PSSession
}
#region Delete after testing
#switch ($true) {
    # ($badIPList){
    #     Write-Host 'Using bad IP list to parse UAL for malicious activity...'
    #     Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir 
    #     Write-Host "DEBUG: Finished Get-M365CompromiseResults"
    #     break
    # }
    # ($allLookups) {
    #     # Code to run when $allLookups is specified
    #     Write-Host 'Performing IPinfo, IPQS, and Scamalytics lookups...'
    #     $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    #     Write-Host  "Debug: Suspect IPs: " 
    #     $suspectip | out-file $outputDir\ipinfosuspects.txt
    #     Write-Host 'Performing Scamalytics lookup'
    #     $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    #     Write-Host "Debug: Suspect IPs: " 
    #     $suspectip | Out-File $outputDir\scamalyticssuspects.txt
    #     Write-Host 'Performing IPQS lookup'
    #     $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge 75).IP
    #     write-Host "Suspect IPs: " 
    #     $suspectip | Out-File $outputDir\ipqssuspects.txt
    #     $badip = $suspectip
    #     Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
    # }
    # ($ipinfoLookup -and $IPQSLookup -and !$ScamalyticsLookup) {
    #     Write-Host 'Performing IPinfo and IPQS lookups...'
    #     $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    #     $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge 75).IP
    #     Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
    # }
    # ($ipinfoLookup -and $ScamalyticsLookup -and !$IPQSLookup) {
    #     Write-Host 'Performing IPinfo and Scamalytics lookups...'
    #     $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    #     $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    #     Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
    # }
    # ($ipinfoLookup -and !$ScamalyticsLookup -and !$IPQSLookup) {
    #     Write-Host "Performing IPinfo lookup..."
    #     $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    #     Write-Host "Done performing IPinfo lookup!"
    #     Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
    # }
    # ($IPQSLookup -and $ScamalyticsLookup -and !$ipinfoLookup) {
    #     Write-Host 'Performing Scamalytics and IPQS lookups...'
    #     $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    #     $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge 75).IP
    #     Write-Host 'Done performing Scamalytics and IPQS Lookup!' -ForegroundColor Green
    # }
    # ($ScamalyticsLookup -and !$IPQSLookup -and !$ipinfoLookup) {
    #     # Code to run when only $ScamalyticsLookup is specified
    #     Write-Host 'Performing Scamalytics lookup...'
    #     $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    #     Write-Host 'Done performing Scamalytics lookup!' -ForegroundColor Green
    # }
    # default {
    #     # Code to run when no switches are specified
    #     Write-Host 'No switches specified.'
    # }
#}
#endregion Delete after testing









if ($maliciousFileops){
    $maliciousFileops | Export-Csv $outputDir\MaliciousFileOps.csv -NoTypeInformation -Encoding UTF8 -Force
}
if ($maliciousLogins){
    $maliciousLogins | Export-Csv $outputDir\MaliciousLogons.csv -NoTypeInformation -Encoding UTF8 -Force
}
if ($maliciousActivities){

    $maliciousActivities | Export-Csv $outputDir\MaliciousActivities.csv -NoTypeInformation -Encoding UTF8 -Force
}

# if(!$maliciousFileops -and !$maliciousLogins -and !$maliciousActivities){
#     Write-Host "No malicious activity found in the UAL based on the Malicious IPs provided or threat intel performed" -ForegroundColor Green
# }
Write-Host "Done!" -ForegroundColor Green
[Console]::Beep()

