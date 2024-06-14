function Get-M365CompromiseInfo {
<#

.Synopsis 
  This script parses Microsoft365 unified audit logs (UAL) in JSON format. If a 
  list of suspicious IP addresses is provided with the badiplist parameter, the 
  script will parse the UAL for events originating from those IP addresses, and 
  export pertinent forensic information.  
  **NB: Unless you use the badiplist parameter, an API key for at least one of 
  these services is required: IP QualityScore, IPInfo.io, or Scamalytics.com.
  **NB: The malicious activity detected by this script is entirely dependent on
  either a list of known-bad IP addresses, or the results of the IP threat intel.
 
  The easiest way to run this script is to retrieve JSON Output from the Invictus 
  Extractor found here: https://github.com/invictus-ir/Microsoft-Extractor-Suite.
  The script will work with M365 logs in JSON format regardless of how they are 
  extracted. If, for example, you have CSV output, you can use the AuditData field,
  which is json.
  

.Description
  This script parses Microsoft365 Unified Audit Logs (UAL) (JSON FORMAT ONLY). If a list of bad IP addresses is provided with the
  badiplist parameter, the script will parse the UAL for events originating from those IP addresses, and export pertinent 
  information to a CSV file. If you have a subscription for IPQualityScore, simply provide it in the ipqsAPIKey parameter, and
  the script will query IPQualityScore for each IP address in the UAL, and will consider any IP address with a fraud score of 75 or
  higher to be malicious.

  If you need to use the free IPQualityScore API, the best approach is to use the ipinfolookup switch parameter, which will
  run your IP addresses through the IPInfo.io API, and present a gridview to the user in which you should check the information,
  select suspicious entries (Based on geography or ASN) using the control key, and click OK, after which the script will either use that 
  list as the suspect IP list, or if you select the ipqslookup switch parameter, it will pass the list to the Get-IPQSLookup 
  function, again, regarding any IP address with a fraud score of 75 or higher to be malicious.  
  Please see individual function help for these by invoking: get-help Get-IPQSLookup -showwindow. 

  If the ipinfolookup switch parameter is specified, the script will retrieve all IP addresses from the M365 JSON files,
  and run them through the IPInfo.io API, then present a grid-view to the user in which you should check the information,
  and select suspicious entries. This creates a suspectIP list, which is passed to the next IP threat
  intelligence lookup function, either Get-IPQSLookup, or Get-ScamalyticsInfo, or both, if specified. 
  If you don't have a paid subscription to IPQualityScore, my recommendation is to start with ipinfolookup, 
  and try to get the number of IPs down to 199 or fewer, then specify the IPQSLookup switch parameter.
  The suspectIP list will be passed to the Get-IPQSLookup function. The script creates a badip list containing any IP
  with an IPQS fraud score of 75 or greater. The fraud score threshold is adjustable with the fraudscorethreshold parameter.
  This suspect IP list will then be used to parse the UAL for events associated
  with the IP addresses in the badIP list. The scamalyticsLookup function can be used as well, although
  it's not as useful as IPQS. The scamalyticsLookup function creates the badIP list with any address
  with a scamalytics risk score of anything other than "low".

  The script will output three CSV files: MaliciousActivities.csv, MaliciousLogons.csv, and MaliciousFileOps.csv.
  MaliciousActivities.csv will contain all events from the UAL that originated from the IP addresses in the badIPList.
  MaliciousLogons.csv will contain all logon events from the UAL that originated from the IP addresses in the badIPList.
  MaliciousFileOps.csv will contain all file operations from the UAL that originated from the IP addresses in the badIPList.
  A future iteration of this script will put them all in an excel spreadsheet.

.Parameter Searchdir
  Specifies the directory containing stored json files. The Invictus suite will create multiple json files. 
  ** NB Currently, you need to include the trailing slash at the end of the dir. This will be fixed in a future update.

.Parameter Outputpath
  Specifies path for exported event data. Output will be a file named MaliciousActivities.csv in the specified
  directory.

.Parameter ipinfolookup
  *API KEY FOR IPinfo.io REQUIRED* This is a switch that will retrieve all IP addresses from the M365 
  JSON files, and run them through the IPInfo.io API, then present
  a grid-view to the user in which you should check the information,
  select suspicious entries using the control key, and click OK. After this, 
  the script will either use that list as the suspect IP list, 
  or pass it along to the next IP lookup function, either Get-IPQSLookup,
  or Get-ScamalyticsInfo. Please see individual function help for these by 
  invoking: get-help Get-IPQSLookup -showwindow after the module is imported.

.Parameter IPQSLookup
  *IPQualityScore API KEY REQUIRED* Switch parameter that passes IP
  Addresses through the IP QUality Score database. This is the 
  best ip threatintel I have used (as of 10/21/2023), but the free
  API is limited to 200, and the commercial service is pretty
  expensive for my needs.  If you want to limit lookups, use the
  ipinfolookup  parameter as well.

.Parameter ScamalyticsLookup
  *SCAMALYTICS API KEY REQUIRED* Switch parameter which passes IPAddresses through
   the scamalytics IP lookup service.  Their data was a bit unreliable in August
   2023, it appears as if they have their problems sorted.  This script considers
   any IP address with a risk score of anything other than "low" to be malicious.
   This is likely too aggressive, but it's a good starting point, especially if you
   run the ipqualityscore parameter.


.paramater allLookups
    API KEYS FOR IPinfo.io, IPQualityScore, and Scamalytics REQUIRED* This is a switch that will run IP addresses
    through all three services, and create a badIP list based on the results.  This is the best way to go if you have a 
    free API keys and a significant number of events. 


.Parameter badIPList
  Carriage-return separated list of IP addresses deemed to be bad.

.PARAMETER fraudScoreThreshold
    Specifies the fraud score threshold for IPQS.  Default is 75.  
    This is the threshold for considering an IP address to be malicious.
    It's worth reading the IPQS documentation: 
    https://www.ipqualityscore.com/documentation/fraud-prevention-scoring
  
  .Example
  C:\Scripts\PowIRShell\Get-M365CompromiseInfo.ps1 -searchdir C:\Scripts\PowIRShell\Test_data\M365Output\UnifiedAuditLog\20231012092146\ -outputDir C:\Temp\365Results -ipinfoLookup -ipinfoAPIKey <ipinfoAPIKey> -IPQSLookup -ipqsAPIKey "<IPQSAPIKey>" -ScamalyticsLookup -scamalyticsAPIKey "<ScamalyticsAPIKey>" -Verbose

  .Inputs
  UAL (Unified Audit Logs) from Microsoft 365 tenant.  Use Invictus Extractor for
   this: https://github.com/invictus-ir/Microsoft-Extractor-Suite

.Outputs
  CSV files containing evnts of interest from the forensic perspective: 
  MaliciousActivities.csv, MaliciousLogons.csv,MaliciousMailItemsAccessed.csv, 
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
    [string]$scamalyticsAPIKey,
    [int]$fraudScoreThreshold = 75
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
    if ($percentComplete -gt 100) {
        $percentComplete = 100
    }
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
Write-Host "TenPercent: $tenPercent Progress bar will update every $tenPercent events" -ForegroundColor Green
$increment = $tenPercent
$counter = 1


$badip = @()
if($badIPList){$badip = Get-Content $badIPList}
$iplist =  Get-UniqueIPs -auditevents $Logevents # this is not necessary if a badiplist is provided



#debugging to ensure that $iplist is an array containing IP addresses only.
$iplist | out-file $outputdir\iplist.txt -Encoding ascii -Force
$suspectip = @()


    function Get-MailItemsAccessedInfo {
      <#
    .SYNOPSIS
        Retrieves "Folder" and "OperationProperties" information for the UAL MailItemsAccessed
        events.
    .INPUTS
        The "Folders" attribute of the UAL MailItemsAccessed events.
        for example:, $event.Folders (assuming MailItemsAccessed event)
    .OUTPUTS
        A PSObject with the following properties:
            - Id
            - Path
            - InternetMessageId
    #>
        param (
            [Parameter(Mandatory=$true)]
            [object]$MailItemsAccessedEvent
        )
    
        $result = @()
    
        $operationProperties = @{}
        foreach ($property in $MailItemsAccessedEvent.OperationProperties) {
            $operationProperties[$property.Name] = $property.Value
        }
    
        foreach ($folder in $MailItemsAccessedEvent.Folders) {
            foreach ($item in $folder.FolderItems) {
                $result += New-Object PSObject -Property @{
                    InternetMessageId = $item.InternetMessageId
                    Id = $folder.Id
                    Path = $folder.Path
                    MailAccessType = $operationProperties['MailAccessType']
                    IsThrottled = $operationProperties['IsThrottled']
                }
            }
        }
    
        return $result
    }
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
    $maliciousMailItemsAccessed=@()
    [array]$maliciousActivities=@()
    Write-Host "Starting to check logs for malicious activity..." -ForegroundColor Green


    Foreach($evt in $Logevents){
        if((Get-IPAddress -ipField $evt.ClientIPAddress) -in $badip -or (Get-IPAddress -ipField $evt.ActorIPAddress) -in $badip){
            #Write-Host "Debug: IP IN BADIP: $($evt.ClientIPAddress)" -ForegroundColor Yellow
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
                    'ClientIPAddress' = $evt.ClientIPAddress
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
                    'ClientIPAddress' = $evt.ClientIPAddress
                    'Operation' = $evt.Operation
                    'AuthenticationType' = $evt.AuthenticationType
                    'ObjectId' = $evt.ObjectId
                    'Platform' = $evt.Platform
                    'SourceFileName' = $evt.SourceFileName
                    'DeviceDisplayName' = $evt.DeviceDisplayName
                    'UserAgent' = $userAgent
                }
                $maliciousFileops += $arrayitems
                Write-Verbose "Added object to maliciousFileops array: $arrayitems"
            } #end elseif $evt.operation in $fileEvents
            #region
            elseif($evt.Operation -eq "MailItemsAccessed" ){
                $mailitemsaccessedInfo = Get-MailItemsAccessedInfo -MailItemsAccessedEvent $evt
                if ($evt.ClientInfoString) {
                    $ClientInfoString = $evt.ClientInfoString.replace(',','-')
                }
                foreach($item in $mailitemsaccessedInfo){
                    $arrayitems = [PSCustomObject]@{
                        'CreationTime' = $evt.CreationTime
                        'UserId' = $evt.UserId
                        'ClientIPAddress' = $evt.ClientIPAddress
                        'Operation' = $evt.Operation
                        'ApplicationId' = $evt.AppID
                        'ApplicationName' = $applicationName
                        'ClientInfoString' = $ClientInfoString
                        'MailAccessType' = $item.MailAccessType
                        'IsThrottled' = $item.IsThrottled
                        'InternetMessageId' = $item.InternetMessageId
                        'Id' = $item.Id
                        'Path' = $item.Path
                    }
                    $maliciousMailItemsAccessed += $arrayitems
                } #end foreach $item in $mailitemsaccessedInfo
            }


            else{
                $arrayitems = [PSCustomObject]@{
                    'CreationTime' = $evt.CreationTime
                    'UserId' = $evt.UserId
                    'ActorIpAddress' = $evt.ActorIpAddress
                    'ClientIPAddress' = $evt.ClientIPAddress
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

    } #end foreach $evt in $Logevents
    #$maliciousActivities | Export-Csv $outputDir\MaliciousActivities.csv -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "Count of malicious logins: $($maliciousLogins.count)"
    Write-Host "Count of malicious fileops: $($maliciousFileops.count)"
    Write-Host "Count of malicious activities: $($maliciousActivities.count)"
    Write-Host "Count of malicious mail items accessed: $($maliciousMailItemsAccessed.count)"
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
    try{
        if ($maliciousMailItemsAccessed.count -gt 0){
            $maliciousMailItemsAccessed | Export-Csv $outputDir\MaliciousMailItemsAccessed.csv -NoTypeInformation -Encoding UTF8 -Force
        }
    }
    catch{
        Write-Host "Could not export malicious mail items accessed to CSV file" -ForegroundColor Red
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


} #end function Get-M365CompromiseResults


if($badIPList){
    try{
        $badip = Get-Content $badIPList -ErrorAction Stop
        Write-Host "Bad IP list imported successfully" -ForegroundColor Green
        Write-Verbose "Debug:  $badip" #-ForegroundColor Yellow
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
}
if($allLookups){
            # Code to run when $allLookups is specified
            Write-Host 'Performing IPinfo, IPQS, and Scamalytics lookups...'
            Write-Host 'Use the gridview to select suspicious IPs' -ForegroundColor Yellow
            $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
            $suspectip | out-file $outputDir\ipinfosuspects.txt
            Write-Host 'Performing Scamalytics lookup'
            $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
            $suspectip | Out-File $outputDir\scamalyticssuspects.txt
            Write-Host 'Performing IPQS lookup'
            #TODO edit line below to use a variable for the fraud score threshold
            $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge 40).IP
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
    $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score $fraudScoreThreshold).IP
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
    $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score $fraudScoreThreshold).IP
    Write-Host 'Done performing Scamalytics and IPQS Lookup!' -ForegroundColor Green
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($ScamalyticsLookup -and !$IPQSLookup -and !$ipinfoLookup) {
    # Code to run when only $ScamalyticsLookup is specified
    Write-Host 'Performing Scamalytics lookup...'
    $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $iplist -outputDir $outputDir | Where-Object risk -ne "low").IP
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
    Write-Host 'Done performing Scamalytics lookup!' -ForegroundColor Green
}
else {
    Write-Host 'No switches specified.  Exiting.' -ForegroundColor Red
    Write-Host "Please specify at least one of the following switches: ipinfoLookup, IPQSLookup, or ScamalyticsLookup, or provide a bad IP list with the badipList argurment" -ForegroundColor Yellow
    Exit-PSSession
}


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

}