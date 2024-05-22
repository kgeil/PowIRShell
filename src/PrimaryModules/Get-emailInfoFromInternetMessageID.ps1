
function Get-emailInformation{
<#
.SYNOPSIS
    Uses a CSV file with InternetMessageId to get email information from Microsoft Graph API.  It can be useful
    when you have a list of InternetMessageId attributes from the M365 MailItemsAccessed audit event, and want 
    to know what emails were accessed.  This is an ancillary script to the M365compromiseInfo script. TODO: Provide location
.DESCRIPTION
The script uses a CSV file with InternetMessageId to get email information from Microsoft Graph API. 
The CSV file requires a field with a header InternetMessageID, with the ID in the format:
<BL3PR01MB6835B5EE5557113C20F3805ECA559@BL3PR01MB6835.prod.exchangelabs.com>. If you used the Get-M365CompromiseInfo function
in this module, the output file named 'MaliciousMailItemsAccessed.csv' is formatted properly to use as input.
This function also requires app registration in Azure AD with the following permissions: Mail.Read.  After registering the app,
you will need to grant admin consent.  You will also need a client secret for the registered app.
The script will prompt for the following information:
TenantId, ClientId, ClientSecret, path to CSV file, output path, and the UserId. (where UserID is the account for the
mailbox you want to query.)
The script will output a CSV file with the following information: Timestamp, Subject, Senders, Recipients, Attachments,
AttachmentType, Importance, and ID.
.PARAMETER TenantId
    The TenantId of the Azure AD tenant.
.PARAMETER ClientId
    The ClientId of the registered app in Azure AD.
.PARAMETER ClientSecret 
    The ClientSecret of the registered app in Azure AD.
.PARAMETER pathtoCSV
    The path to the CSV file with the InternetMessageId.  The CSV file requires a field with a header InternetMessageID.
.PARAMETER outputpath
    The path to the output CSV file.
.PARAMETER UserId
    The account for the mailbox you want to query.
.EXAMPLE
    Get-emailInformation -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "12345678-1234-1234-1234-123456789012" 
    -ClientSecret "12345678-1234-1234-1234-123456789012" -pathtoCSV "C:\temp\maliciousMailItemsAccessed.csv" -outputpath "C:\temp" 
    -UserId "victimuser@greycastlesandbox.onmicrosoft.com" 
    This example will get email information from the Microsoft Graph API using the provided parameters.

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [Parameter(Mandatory=$true)]
    [string]$ClientId,
    [Parameter(Mandatory=$true)]
    [string]$ClientSecret,
    [Parameter(Mandatory=$true)]
    $pathtoCSV,
    [Parameter(Mandatory=$true)]
    $outputpath,
    [Parameter(Mandatory=$true)]
    $UserId
)
$dataFromCSV = Import-Csv $pathtoCSV
function Get-GraphApiAccessToken {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantId,
        [Parameter(Mandatory=$true)]
        [string]$ClientId,
        [Parameter(Mandatory=$true)]
        [string]$ClientSecret
    )

    $Scope = "https://graph.microsoft.com/.default"
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenRequest = @{
        client_id     = $ClientId
        scope         = $Scope
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }

    try {
        $response = Invoke-WebRequest -Uri $tokenEndpoint -Method Post -Body $tokenRequest
        if ($response.StatusCode -eq 200) {
            $tokenResponse = $response | ConvertFrom-Json
            if ($tokenResponse.access_token) {
                Write-Host "Token generated successfully" -ForegroundColor Yellow
                return $tokenResponse.access_token
            } else {
                throw "Token generation failed: No access token in response"
            }
        } else {
            $errorResponse = $response.Content | ConvertFrom-Json
            throw "Token generation failed: $($errorResponse.error_description)"
        }
    } catch {
        throw "Token generation failed: $_"
    }
}

function Get-EmailAttachmentNames {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        [Parameter(Mandatory=$true)]
        [string]$idFromMessage
    )

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://graph.microsoft.com/v1.0/users/$UserId/messages/$idFromMessage/attachments"
    Write-Host "URI: " $uri -ForegroundColor Yellow
    #sample: GET https://graph.microsoft.com/v1.0/me/messages/AAMkAGVmMDEzMTM4LTZmYWUtNDdkNC1hMDZiLTU1OGY5OTZhYmY4OABGAAAAAAAiQ8W967B7TKBjgx9rVEURBwAiIsqMbYjsT5e-T7KzowPTAAAAAAEMAAAiIsqMbYjsT5e-T7KzowPTAASoXUT3AAA=/attachments
    #graph API Documentation: GET /users/{id | userPrincipalName}/messages/{id}/attachments

    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    #Write-Host "Response: " $response.value

    $result = @()

    foreach ($attachmentinfo in $response.value) {
        $result += New-Object PSObject -Property @{
            Timestamp = $attachmentinfo.lastModifiedDateTime
            Name = $attachmentinfo.name
            ContentType = $attachmentinfo.contentType
        }
    }

    return $result
}
function Get-EmailDetails {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        [Parameter(Mandatory=$true)]
        [string]$InternetMessageId
    )

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://graph.microsoft.com/v1.0/users/$UserId/messages?`$filter=internetMessageId eq '$InternetMessageId'"

    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    Write-Host "Response: " $response.value

    $result = @()

    foreach ($message in $response.value) {
        $attachments = $null
        if ($message.hasAttachments) {
            $attachments = Get-EmailAttachmentNames -AccessToken $AccessToken -UserId $UserId -idFromMessage $message.id
        }

        $result += New-Object PSObject -Property @{
            Timestamp = $message.receivedDateTime
            Subject = $message.subject
            Senders = $message.from.emailAddress.address
            Recipients = $message.toRecipients.emailAddress.address
            Attachments = ($attachments.name -join "; ")
            AttachmentType = ($attachments.contentType -join "; ")
            Importance = $message.importance
            ID = $message.id
        }
    }

    return $result
}

foreach ($item in $dataFromCSV.InternetMessageId){
    $accessToken = Get-GraphApiAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Verbose "Access Token: $accessToken"
    $emailDetails = Get-EmailDetails -AccessToken $accessToken -UserId $UserId -InternetMessageId $item
    $emailDetails | Export-Csv -Path $outputpath\emaildetails.csv -Append -NoTypeInformation -Force
}

}