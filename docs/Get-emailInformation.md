---
external help file: Get-M365CompromiseInfo-help.xml
Module Name: M365CompromiseInfo
online version:
schema: 2.0.0
---

# Get-emailInformation

## SYNOPSIS
Uses a CSV file with InternetMessageId to get email information from Microsoft Graph API. 
It can be useful
when you have a list of InternetMessageId attributes from the M365 MailItemsAccessed audit event, and want 
to know what emails were accessed. 
This is an ancillary script to the M365compromiseInfo script.
TODO: Provide location

## SYNTAX

```
Get-emailInformation [-TenantId] <String> [-ClientId] <String> [-ClientSecret] <String> [-pathtoCSV] <Object>
 [-outputpath] <Object> [-UserId] <Object> [<CommonParameters>]
```

## DESCRIPTION
The script uses a CSV file with InternetMessageId to get email information from Microsoft Graph API. 
The CSV file requires a field with a header InternetMessageID, with the ID in the format:
\<BL3PR01MB6835B5EE5557113C20F3805ECA559@BL3PR01MB6835.prod.exchangelabs.com\> It also requires app 
registration in Azure AD with the following permissions: Mail.Read. 
After registering the app,
you will need to grant admin consent. 
You will also need a client secret for the registered app.
The script will prompt for the following information:
TenantId, ClientId, ClientSecret, path to CSV file, output path, and the UserId.
(where UserID is the account for the
mailbox you want to query.)
The script will output a CSV file with the following information: Timestamp, Subject, Senders, Recipients, Attachments,
AttachmentType, Importance, and ID.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -TenantId
{{ Fill TenantId Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClientId
{{ Fill ClientId Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClientSecret
{{ Fill ClientSecret Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -pathtoCSV
{{ Fill pathtoCSV Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -outputpath
{{ Fill outputpath Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserId
{{ Fill UserId Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
