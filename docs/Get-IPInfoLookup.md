---
external help file: Get-M365CompromiseInfo-help.xml
Module Name: M365CompromiseInfo
online version:
schema: 2.0.0
---

# Get-IPInfoLookup

## SYNOPSIS
*API KEY REQUIRED* This script checks a list of IP addresses against IPinfo.io, and returns city, country, and ASN

## SYNTAX

```
Get-IPInfoLookup [[-IPListPath] <String>] [[-ipinfoAPIKey] <String>] [[-outputdir] <String>]
 [[-ipListArray] <Array>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -IPListPath
Path to a text file list of IP addresses separated by a carriage return.
This function can also be used in other scripts by passing
an array of IP addresses as the $iplistarray parameter

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ipinfoAPIKey
API key for IP info https://ipinfo.io/

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -outputdir
{{ Fill outputdir Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ipListArray
An array of IP addresses passed into the function

```yaml
Type: Array
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
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
