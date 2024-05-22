---
external help file: Get-M365CompromiseInfo-help.xml
Module Name: M365CompromiseInfo
online version:
schema: 2.0.0
---

# Get-Scamalytics_lookup

## SYNOPSIS
This script checks a list of IP addresses separated by a carriage return against the scamalytics threat intelligence service.
You can check 5,000 per month for free. 
See here: https://scamalytics.com/ip/api/pricing.

## SYNTAX

```
Get-Scamalytics_lookup [-scamalyticsAPIKey] <String> [-outputdir] <String> [[-ipListArray] <Array>]
 [[-IPListPath] <String>] [<CommonParameters>]
```

## DESCRIPTION
Scamalytics used to be my go-to source for IP intelligence.
In Summer 2023, the accuracy of the results was inconsistent.
Currently, if results are anything other than "low", I recommend checking the IP address against ipqualityscore.com.
This script has two optional parameters, $IPListPath and $ipListArray.
If $IPListPath is specified, the script will read
IP addresses from a text file, one per line.
If $ipListArray is specified, the script will use an array of IP addresses.
The script will then query scamalytics.com and return the following information for each IP address: IP, risk, score.
The script will write the results to a file named scamalytics.csv in the directory specified by the outputdir.
Errors will be written to scamalyticserrors.txt in the same directory.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -scamalyticsAPIKey
API Key for scamalytics Get one here: https://scamalytics.com/

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

### -outputdir
Path to the directory where the output file will be written.
File name will be scamalytics.csv

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

### -ipListArray
An array of IP addresses passed into the function.

```yaml
Type: Array
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPListPath
path to a list of IP addresses separated by a carriage return.

```yaml
Type: String
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
