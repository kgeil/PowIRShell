---
external help file: Get-M365CompromiseInfo-help.xml
Module Name: M365CompromiseInfo
online version:
schema: 2.0.0
---

# Get-IPQSLookup

## SYNOPSIS
*API KEY REQUIRED* This script checks a list of IP addresses against IPQS:  https://www.ipqualityscore.com/, and valuable information

## SYNTAX

```
Get-IPQSLookup [-ipQSAPIKey] <String> [-outputdir] <String> [[-IPListPath] <String>] [[-ipListArray] <Array>]
 [<CommonParameters>]
```

## DESCRIPTION
Ipqualityscore.com is a highly regarded source of IP threat intelligence.
This script has two 
optional parameters, $IPListPath and $ipListArray.
If $IPListPath is specified, the script will read
IP addresses from a text file, one per line.
If $ipListArray is specified, the script will use an 
array of IP addresses passed into the function.
The script will then query ipqualityscore.com and return
the following information for each IP address: fraud_score, country_code, region, city, ISP, ASN, organization.
The script will write the results to a file named ipQSresults.txt in the directory specified by the outputdir
parameter.
The file will be overwritten if it already exists.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -ipQSAPIKey
API Key for IPQualityScore Sign up for a free account here: https://www.ipqualityscore.com/

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
File name will be ipQSresults.txt

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

### -IPListPath
path to a list of IP addresses separated by a carriage return.

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

### Either a text file containing a list of IP addresses, or an array of IP addresses
## OUTPUTS

### Outputs are written to the directory specified with thte outputdir parameter.  Two text outputs are created: 
### 1. A CSV file containing the results of the IPQS lookup named ipQSresults.csv, and: 
### 2. An error log file named ipqs_errors.txt
## NOTES

## RELATED LINKS
