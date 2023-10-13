# PowIRShell
PowerShell scripts useful for incident response and Active Directory auditing.

This is a collection of Powershell scripts which are useful for information security tasks.

The script "PowerConTalk.ps1" is not really  a script, but rather  a series of useful commands.  The first section provides ideas for auditing Active Directory, and the second section is a walkthrough of a business email compromise investigation, using some of the scripts from this repository.

## Included scripts:

* Get-IPInfoLookup.ps1: Input: list of IP addresses separated by newlines. Output: Geo-ip and ASN info for each IP. IPInfo's API. API Key required.  Get it here: *https://ipinfo.io/*
* Get-IPQSLookup.ps1: Input: list of IP addresses separated by newlines. Output: IP Quality Score's threat intelligence information. API Key required. Get it here: *https://www.ipqualityscore.com/*
* Get-Scamalytics_lookup.ps1: Input: list of IP addresses separated by newlines. Output: Scamalytics threat intelligence information. API Key required. Get it here: *https://scamalytics.com/*
* Get-M365CompromiseInfo.ps1. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow
* PowerConTalk.ps1 Used to provide a live demo of some useful PowerShell techniques and some scripts from this repository.
* Get-Artifacts.ps1: Parses evtx files and returns output usful in incident response triage. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow.
* Resolve-Hostnames.ps1: *A work in progress*.  Takes a list of hostnames and returns A and AAAA records. 
