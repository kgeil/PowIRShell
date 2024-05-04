# PowIRShell
PowerShell scripts useful for incident response and Active Directory auditing.

This is a collection of Powershell scripts which are useful for information security tasks.

The script "PowerConTalk.ps1" is not really  a script, but rather  a series of useful commands.  The first section provides ideas for auditing Active Directory, and the second section is a walkthrough of a business email compromise investigation, using some of the scripts from this repository.

## Included scripts:

* Get-M365CompromiseInfo.ps1.   Analyzes M365 logs (in JSON) and checks IP addresses against threat intelligence services. and outputs a csv file of actions taken originating from suspicous IP addresses. Requires API keys to one of these services: IPQS, Scamalytics, or ipinfo.io. Recommended usage is to use ipinfo.io, then select IP addresses of interest in the PowerShell grid-view that pops up, which will then get passed IPQS, scamalytics, or both.  *If you pay for an IPQS subscription, it will be fastest if you just use that service.* IPQS is well-known for its accuracy, but it's expensive, and their free API lookups are quite limited.
* Get-IPInfoLookup.ps1: Input: list of IP addresses separated by newlines. Output: Geo-ip and ASN info for each IP. Uses IPInfo's API. API Key required.  Get it here: *https://ipinfo.io/*
* Get-IPQSLookup.ps1: Input: list of IP addresses separated by newlines. Output: IP Quality Score's threat intelligence information. API Key required. Get it here: *https://www.ipqualityscore.com/*
* Get-Scamalytics_lookup.ps1: Input: list of IP addresses separated by newlines. Output: Scamalytics threat intelligence information. API Key required. Get it here: *https://scamalytics.com/*

* PowerConTalk.ps1 Used to provide a live demo of some useful PowerShell techniques and some scripts from this repository.
* Get-Artifacts.ps1: Parses evtx files and returns output usful in incident response triage. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow.
* Resolve-Hostnames.ps1: *A work in progress*.  Takes a list of hostnames and returns A and AAAA records. I needed it for a job, and it landed in this collection...
