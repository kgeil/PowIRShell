﻿##################Basics:#################
cd # linux commands are aliased to PowerShell commands! Technically, cd is aliased to 
#PowerShell's set-location cmdlet
cd C:\Us#<hit the tab key!>  Tab completion is critical to success

mkdir C:\scripts\output -Force # make a directory.  -Force is necessary to create a directory with a parent directory that doesn't exist
# I typically put scripts in C:\scripts.  We will use this directory for the rest of the demo
mkdir C:\temp # if you already have a C:\temp directory, this will throw an error.
echo 'this is a test' | Out-File 'C:\temp\file with spaces in name'
# retrieve short 8.3 names: A way to easily handle files with spaces in file names
cmd.exe /c "dir /x" C:\temp

Get-Content $env:USERPROFILE\AppData<hit tab key> # this will auto-complete with the path to your AppData directory
C:\Users\KevinGeil\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | Select-String 'mystr'
# the above command will get-the content of the history file, and search for 'mystr' in the file.
# if you want to just scroll through everything in the history file, you can use the following command:
Get-Content $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | out-host -Paging
# the -Paging flag is like the Linux "less" command.  It allows you to scroll through the output one page at a time
Get-History # this command will show you the history of commands you've run in the current session

# Pipelining: PowerShell is good at piping the output of one command into another command.
# We have already used this in a few places.

#finding commands:  

Get-command *json* # gcm is a built-in alias

#Getting help:
Get-Help ConvertFrom-Json -ShowWindow # opens help for the command in a nice, searchable window.

#Get-help <command> -ShowWindow
# variables: start with a $, convention is to start lowercase and use $camelCase
$myvar = 3
$myvar + 8

# But that's boring:  Arrays are where much of the fun is in PowerShell.
$myArray = @() #initialize empty array.  This is usually not necessary, but 
# it can help if PowerShell's auto-typing gets things wrong...
$myArray = @(3,7,9.12,18,33,55,42,42,42)
Get-ExecutionPolicy
$services = Get-Service
$services.Count
$services[0] | Get-Member
$services | where status -eq 'Running' | select ServiceName
$running = $services | where status -eq 'running'
$running.Count
$running[44] | ft
Dir env:\
$env:OS
$env:PATH
Set-item env:\scamalyticsAPIKey -value "<apikey>"
$env:scamalyticsAPIKey


#Region AD User Queries
#Descriptions for each command are above the command itself
# The queries below require Microsoft Remote Server Administration Tools (RSAT)
# The easiest way to install RSAT:
dism /online /add-capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
dism /online /add-capability /CapabilityName:Rsat.Dns.Tools~~~~0.0.1.0

#Load the AD commandlets.  This step isn't necessary, but speeds things up.
Import-Module activedirectory

# MS reference on finding stale accounts: https://social.technet.microsoft.com/wiki/contents/articles/22461.understanding-the-ad-account-attributes-lastlogon-lastlogontimestamp-and-lastlogondate.aspx
# The command below presents dialog box for entering a credential and storing it securely in the $cred variable
$cred = Get-Credential 

myArray = @() # initialize a variable, $domainusers as an empty array.  Occasionally, you want output to be 
# stored as an array, and PowerShell automatically types your output as a string

# The query below retrieves all properties for all domain users, and stores it in the $domainusers array variable
# PowerShell's auto-variable typing works well most of the time, and in this case, it populates
# an array for us with all domain user objects.  
$domainusers=Get-ADUser -filter * -Properties * -Server <DC-IP> -Credential $cred

# Optional:  export the $domainusers array into an xml text file for future storage.  It can be useful to keep 
# historical copies of this around for comparison over time
$domainusers | Export-Clixml TrainingUsers.xml

# If you have stored xml output, import usersexport00.xml into the $domainusers variable 
$domainusers = Import-Clixml .\TrainingUsers.xml

#show number of objects in $domainusers array
$domainusers.count

# Populate an array called $activeusers from the $domainusers array, selecting accounts which are enabled
$activeusers = $domainusers | where enabled -eq true

#reference on AD attribute to use forfinding stale accounts: https://social.technet.microsoft.com/wiki/contents/articles/22461.understanding-the-ad-account-attributes-lastlogon-lastlogontimestamp-and-lastlogondate.aspx

# Produce a list of users who  are enabled, and haven't logged in since 01/01/2023
$activeusers | select SamAccountName, LastLogonDate | where LastLogonDate -lt '01/01/2023'

# Populate an array called $olderusers by selecting accounts from the $activeusers  array which haven't logged in since 01/01/2023
$olderusers = $activeusers | where LastLogonDate -lt '01/01/2023'

# display number of older users
$olderusers.count

#Display available attributes for an account in the $olderusers array 
$olderusers | get-member 

# Display interesting info about the user accounts in the $olderusers array
$olderusers | select SamAccountName, Description, LastLogonDate | out-host -paging  #out-host -paging is like the Linux "less" command

# Another approach:
$domainusers | where {$_.LastLogonDate -lt '01/01/2023' -and $_.enabled -eq 'true'} | select samAccountName, LastLogonDate 
# Note the use of the default variable '$_' as well as the necessity to use where-object before select (because $_ refers to the current item in the
# pipeline

#Endregion AD User Queries

#Region AD Group Queries
#sample AD Group queries
#store credential in $cred.  Any domain credential will suffice
$cred = get-credential #if you used this above, $cred still works

#Create an array variable named $groups, populate it with ad groups
# Note the syntax here of using @(<Command goes here>).  This ensures that the variable is an array
# Sometimes PowerShell's auto-typing gets this wrong, so I want to highlight it here 
$groups = @(Get-ADGroup -Filter * -Properties * -Server <DC-IP> -Credential $cred)

#display the names of all groups with "*admin*" in the name
$groups | where name -like "*admin*" |select Name

#Display the name of the group, and the members of the "Domain Admins" group, then the "Enterprise Admins" Group.  
#ALWAYS LOOK AT BOTH OF THESE!
$groups | where name -eq "Domain Admins" | select Name, Members
$groups | where name -eq "Enterprise Admins" | select Name, Members
#Endregion AD Group Queries

#Region AD Computer Queries
## Sample AD Computer queries
#store credential in $cred.  Any domain credential will suffice
$cred = get-credential
$computers = Get-ADComputer -filter * -Properties *  -Server <DC-IP> -Credential $cred
#export array for long-term storage
$computers | Export-Clixml ADMachines.xml
#import from saved xml
$computers=Import-Clixml .\trainingComputers.xml
#create new array with machines with a LastLogonDate after 02/01/2023
$activemachines = $computers |where LastLogonDate -gt '02/01/2023'
# display list of operating systems in the $activemachines object with count
$activemachines.operatingsystem | group -NoElement | sort Count -Desc | Format-Table -AutoSize

#create an array of outdated operating systems
$outdatedOS = ('Windows 2000 Server','Windows 7 Enterprise','Windows 7 Professional','Windows Server 2003','Windows Server 2008 R2 Standard','Windows Server 2008
Standard','Windows Server 2008 R2 Standard','Windows XP Professional','Windows Server 2012 R2 Standard')

#Report on machines with old OS:
$activemachines |where OperatingSystem -in $outdatedOS | select name, IPV4Address, OperatingSystem
#Endregion AD Computer Queries


# hashtables are a powerful data structure in PowerShell.  They are like dictionaries in Python
# and can be used to store key-value pairs.  They are also used to store configuration data
$myports = @(110,143) # create an array with some ports
$myhash = @{}
$myports = @(53,110,143,443)
# Test-Netconnection is a lovely little utility:  https://docs.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection?view=windowsserver2022-ps
foreach($port in $myports){$myhash.add($port,(Test-NetConnection 8.8.8.8 -Port $port).TcpTestSucceeded)}



##################Begin M365 Audit############################
<#
Audit data was generated by operating a sandbox M365 tenant. 
Data was extracted using the invictus extractor suite:
https://github.com/invictus-ir/Microsoft-Extractor-Suite
UAL Log fields are (mostly) described here:
https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
When we discuss IP addresses below:
"The actorIPAddress property is used to identify the IP address of the user or
service account that performed an action. It is a core dimension in the 
Office 365 auditing concepts and is included in every audit record":
 https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema

"Clientip is a location-specific property that identifies the IP address of 
the client device used for a login event. It is included in Azure 
Active Directory events and can be used to determine the location of a 
login event":
https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties
#>
cd 'C:\Scripts\PowIRShell\Test_data\M365Output\'
#Create an array with M365 logs (json format required)
$auditdata = get-content .\UnifiedAuditLog\20231012092146\*.json | ConvertFrom-Json

# Make sure it worked
$auditdata.count
#take a look at an event to see what we have.
$auditdata[099] | gm #gm is short for get-member 
$auditdata[099] |fl #fl is short for format-list
#retrieve unique ClientIP addresses
$allip = $auditdata.ActorIPAddress | Sort-Object -Unique

# if you need to deal with the ClientIP (usually the case but not for this demo)
$clientIPAddresses = $auditdata.ClientIP | Sort-Object -Unique 
foreach($ip in $clientIPAddresses){
  try{$allip += $ip -replace ":\d{4,6}$",""  }
  catch{$allip += $ip }
  }

#write IPs to test to file
$ipstotest =  $allip | Sort-Object -Unique 
$ipstotest | out-file C:\Scripts\PowIRShell\test-IPs.txt -Encoding utf8
#NB*** For Demo, use test-IPs-short.txt, which is edited for brevity

# Take a look at all of the operations
$auditevents.Operation | Sort-Object -Unique


# navigate to the PowIRShell directory
cd C:\Scripts\PowIRShell

# This will give you a potential bad IP list just based on geography and ASN 
.\Get-IPInfoLookup.ps1 -IPListPath .\test-IPs.txt -ipinfoAPIKey "<API KEY HERE>" -outputdir .\ScriptOutput\

#manually look through the results from Get-IPInfoLookup and determine your suspect IP addresses and create badip.txt in the PowIRShell directory

#run ipqualityscore script against your suspect IP addresses to get a second opinion.  If you want to pay for IPQS, go for this first,
# but it's expensive for me, so I try to edit my suspect IP list using other scripts before IPQS, which limits free users to 50 lookups per day.
.\Get-IPQSLookup.ps1 -IPListPath .\badip.txt -ipQSAPIKey "<API KEY HERE>" -outputdir .\ScriptOutput

# run the Get-M365CompromiseInfo.ps1 script
.\Get-M365CompromiseInfo.ps1 -searchdir .\Test_data\M365Output\UnifiedAuditLog\20231012092146\ -outputDir .\ScriptOutput -badIPList .\badip.txt