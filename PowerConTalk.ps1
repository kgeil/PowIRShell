#Basics:  
cd # linux commands are aliased to PowerShell commands! Technically, cd is aliased to 
#PowerShell's set-location cmdlet
cd C:\Us#<hit the tab key!>  Tab completion is critical to success

#find commands:  

Get-command *json*

#Get-help <command> -ShowWindow
# variables: start with a $, convention is to start lowercase and use $camelCase
$myvar = 3
$myvar + 8

# But that's boring:  Arrays are where much of the fun is in PowerShell.
myArray = @() #initialize empty array.  This is usually not necessary, but 
# it can help if PowerShell's auto-typing gets things wrong...
$myArray = @(3,7,9.12,18,33,55,42,42,42)

#Descriptions for each command are above the command itself
# The queries below require Microsoft Remote Server Administration Tools (RSAT)
# The easiest way to install RSAT:
dism /online /add-capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
dism /online /add-capability /CapabilityName:Rsat.Dns.Tools~~~~0.0.1.0

#Load the AD commandlets.  This step isn't necessary, but speeds things up.
Import-Module activedirectory

# The command below presents dialog box for entering a credential and storing it securely in the $cred variable
$cred = Get-Credential 

# initialize a variable, $domainusers as an empty array.  Occasionally, you want output to be 
# stored as an array, and PowerShell automatically types your output as a string

# The query below retrieves all properties for all domain users, and stores it in the $domainusers array variable
# PowerShell's auto-variable typing works well most of the time, and in this case, it populates
# an array for us with all domain user objects.  
$domainusers=Get-ADUser -filter * -Properties * -Server <DC-IP> -Credential $cred

# Optional:  export the $domainusers array into an xml text file for future storage.  It can be useful to keep 
# historical copies of this around for comparison over time
$domainusers | Export-Clixml usersexport00.xml

# If you have stored xml output, import usersexport00.xml into the $domainusers variable 
$domainusers = Import-Clixml .\usersexport00.xml

#show number of objects in $domainusers array
$domainusers.count

# Populate an array called $activeusers from the $domainusers array, selecting accounts which are enabled
$activeusers = $domainusers | where enabled -eq true

# Populate an array called $olderusers by selecting accounts from the $activeusers  array which haven't logged in since 01/01/2023
$olderusers = $activeusers | where LastLogonDate -lt '01/01/2023'

# display number of older users
$olderusers.count

#Display available attributes for an account in the $olderusers array 
$olderusers | get-member 

# Display interesting info about the user accounts in the $olderusers array
$olderusers | select SamAccountName, Description, LastLogonDate | out-host -paging  #out-host -paging is like the Linux "less" command

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




## Sample AD Computer queries
#store credential in $cred.  Any domain credential will suffice
$cred = get-credential
$computers = Get-ADComputer -filter * -Properties *  -Server <DC-IP> -Credential $cred
#export array for long-term storage
$computers | Export-Clixml ADMachines.xml
#import from saved xml
$computers=Import-Clixml .\ADMachines.xml
#create new array with machines with a LastLogonDate after 02/01/2023
$activemachines = $computers |where LastLogonDate -gt '02/01/2023'
# display list of operating systems in the $activemachines object with count
$activemachines.operatingsystem | group -NoElement | sort Count -Desc | Format-Table -AutoSize


