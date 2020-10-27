#Requires -Version 4
#Requires -Modules Azure

<# 
 .SYNOPSIS
  Script to monitor Azure VM, collect a group of web counters, retrieve and archive HTTPErr log files,
  parse the collected HTTPErr log files, update the Azure VM web Endpoint to block IPs that showed up 
  in any log file more than a given number of times (500 by default)

 .DESCRIPTION
  This is a controller script that uses 3 tool scripts/functions (bundled here as well).
  The script will:
  - Check if the computer running it has Internet access
  - Open a PS session to the Azure VM
  - Collect a group of web counters
  - Download HTTPErr log files if any
  - Archive those log files to a local folder on the Azure VM
  - Parse the downloaded files, extract IPs, identify those that appear more than $Threshold times
  - Retrieve the VM web Endpoint ACL
  - Update the VM web Endpoint ACL by adding offending IPs
  - Check if a given URL is online

 .PARAMETER SubscriptionName
  Name of the Azure Subscription where the Azure VM resides.
  To see your Azure subscriptions use the cmdlet:
      (Get-AzureSubscription).SubscriptionName

 .PARAMETER VMName
  Name of the Azure VM 
  To see your Azure VMs use the cmdlet:
      (Get-AzureVM).Name

 .PARAMETER AdminName
  Name of local administrator account on Azure VM

 .PARAMETER PwdFile
  Path to text file containing encrypted password of the AdminName.
  If it does not exist, the script will prompt the user to enter the password.
  If running this script as a scheduled task, run it manually once to generate the 
  encrypted password file, then use its path in this parameter.

 .PARAMETER EndPointName
  Name of the Azure VM EndPoint
  To see your Azure VM Endpoints for a given VM use the cmdlet:
      $VMName = "MyAzureVM"
      (Get-AzureVM | where { $_.Name -eq $VMName } | Get-AzureEndpoint).Name

 .PARAMETER URL
  URL to test if it's online or not.
  Example: http://mydomainname.com

 .PARAMETER IntakeFolder
  Path to local folder on the computer running this script. 
  The script will download HTTPErr files from the Azure VM to this folder.

 .PARAMETER DoneFolder
  Path to local folder on the computer running this script. 
  The script will move parsed HTTPErr files from the Intake folder to this folder.
  
 .PARAMETER ArchiveFolder
  Path on the remote Azure VM. After the script downloads the HTTPErr files, 
  it will move them from C:\Windows\System32\LogFiles\HTTPERR to this folder.
  
 .PARAMETER Threshold
  Number of times an IP address appears in a log file to be included in the master IP list
  Default value is 500

 .EXAMPLE
  E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1 -SubscriptionName SB01-Subscription -VMName SB01 -AdminName Samb -PwdFile d:\sandbox\Cred.txt -EndPointName HTTP -URL http://washwasha.com -Verbose
  This example runs the script once. This can be used to generate the d:\sandbox\Cred.txt encrypted password file.

 .EXAMPLE
  #
  #   
    $ScriptPath          = 'E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1'
    $Params = @{
        SubscriptionName = 'SB01-Subscription'
        VMName           = 'SB01'
        AdminName        = 'Samb'
        PwdFile          = 'd:\sandbox\Cred.txt'
        EndPointName     = 'HTTP'
        URL              = 'http://washwasha.com'
        Verbose          = $true
    }
    & $ScriptPath @Params

Similar example, runs manually once.

 .EXAMPLE
  #
  #
    $RepeatEvery         = 300 # seconds
    $ScriptPath          = 'E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1'
    $Params = @{
        SubscriptionName = 'SB01-Subscription'
        VMName           = 'SB01'
        AdminName        = 'Samb'
        PwdFile          = 'd:\sandbox\Cred.txt'
        EndPointName     = 'HTTP'
        URL              = 'http://washwasha.com'
        Verbose          = $true
    }
    While ($true) { # Repeat until CTRL-C
        "Start at $(Get-Date)"
        $Duration = Measure-Command { & $ScriptPath @Params }
        "End at $(Get-Date)"
        "  done in $($Duration.Minutes):$($Duration.Seconds) mm:ss, waiting for $RepeatEvery seconds"
        Start-Sleep -Seconds $RepeatEvery
    }

In this example the script runs every 5 minutes and displays progress on the console screen.

 .EXAMPLE
  #
  #
    $RepeatEvery         = 300 # seconds
    $ScriptPath          = 'E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1'
    $ScriptLog           = "D:\Docs\EG\Azure\Mitigate-DDOS_$(Get-Date -format yyyyMMdd).txt"
    $Params = @{
        SubscriptionName = 'SB01-Subscription'
        VMName           = 'SB01'
        AdminName        = 'Samb'
        PwdFile          = 'd:\sandbox\Cred.txt'
        EndPointName     = 'HTTP'
        URL              = 'http://washwasha.com'
        Verbose          = $true
    }
    While ($true) { # Repeat until CTRL-C
        "Start at $(Get-Date)" *>> $ScriptLog
        $Duration = Measure-Command { & $ScriptPath @Params  *>> $ScriptLog }
        "End at $(Get-Date)" *>> $ScriptLog
        "  done in $($Duration.Minutes):$($Duration.Seconds) mm:ss, waiting for $RepeatEvery seconds" *>> $ScriptLog
        Start-Sleep -Seconds $RepeatEvery
    }

In this example, the script runs every 5 minutes and logs all output to log file $ScriptLog

 .EXAMPLE
  #
  #
    $ScriptPath          = 'E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1'
    $ScriptLog           = "D:\Docs\EG\Azure\Mitigate-DDOS_$(Get-Date -format yyyyMMdd).txt"
    $Params = @{
        SubscriptionName = 'SB01-Subscription'
        VMName           = 'SB01'
        AdminName        = 'Samb'
        PwdFile          = 'd:\sandbox\Cred.txt'
        EndPointName     = 'HTTP'
        URL              = 'http://washwasha.com'
        Verbose          = $true
    }
    "Start at $(Get-Date)" *>> $ScriptLog
    $Duration = Measure-Command { & $ScriptPath @Params  *>> $ScriptLog }
    "End at $(Get-Date)" *>> $ScriptLog
    "  done in $($Duration.Minutes):$($Duration.Seconds) mm:ss" *>> $ScriptLog
  
This example runs once and logs all output to $ScriptLog file. 
When saved as E:\Install\Scripts\Mitigate-DDOS4.ps1 for example, this short script can be scheduled to run every 5 minutes:

    $a = New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Seconds 300) -RepetitionDuration ([TimeSpan]::MaxValue) 
    Register-ScheduledJob -Name DDOS4 -FilePath 'E:\Install\Scripts\Mitigate-DDOS4.ps1' -Trigger $a

 .OUTPUTS
  None. 
  Script progress can be viewed using the -Verbose switch.

 .LINK
  https://superwidgets.wordpress.com/category/powershell/
  IamOnline
  http://superwidgets.wordpress.com/2014/12/19/powershell-functiontool-to-detect-of-computer-has-internet-access/
  Set-AzACL
  http://superwidgets.wordpress.com/2014/12/19/powershell-functiontool-to-setupdate-azure-vm-endpoint-access-control-list/
  Get-IPsFromLogs
  http://superwidgets.wordpress.com/2014/12/18/powershell-functiontool-to-get-ips-from-httperr-logs-based-on-frequency/
  
 .NOTES
  Script by Sam Boutros
  v1.0 - 12/20/2014

#>

[CmdletBinding(ConfirmImpact='High')] 
Param(
    [Parameter(Mandatory=$true,
                Position=0)]
        [String]$SubscriptionName,
    [Parameter(Mandatory=$true,
                Position=1)]
        [String]$VMName,
    [Parameter(Mandatory=$true,
                Position=2)]
        [String]$AdminName,
    [Parameter(Mandatory=$true,
                Position=3)]
        [String]$PwdFile,
    [Parameter(Mandatory=$true,
                Position=4)]
        [String]$EndPointName,    
    [Parameter(Mandatory=$true,
                Position=5)]
        [String]$URL,
    [Parameter(Mandatory=$false,
                Position=6)]
        [ValidateScript({ Test-Path $_ })]
        [String]$IntakeFolder = "D:\Docs\EG\Intake",
    [Parameter(Mandatory=$false,
                Position=7)]
        [ValidateScript({ Test-Path $_ })]
        [String]$DoneFolder = "D:\Docs\EG\Done",
    [Parameter(Mandatory=$false,
                Position=8)]
        [String]$ArchiveFolder = "c:\HTTPArchive",
    [Parameter(Mandatory=$false,
                Position=9)]
        [Int32]$Threshold = 500
)


function IamOnline {
<# 
 .SYNOPSIS
  Function/tool to detect if the computer has Internet access

 .DESCRIPTION
  Function/tool to detect if the computer has Internet access

 .PARAMETER URLs
  One or more URL like http://microsoft.com
  I've entered 3 URLs as the default: 
    'http://google.com','http://facebook.com','http://youtube.com'
  
 .EXAMPLE
  if (IamOnline) { "I'm online" } else { "I'm offline" }
  If any of the input URLs retuns a status code, 
  it's considered online and function returns a positive result
 
 .EXAMPLE
  #
  $MyURL = 'http://mycustomurl.com/abc/cde/page.html'
  if (IamOnline) { 
    If (IamOnline $MyURL) { 
      Write-Host "$MyURL is online" -Fore Green
    } else {
      Write-Host "$MyURL is offline" -Fore Yellow
    }
  } else { 
    Write-Host "I'm offline" -Fore Yellow
  }

  In this example, the first if statement checks if the computer is online. 
  The second if statement checks if $MyURL is online
 
 .INPUTS
  One or more URLs

 .OUTPUTS
  A number ranging from zero to the count of URLs entered

 .LINK
  https://superwidgets.wordpress.com/category/powershell/

 .NOTES
  Function by Sam Boutros
  v1.0 - 12/19/2014

#>

    [CmdletBinding(ConfirmImpact='Low')] 
    Param(
        [Parameter(Mandatory=$false,
                   Position=0)]
            [String[]]$URLs = @('http://google.com','http://facebook.com','http://youtube.com')
    )

    $Bingo = 0
    Foreach($Uri in $URLs) {
        try { 
            $Response = Invoke-WebRequest -Uri $uri -ErrorAction Stop
            if ($Response.StatusCode) { $Bingo++ }
        } catch {}
    }
    $Bingo

} # function


function Get-IPsFromLogs {
<# 
 .SYNOPSIS
  Function/tool to get list of IP addresses that appear frequently in HTTPErr log files 

 .DESCRIPTION
  Function will search one or more HTTPERR log files which are typically located under
    C:\Windows\System32\LogFiles\HTTPERR
  It will parse lines that look like:
    2014-12-14 17:11:03 89.163.239.48 53445 100.73.78.132 80 HTTP/1.1 GET /?QHYCAQ=KLXMKXQL 503 2 ConnLimit Wash.com
  It will 
    1. Extract the first IP in every line 
    2. Compile a list of the IPs found in a file
    3. Generate a Frequency list that has each IP and how often it showed up in the file
    4. Filter the Frequency list to keep only those IPs that appeared more times than the $Threshold
    5. Compile master frequency list by summing up frequencies of duplicate IPs from different files

 .PARAMETER Logs
  Path to one or more HTTPErr log file

 .PARAMETER Threshold
  Number of times an IP address appears in a log file to be included in the master IP list
  Default value is 500

 .EXAMPLE
  Get-IPsFromLogs -Logs D:\Docs\EG\Sample\httperr12046.log 
  This example will parse the D:\Docs\EG\Sample\httperr12046.log file and 
      output a list of IPs that appeared more than 500 times

 .EXAMPLE
  Get-IPsFromLogs -Logs (Get-ChildItem -Path D:\Docs\EG\Sample).FullName -Verbose | FT -AutoSize
  This example will parse each file in the D:\Docs\EG\Sample folder and 
      output a master list of IPs that appeared more than 500 times in any file

 .EXAMPLE
  Get-IPsFromLogs -Logs (Get-ChildItem -Path D:\Docs\EG\Sample).FullName | Export-Csv D:\Docs\EG\BlockList.csv -NoType
  This example will parse each file in the D:\Docs\EG\Sample folder and 
      output a master list of IPs that appeared more than 500 times in any file and
      saves that list to CSV file D:\Docs\EG\BlockList.csv
 
 .OUTPUTS
  The function returns a PSObject that has 3 properties: IP, Date, & Frequency, sorted by Frequency descending

 .LINK
  https://superwidgets.wordpress.com/category/powershell/
  http://superwidgets.wordpress.com/2014/12/18/powershell-functiontool-to-get-ips-from-httperr-logs-based-on-frequency/
  Set-AzACL
  Mitigate-DDOS

 .NOTES
  Function by Sam Boutros
  v1.0 - 12/18/2014
  v1.1 - 12/18/2014 - added 3rd property to output object: Date of file from which IP was captured

#>

    [CmdletBinding(ConfirmImpact='Low')] 
    Param(
        [Parameter(Mandatory=$true,
                   ValueFromPipeLine=$true,
                   ValueFromPipeLineByPropertyName=$true,
                   Position=0)]
            [ValidateScript({Test-Path $_})]
            [String[]]$Logs,
        [Parameter(Mandatory=$false,
                   Position=1)]
            [Int32]$Threshold = 500
    )


    Write-Verbose "Got $($Logs.Count) file(s)" 
    $i = 0
    $BlockList = @()


    foreach ($File in $Logs) {
        $List = @()
        $Complete = "{0:N1}" -f ($i*100/$Logs.Count)
        Write-Progress -Activity "Processed $i of $($Logs.Count) files..." -CurrentOperation "$Complete % complete" -PercentComplete $Complete
        $i++


        # Extract IPs from log file(s)
        Write-Verbose "Processing file $File" 
        $j = 0
        $Duration = Measure-Command {
            (Get-Content -Path $File) | % { 
                $IP = $_.split(" ")[2] 
                if ($IP -and $IP.IndexOf(".") -gt 0) { $List += $IP; $j++ }
            }
        }
        Write-Verbose "  $j IPs found in $($Duration.Minutes):$($Duration.Seconds) mm:ss"


        # Create frequency list from raw IP list
        $FreqList = $List | Group-Object | % { 
            $Date = (Get-Item -Path $File).LastWriteTime
            $Props = [ordered]@{ 
                IP = $_.Name
                Frequency = $_.Count
                Date = "HTER-$($Date.Year)-$($Date.Month)-$($Date.Day)" 
            }
            New-Object -TypeName psobject -Property $Props
        }
        Write-Verbose "    $($FreqList.IP.Count) unique IPs found"


        # Filter to keep only IPs that showed up more than the $Threshold number of times
        $Filtered = $FreqList | Where { $_.Frequency -gt $Threshold } | Sort Frequency -Descending 
        if ($Filtered) {
            $BlockList += $Filtered
            Write-Verbose "      $($Filtered.IP.Count) IPs with frequency over $Threshold"
        } else {
            Write-Verbose "      No IPs found that showed up more than $Threshold times.."
        }
    } # foreach


    # Compile master block list (sum up frequencies of duplicate IPs from different files)
    $BlockList.IP | Group-Object | % {
        $IP = $_.Name
        $Date = ($BlockList.Where( { $_.IP -eq $IP } )).Date | select -Unique
        if ($Date.Count -gt 1) { $Date = $Date[$Date.Count-1] } 
        $Props = [ordered]@{ 
            IP = $IP
            Frequency = (($BlockList.Where( { $_.IP -eq $IP } )).Frequency | Measure-Object -Sum).Sum 
            Date = $Date
        }
        New-Object -TypeName psobject -Property $Props            
    } | sort Frequency -Descending


} # function


function Set-AzACL {
<# 
 .SYNOPSIS
  Function/tool to set/update Azure Access Control List for a given Azure VM Endpoint

 .DESCRIPTION
  Function/tool to set/update Azure Access Control List for a given Azure VM Endpoint

 .PARAMETER IPList
  One or more PSObjects that have 'IP' and 'Date' properties.
  This object is the output object from Get-IPsFromLogs function/tool
  http://superwidgets.wordpress.com/2014/12/18/powershell-functiontool-to-get-ips-from-httperr-logs-based-on-frequency/
  
 .PARAMETER SubscriptionName
  Name of the Azure Subscription where the Azure VM resides.
  To see your Azure subscriptions use the cmdlet:
      (Get-AzureSubscription).SubscriptionName

 .PARAMETER VMName
  Name of the Azure VM 
  To see your Azure VMs use the cmdlet:
      (Get-AzureVM).Name

 .PARAMETER EndPointName
  Name of the Azure VM EndPoint
  To see your Azure VM Endpoints for a given VM use the cmdlet:
      $VMName = "MyAzureVM"
      (Get-AzureVM | where { $_.Name -eq $VMName } | Get-AzureEndpoint).Name

 .EXAMPLE
  Set-AzACL -IPList (Get-IPsFromLogs -Logs c:\temp\log1.txt) -SubscriptionName "MyAzureSubscription" -VMName "MyAzureVM" -EndpointName "Web"
  In this example, the function/tool Get-IPsFromLogs compiles a list of IPs that appeared more than 500 times
  in the log file c:\temp\log1.txt, and the function/tool Set-AzACL adds that list to the Web endpoint of MyAzureVM
 
 .INPUTS
  The function requires a PSObject that has 2 properties: IP, Date
  The Date is used to populate the rule description of the ACL
  This object is the output object from Get-IPsFromLogs function/tool
  http://superwidgets.wordpress.com/2014/12/18/powershell-functiontool-to-get-ips-from-httperr-logs-based-on-frequency/

 .OUTPUTS
  None

 .LINK
  https://superwidgets.wordpress.com/category/powershell/

 .NOTES
  Function by Sam Boutros
  v1.0 - 12/19/2014

#>

    [CmdletBinding(ConfirmImpact='High')] 
    Param(
        [Parameter(Mandatory=$true,
                   Position=0)]
            [System.Object[]]$IPList,
        [Parameter(Mandatory=$true,
                   Position=1)]
            [String]$SubscriptionName,
        [Parameter(Mandatory=$true,
                   Position=2)]
            [String]$VMName,
        [Parameter(Mandatory=$true,
                   Position=3)]
            [String]$EndPointName
    )


    Begin {
        $Props = ($IPList | Get-Member -MemberType NoteProperty).Name
        if ($Props -notcontains "Date" -or $Props -notcontains "IP") {
            throw "Incorrect object received. Expecting PSObject containing 'Date' and 'IP' properties."
        }
        try { 
            Select-AzureSubscription -SubscriptionName $SubscriptionName -ErrorAction Stop 
        } catch { 
            throw "unable to select Azure subscription '$SubscriptionName', check correct spelling.. " 
        }
        try { 
            $ServiceName = (Get-AzureVM -ErrorAction Stop | where { $_.Name -eq $VMName }).ServiceName 
        } catch { 
            throw "unable to get Azure VM '$VMName', check correct spelling, or run Add-AzureAccount to enter Azure credentials.. " 
        }
        $objVM = Get-AzureVM -Name $VMName -ServiceName $ServiceName
    }

    Process {
        # Get current ACL
        $ACL = Get-AzureAclConfig -EndpointName $EndPointName -VM $objVM
        Write-Verbose "Current ACL:" 
        Write-Verbose  ($ACL | FT -Auto | Out-String) 


        # Add/Update rules from $IPList
        Write-Verbose "Updating Access Control List for '$EndPointName' endpoint for VM '$VMName'"
        foreach ($IP in $IPList) {
            $ExistingRule = $ACL | where { $_.RemoteSubnet -match "$($IP.IP)/32"} 
            if ($ExistingRule) { # Update Description
                Set-AzureAclConfig -SetRule -Action Deny -RuleId $ExistingRule.RuleID -RemoteSubnet $ExistingRule.RemoteSubnet -Description $IP.Date -ACL $ACL | Out-Null
            } else { # Add new rule
                Set-AzureAclConfig -AddRule Deny -RemoteSubnet "$($IP.IP)/32" -Description $IP.Date -ACL $ACL | Out-Null
            }
        } 


        # Reset rule order
        $i=0
        $ACL | Sort Description -Descending | % {
            Set-AzureAclConfig -SetRule -RuleId $_.RuleID -Action Deny -RemoteSubnet $_.RemoteSubnet -Description $_.Description -Order $i -ACL $ACL | Out-Null
            $i++
        }
        Write-Verbose ($ACL | Sort Order | FT -Auto | Out-String)


        # check for duplicates
        if ($ACL.RemoteSubnet.Count -eq ($ACL.RemoteSubnet | Select -Unique).Count) {
            Write-Verbose "Verified no duplicate rules. Rule count: '$($ACL.RemoteSubnet.Count)'"
        } else {
            throw "Found '$($ACL.RemoteSubnet.Count - ($ACL.RemoteSubnet | Select -Unique).Count)' duplicate rules."
        }


        Write-Verbose "Saving updated ACL to EndPoint '$EndPointName' for VM '$VMName'"
        $Duration = Measure-Command {
            $Result = Set-AzureEndpoint –ACL $ACL –Name $EndPointName -VM $objVM | Update-AzureVM 
        }
        Write-Verbose "  done in $($Duration.Minutes):$($Duration.Seconds) mm:ss"
        Write-Verbose ($Result | FT -AutoSize | Out-String)
    } # Process


} # function


# Check if this computer has Internet access
if (IamOnline) {
    Write-Verbose "Confirmed this computer '$env:COMPUTERNAME' has Internet access"

    try { 
        Select-AzureSubscription -SubscriptionName $SubscriptionName -ErrorAction Stop 
    } catch { 
        throw "unable to select Azure subscription '$SubscriptionName', check correct spelling.. " 
    }
    try { 
        $ServiceName = (Get-AzureVM -ErrorAction Stop | where { $_.Name -eq $VMName }).ServiceName 
    } catch { 
        throw "unable to get Azure VM '$VMName', check correct spelling, or run Add-AzureAccount to enter Azure credentials.. " 
    }
    $objVM = Get-AzureVM -Name $VMName -ServiceName $ServiceName
    $VMFQDN = (Get-AzureWinRMUri -ServiceName $ServiceName).Host
    $Port = (Get-AzureWinRMUri -ServiceName $ServiceName).Port
    
    # Get certificate for Powershell remoting to the Azure VM if not installed already
    if ((Get-ChildItem -Path Cert:\LocalMachine\Root).Subject -notcontains "CN=$VMFQDN") {
        Write-Verbose "Adding certificate 'CN=$VMFQDN' to 'LocalMachine\Root' certificate store.." 
        $Thumbprint = (Get-AzureVM -ServiceName $ServiceName -Name $VMName | 
            select -ExpandProperty VM).DefaultWinRMCertificateThumbprint
        $Temp = [IO.Path]::GetTempFileName()
        (Get-AzureCertificate -ServiceName $ServiceName -Thumbprint $Thumbprint -ThumbprintAlgorithm sha1).Data | Out-File $Temp
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Temp
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root","LocalMachine"
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($Cert)
        $store.Close()
        Remove-Item $Temp -Force -Confirm:$false
    }
} else {
    throw "This computer '$env:COMPUTERNAME' appears to have no Internet access, stopping.."
}


# Attempt to open Powershell session to Azure VM
Write-Verbose "Opening PS session with computer '$VMName'.." 
if (-not (Test-Path -Path $PwdFile)) { 
        Write-Verbose "Pwd file '$PwdFile' not found, prompting to pwd.."
        Read-Host "Enter the pwd for '$AdminName' on '$VMFQDN'" -AsSecureString | 
            ConvertFrom-SecureString | Out-File $PwdFile 
    }
$Pwd = Get-Content $PwdFile | ConvertTo-SecureString 
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AdminName, $Pwd
try { 
    $Session = New-PSSession -ComputerName $VMFQDN -Port $Port -UseSSL -Credential $Cred -ErrorAction Stop


    # Collect VM counters
    $ScriptBlock = { 
        $Counters = '\Web Service(*)\Current Anonymous Users',
                    '\Web Service(*)\Current Connections',
                    '\Processor(*)\% Processor Time'
        (Get-Counter -Counter $Counters).CounterSamples | where { $_.InstanceName -eq '_total' }
    }
    $Result = Invoke-Command -Session $Session -ScriptBlock $ScriptBlock 
    $Stats = New-Object -TypeName psobject -Property @{ Date = (Get-Date -format MM/dd/yyyy); Time = (Get-Date -format HH:mm:ss) }
    $Result | % { $Stats | Add-Member -MemberType NoteProperty -Name $_.Path.Split("\")[$_.Path.Split("\").Count-1] -Value $_.CookedValue }
    Write-Verbose ($Stats | FT -AutoSize | Out-String)


    # Get HTTPErr logs
    # First, get a list of log files
    $LogFiles = Invoke-Command -Session $Session -ScriptBlock { 
        $HTTPErrFolder = "$env:windir\System32\LogFiles\HTTPERR"
        Get-ChildItem -Path $HTTPErrFolder | sort LastWriteTime
    }
    if ($LogFiles.Count -gt 1) {
        Write-Warning "Found $($LogFiles.Count) new HTTPErr log files on VM '$VMName'"
    } else {
        Write-Verbose "No new HTTPErr log files founud on VM '$VMName'"
    }

    # Next, if we have more than one file, download each file, move the original to local Archive folder
    while ($LogFiles.Count -gt 1) {
            # Get file name
            $FileName = Invoke-Command -Session $Session -ScriptBlock { 
                $HTTPErrFolder = "$env:windir\System32\LogFiles\HTTPERR"
                (Get-ChildItem -Path $HTTPErrFolder | sort LastWriteTime | Select -First 1).Name
            }
                
            # Get file content
            Write-Verbose "Downloading file '$FileName'"
            $Duration = Measure-Command { $FileContent = Invoke-Command -Session $Session -ScriptBlock { 
                $HTTPErrFolder = "$env:windir\System32\LogFiles\HTTPERR"
                Get-Content  (Get-ChildItem -Path $HTTPErrFolder | sort LastWriteTime | Select -First 1).FullName -Raw
            } }
            $Destination = Join-Path -Path $IntakeFolder -ChildPath $FileName
            $FileContent | Out-File $Destination
            $FileSize = (Get-Item -Path $Destination).Length
            Write-Verbose "  done in $($Duration.Minutes):$($Duration.Seconds) mm:ss, size: $('{0:N2}' -f ($FileSize/1MB)) MB"

            # Move original source log file to archive folder
            $Successful = Invoke-Command -Session $Session -ScriptBlock { 
                $HTTPErrFolder = "$env:windir\System32\LogFiles\HTTPERR"
                try {
                    $Source = Get-ChildItem -Path $HTTPErrFolder | sort LastWriteTime | Select -First 1
                    $Destination = Join-Path -Path $using:ArchiveFolder -ChildPath $Source.Name
                    if (-not(Test-Path -Path $using:ArchiveFolder)) { 
                        New-Item -Path $using:ArchiveFolder -ItemType Directory -Force -Confirm:$false -ErrorAction Stop
                    }
                    Move-Item -Path $Source.FullName -Destination $Destination -Force -Confirm:$false -ErrorAction Stop
                    1
                } catch {
                    0
                }
            } 
            if ($Successful) {
                Write-Verbose "Successfully moved '$FileName' file to '$ArchiveFolder' folder on '$VMName' VM"
            } else { 
                # Must break here or while loop besomes infinite
                Remove-PSSession -Session $Session
                throw "Failed to move '$FileName' file to '$ArchiveFolder' folder on '$VMName' VM"
            }

            # Get updated LogFile list for the while loop
            $LogFiles = Invoke-Command -Session $Session -ScriptBlock { 
                $HTTPErrFolder = "$env:windir\System32\LogFiles\HTTPERR"
                Get-ChildItem -Path $HTTPErrFolder | sort LastWriteTime
            }
        } # while
    Write-Verbose "Current HTTPErr file '$($LogFiles.Name)' size: $('{0:N2}' -f ($LogFiles.Length/1KB)) KB"
        

    # Display current VM Endpoint Access Control List
    $ACL = Get-AzureAclConfig -EndpointName $EndPointName -VM $objVM
    Write-Verbose "Current ACL:" 
    Write-Verbose  ($ACL | FT -Auto | Out-String)


    # Parse downloaded HTTPErr log files, update VM Endpoint ACL
    $Files = Get-ChildItem -Path $IntakeFolder
    if ($Files) {
        Write-Warning "Processing '$($Files.Count)' files in '$IntakeFolder' folder"
        $BlockList = Get-IPsFromLogs -Logs $Files.FullName -Threshold $Threshold  
        if ($BlockList) { 
            Write-Warning ($BlockList | FT -AutoSize | Out-String)
            try {
                $Error.Clear()
                Set-AzACL -IPList $BlockList -SubscriptionName $SubscriptionName -VMName $VMName -EndPointName $EndpointName -ErrorAction stop
                $Files | Move-Item -Destination $DoneFolder
            } catch {
                Write-Warning $Error[0]
            } # try
        } else {
            Write-Verbose "No IPs found in HTTPErr log files that showed up more than '$Threshold' times.."
        } # if ($BlockList)
    } # if ($Files)


    Remove-PSSession -Session $Session
} catch { 
    Write-Warning "Unable to establish PS remote session '$VMName'.."
}


# Check if URL is online
if (IamOnline $URL) {
    Write-Verbose "Confirmed '$URL' is online"
} else {
    Write-Warning "'$URL' appears to be offline"
}