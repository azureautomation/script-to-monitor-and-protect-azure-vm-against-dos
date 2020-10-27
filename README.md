Script to monitor and protect Azure VM against DOS
==================================================

            

This script will monitor Azure VM, collect a group of web counters, retrieve and archive HTTPErr log files,  parse the collected HTTPErr log files, update the Azure VM web Endpoint to block IPs that showed up   in any log file more than a
 given number of times (500 by default)


This is a controller script that uses 3 tool scripts/functions (bundled here as well).  The script will: 


  *  Check if the computer running it has Internet access   
  *  Open a PS session to the Azure VM   
  *  Collect a group of web counters   
  *  Download HTTPErr log files if any   
  *  Archive those log files to a local folder on the Azure VM   
  *  Parse the downloaded files, extract IPs, identify those that appear more than $Threshold times  

  *  Retrieve the VM web Endpoint ACL   
  *  Update the VM web Endpoint ACL by adding offending IPs   
  *  Check if a given URL is online 

For more information see  


 


  *  [https://superwidgets.wordpress.com/category/powershell/ ](  https://superwidgets.wordpress.com/category/powershell/   IamOnline   http://superwidgets.wordpress.com/2014/12/19/powershell-functiontool-to-detect-of-computer-has-internet-access/   Set-AzACL   http://superwidgets.wordpress.com/2014/12/19/powershell-functiontool-to-setupdate-azure-vm-endpoint-access-control-list/   Get-IPsFromLogs   http://superwidgets.wordpress.com/2014/12/18/powershell-functiontool-to-get-ips-from-httperr-logs-based-on-frequency/)

  *  [IamOnline](http://superwidgets.wordpress.com/2014/12/19/powershell-functiontool-to-detect-of-computer-has-internet-access/) 

  *  [Set-AzACL](http://superwidgets.wordpress.com/2014/12/19/powershell-functiontool-to-setupdate-azure-vm-endpoint-access-control-list/ )

  *  [Get-IPsFromLogs](http://superwidgets.wordpress.com/2014/12/18/powershell-functiontool-to-get-ips-from-httperr-logs-based-on-frequency/)


 


To use this script download it, unblock the file, and run the built-in help using:

Powershell displays help similar to:

 

Synopsis
    Script to monitor Azure VM, collect a group of web counters, retrieve and archive HTTPErr log files,
    parse the collected HTTPErr log files, update the Azure VM web Endpoint to block IPs that showed up 
    in any log file more than a given number of times (500 by default)

Syntax
    E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1 [-SubscriptionName]  [-VMName]  [-AdminName]  [-PwdFile]  [-EndPointName]  [-URL]  [[-IntakeFolder] ] [[-DoneFolder] ] [[-ArchiveFolder] ] [[-Threshold] ] []


Description
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


Parameters
    -SubscriptionName 
        Name of the Azure Subscription where the Azure VM resides.
        To see your Azure subscriptions use the cmdlet:
            (Get-AzureSubscription).SubscriptionName

        Required?                    true
        Position?                    1
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -VMName 
        Name of the Azure VM 
        To see your Azure VMs use the cmdlet:
            (Get-AzureVM).Name

        Required?                    true
        Position?                    2
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -AdminName 
        Name of local administrator account on Azure VM

        Required?                    true
        Position?                    3
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -PwdFile 
        Path to text file containing encrypted password of the AdminName.
        If it does not exist, the script will prompt the user to enter the password.
        If running this script as a scheduled task, run it manually once to generate the 
        encrypted password file, then use its path in this parameter.

        Required?                    true
        Position?                    4
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -EndPointName 
        Name of the Azure VM EndPoint
        To see your Azure VM Endpoints for a given VM use the cmdlet:
            $VMName = 'MyAzureVM'
            (Get-AzureVM | where { $_.Name -eq $VMName } | Get-AzureEndpoint).Name

        Required?                    true
        Position?                    5
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -URL 
        URL to test if it's online or not.
        Example: http://mydomainname.com

        Required?                    true
        Position?                    6
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -IntakeFolder 
        Path to local folder on the computer running this script. 
        The script will download HTTPErr files from the Azure VM to this folder.

        Required?                    false
        Position?                    7
        Default value                D:\Docs\EG\Intake
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -DoneFolder 
        Path to local folder on the computer running this script. 
        The script will move parsed HTTPErr files from the Intake folder to this folder.

        Required?                    false
        Position?                    8
        Default value                D:\Docs\EG\Done
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -ArchiveFolder 
        Path on the remote Azure VM. After the script downloads the HTTPErr files, 
        it will move them from C:\Windows\System32\LogFiles\HTTPERR to this folder.

        Required?                    false
        Position?                    9
        Default value                c:\HTTPArchive
        Accept pipeline input?       false
        Accept wildcard characters?  false

    -Threshold 
        Number of times an IP address appears in a log file to be included in the master IP list
        Default value is 500

        Required?                    false
        Position?                    10
        Default value                500
        Accept pipeline input?       false
        Accept wildcard characters?  false



Outputs
    None. 
    Script progress can be viewed using the -Verbose switch.

Notes
    Script by Sam Boutros
    v1.0 - 12/20/2014

Examples
    -------------------------- EXAMPLE 1 --------------------------
    C:\PS>E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1 -SubscriptionName SB01-Subscription -VMName SB01 -AdminName Samb -PwdFile d:\sandbox\Cred.txt -EndPointName HTTP -URL http://washwasha.com -Verbose
    
    This example runs the script once. This can be used to generate the d:\sandbox\Cred.txt encryoted password file.




    -------------------------- EXAMPLE 2 --------------------------
    C:\PS>#
    
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




    -------------------------- EXAMPLE 3 --------------------------
    C:\PS>#
    
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
      'Start at $(Get-Date)'
      $Duration = Measure-Command { & $ScriptPath @Params }
      'End at $(Get-Date)'
      '  done in $($Duration.Minutes):$($Duration.Seconds) mm:ss, waiting for $RepeatEvery seconds'
      Start-Sleep -Seconds $RepeatEvery
  }

In this example the script runs every 5 minutes and displays progress on the console screen.




    -------------------------- EXAMPLE 4 --------------------------
    C:\PS>#
    
    #
  $RepeatEvery         = 300 # seconds
  $ScriptPath          = 'E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1'
  $ScriptLog           = 'D:\Docs\EG\Azure\Mitigate-DDOS_$(Get-Date -format yyyyMMdd).txt'
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
      'Start at $(Get-Date)' *>> $ScriptLog
      $Duration = Measure-Command { & $ScriptPath @Params  *>> $ScriptLog }
      'End at $(Get-Date)' *>> $ScriptLog
      '  done in $($Duration.Minutes):$($Duration.Seconds) mm:ss, waiting for $RepeatEvery seconds' *>> $ScriptLog
      Start-Sleep -Seconds $RepeatEvery
  }

In this example, the script runs every 5 minutes and logs all output to log file $ScriptLog




    -------------------------- EXAMPLE 5 --------------------------
    C:\PS>#
    
    #
  $ScriptPath          = 'E:\Install\Scripts\Azure\AZ-MonitorAndRepair.ps1'
  $ScriptLog           = 'D:\Docs\EG\Azure\Mitigate-DDOS_$(Get-Date -format yyyyMMdd).txt'
  $Params = @{
      SubscriptionName = 'SB01-Subscription'
      VMName           = 'SB01'
      AdminName        = 'Samb'
      PwdFile          = 'd:\sandbox\Cred.txt'
      EndPointName     = 'HTTP'
      URL              = 'http://washwasha.com'
      Verbose          = $true
  }
  'Start at $(Get-Date)' *>> $ScriptLog
  $Duration = Measure-Command { & $ScriptPath @Params  *>> $ScriptLog }
  'End at $(Get-Date)' *>> $ScriptLog
  '  done in $($Duration.Minutes):$($Duration.Seconds) mm:ss' *>> $ScriptLog

This example runs once and logs all output to $ScriptLog file. 
When saved as E:\Install\Scripts\Mitigate-DDOS4.ps1 for example, this short script can be scheduled to run every 5 minutes:

  $a = New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Seconds 300) -RepetitionDuration ([TimeSpan]::MaxValue) 
  Register-ScheduledJob -Name DDOS4 -FilePath 'E:\Install\Scripts\Mitigate-DDOS4.ps1' -Trigger $a



        
    
TechNet gallery is retiring! This script was migrated from TechNet script center to GitHub by Microsoft Azure Automation product group. All the Script Center fields like Rating, RatingCount and DownloadCount have been carried over to Github as-is for the migrated scripts only. Note : The Script Center fields will not be applicable for the new repositories created in Github & hence those fields will not show up for new Github repositories.
