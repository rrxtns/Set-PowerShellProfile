###############################################################################
# ScriptName:           sntxrr's PowerShell profile Configuration
# Author:               Syntax Error (rrxtns@users.noreply.github.com)
# Credits:              Gary Burns, Joshua Johnson, Steven Murawski
# Date Last Modified:   September 14th, 2016 (09/14/2016)
# Description:          Prepares PowerShell environment
###############################################################################
###############################################################################

#Modules
Import-Module Azure
Import-Module AzureRM

#Aliases
Set-Alias gs get-serverlist
Set-Alias gb Get-Buffer
Set-Alias wbs Get-ISWSuppressionStatus
Set-Alias chef C:\opscode\chefdk\bin\chef
Set-Alias sudo elevate-process;
Set-Alias epf Edit-ProfileFile
Set-Alias ML Measure-LastDateTime
Set-Alias MF Measure-FirstDateTime

###############################################################################

###############################################################################
#function Definitions

# Set preferred editor
function edit($file)
{
  if ($file -eq $null)
    {
		if (test-path 'C:\Program Files (x86)\Notepad++\notepad++.exe') {
        & 'C:\Program Files (x86)\Notepad++\notepad++.exe';
		} else {
		& notepad
		}
    }
    else
    {
		if (test-path 'C:\Program Files (x86)\Notepad++\notepad++.exe') {
        & 'C:\Program Files (x86)\Notepad++\notepad++.exe' $file;
		} else {
		& notepad $file
		}
    }
}

#Customize command prompt to include datetime stamp / user@computer / path
function prompt
{

    # Set Window Title
    $host.UI.RawUI.WindowTitle = "$ENV:USERNAME@$ENV:COMPUTERNAME - $(Get-Location)"

    # Set Prompt
    Write-Host (Get-Date -Format G) -NoNewline -ForegroundColor Red
    Write-Host " :: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$ENV:USERNAME@$ENV:COMPUTERNAME" -NoNewline -ForegroundColor White
    Write-Host " :: " -NoNewline -ForegroundColor DarkGray
    Write-Host $(get-location) -ForegroundColor Green

    # Check Running Jobs
    $jobs = Get-Job -State Running
    $jobsCount = $jobs.Count

    # Check for Administrator elevation
    $wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp=new-object System.Security.Principal.WindowsPrincipal($wid)
    $adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
    $IsAdmin=$prp.IsInRole($adm)
    if ($IsAdmin) {
        if ($jobsCount -eq $null) {
            Write-Host "(admin) #" -NoNewline -ForegroundColor Gray
            return " "
        }
        else {
            Write-Host "(admin) jobs:" $jobsCount -NoNewline -ForegroundColor Gray
            Write-Host "#" -NoNewline -ForegroundColor Gray
            return " "
        }
    }
    else {
        if ($jobsCount -eq $null) {
            Write-Host ">" -NoNewline -ForegroundColor Gray
            return " "
        }
        else {
            Write-Host "jobs:" $jobsCount  -NoNewline -ForegroundColor Gray
            Write-Host ">" -NoNewline -ForegroundColor Gray
            return " "
        }
    }
}

#Edit PowerShell profile easily
function Edit-ProfileFile{
   edit $profile
}

#Reload Profile
function Reload-Profile {
    @(
        $Profile.AllUsersAllHosts,
        $Profile.AllUsersCurrentHost,
        $Profile.CurrentUserAllHosts,
        $Profile.CurrentUserCurrentHost
    ) | % {
        if(Test-Path $_){
            Write-Verbose "Running $_"
            . $_
        }
    }
}

#Measure Dates and Times
function Measure-LastDateTime
{
   BEGIN{ $dtLastDateTime = $null}
   PROCESS{ if(($_ -ne $null) -and (($dtLastDateTime -eq $null) -OR ($_ -gt $dtLastDateTime))){$dtLastDateTime = $_}}
   END{$dtLastDateTime}
}

function Measure-FirstDateTime
{
   BEGIN{ $dtFirstDateTime = $null}
   PROCESS{ if(($_ -ne $null) -and (($dtFirstDateTime -eq $null) -OR ($_ -lt $dtFirstDateTime))){$dtFirstDateTime = $_}}
   END{$dtFirstDateTime}
}

function Measure-AverageTimeBetween
{
  BEGIN
  {
   $average = 0;
   $last = $null;
  }
  PROCESS
  {
    if($last -eq $null){$last = $_}
    else{ $average = [timespan]::FromMilliSeconds((($last - $_).TotalMilliSeconds + $average.TotalMilliseconds)/2);
          $last = $_;}
  }
  END
  {
    $average;
  }
}

#Comb event logs
function Comb-EventLog
{
param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)] [string] $ComputerName = $env:COMPUTERNAME,
        [string] $LogName = "",
        [string] $Source = "",
        [string] $Message = $null,
        [string] $Before = $null,
        [string] $After = $null,
        [string] $Newest = $null,
        [string] $InstanceID = $null,
        [string] $EntryType = $null
);
BEGIN
{
        $jobList = @();
        $DefaultArgs = "";
        foreach($argument in $MyInvocation.BoundParameters.GetEnumerator())
        {
                $DefaultArgs += $("-{0} {1} " -f $argument.key,$argument.value);
        }
        if(! $MyInvocation.BoundParameters.ContainsKey("Logname"))
        {
                $DefaultArgs += "-LogName Application";
        }
}
PROCESS
{
        $command = "Invoke-Command -computername $ComputerName -ScriptBlock { Get-Eventlog $DefaultArgs -ErrorAction SilentlyContinue; } -AsJob";
        $jobList += Invoke-Expression $command;
}
END
{
       $result = $jobList | Wait-Job -Timeout 30 | Receive-Job;
       $jobList | Remove-Job -Force;
       $result
}
}

# Get PowerShell buffer to copy pretty output into emails
Function Get-Buffer
{
  # presumes Get-Buffer.ps1 is in your $path!
	$SortableDate = Get-Date -format yyyy_M_d_HH_mm_ss
	Get-Buffer.ps1 >> output_$SortableDate.html;$ie=new-object -com InternetExplorer.Application;$ie.visible=$true;$ie.Navigate2($pwd.path+"\output_"+$SortableDate+".html");
}

Function Elevate-Process
{
        [string]$arguments = $args;
        $psi = New-Object System.Diagnostics.ProcessStartInfo powershell.exe
        $psi.Arguments = "-NoProfile -ExecutionPolicy ByPass -Command $arguments;exit;";
        $psi.Verb = "runas";
        $psi.WorkingDirectory = get-location;
        $null = [System.Diagnostics.Process]::Start($psi);
}

# This function courtesy Steven Murawski! (https://github.com/smurawski)
Function Start-VsDevShell {
  cmd.exe --% /k ""C:\Program Files (x86)\Microsoft Visual C++ Build Tools\vcbuildtools.bat" amd64" & powershell
}
