param(
[Parameter(Mandatory=$true)][string]$ConfigFileName,
[bool]$creat = $true,
[bool]$delete = $false,
[bool]$test = $false
)
set-psdebug -strict -trace 0
if((Test-Path $ConfigFileName) -eq $false) {$(throw "Config file dosent exist")}
[xml] $Config = Get-Content $ConfigFileName

.\src\FunLib.ps1

Make-Directory(".\logs")
$scriptName =$MyInvocation.MyCommand.Name
try { 
    Stop-Transcript
    Write-Host "Stoping old transcript"
} catch {}
$runDate = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
start-transcript "$PSScriptRoot\logs\$scriptName.$($env:ComputerName).$runDate.log" 

foreach($item in $Config.Config.ChildNodes)
{
	$element = $($item.Get_Name())
	Write-Host "Processing: $element"
	if($element -eq "#comment"){continue}
	
	Invoke-Expression "Execute$element(`$item)"
}
stop-transcript -errorAction SilentlyContinue
