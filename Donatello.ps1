param(
[Parameter(Mandatory=$true)][string]$ConfigFileName,
[bool]$creat = $true,
[bool]$delete = $false,
[bool]$test = $false
)
if((Test-Path $ConfigFileName) -eq $false) {$(throw "Config file dosent exist")}
[xml] $Config = Get-Content $ConfigFileName

.\src\FunLib.ps1

MakeDirectory(".\logs")
stop-transcript -errorAction SilentlyContinue
start-transcript .\logs\MasterKey.log -append -noclobber

foreach($item in $Config.Config.ChildNodes)
{
	$element = $($item.Get_Name())
	Write-Host "Processing: $element"
	if($element -eq "#comment"){continue}
	
	Invoke-Expression "Execute$element(`$item)"
}
