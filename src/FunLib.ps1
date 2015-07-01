if (!(Test-Path variable:_TESTLIB)) { .\src\TestLib.ps1 }

function global:Get-Font {
           
    <#
    .Synopsis
        Gets the fonts currently loaded on the system
    .Description
        Uses the type System.Windows.Media.Fonts static property SystemFontFamilies,
        to retrieve all of the fonts loaded by the system.  If the Fonts type is not found,
        the PresentationCore assembly will be automatically loaded
    .Parameter font
        A wildcard to search for font names
    .Example
        # Get All Fonts
        Get-Font
    .Example
        # Get All Lucida Fonts
        Get-Font *Lucida*
    #>
    param($font = "*")
if (-not ("Windows.Media.Fonts" -as [Type])) {
        Add-Type -AssemblyName "PresentationCore"
    }       

    [Windows.Media.Fonts]::SystemFontFamilies |
        Where-Object { $_.Source -like "$font" } 
}

function global:StartProcess([string] $command = $(throw "Missing: command parameter"), [string[]] $parameters, [switch] $wait, [switch] $cmd)
{
    if ($cmd.IsPresent)
    {
        cmd /C $command $parameters
    }
    else
    {
        $process = [Diagnostics.Process]::Start($command, $parameters);
        if ($wait.IsPresent)
        {
            $process.WaitForExit();
        }
    }
}

function global:LocalUserExist([string] $UserName)
{
	$objComputer = [ADSI]("WinNT://$env:ComputerName,computer")
	$colUsers = ($objComputer.psbase.children | Where-Object {$_.psBase.schemaClassName -eq "User"} | Select-Object -expand Name)
	return $colUsers -contains $UserName
}

function global:Set-CertPermission([string]$CertName, [string]$User)
{
	$OsVersion = "$([environment]::OSVersion.Version.Major).$([environment]::OSVersion.Version.Minor)"
	Write-Host "OsVersion: $OsVersion"
	$tokenCert = Get-ChildItem CERT:\LocalMachine\My | where {$_.FriendlyName -match "$CertName"} | select -first 1 -erroraction STOP
	
	$rsaFile = $tokenCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
	Write-Host "RSA File: $rsaFile"
	$keyPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\$rsaFile"
	Write-Host "Key path: $keyPath"
	$acl=Get-Acl -Path "$keyPath"

	$permission= "$User", "Read","Allow"
	$accessRule=new-object System.Security.AccessControl.FileSystemAccessRule $permission
	$acl.AddAccessRule($accessRule)
	Set-Acl $keyPath $acl
}

function global:Assign-IISCertToPort([string]$Hostname, [string]$CertName, [string]$SitePort, [string]$IpAddress)
{
	if($IpAddress)
	{
		$ipAddress = $IpAddress
		} else {
		$ipAddress = "0.0.0.0"
	}

	$bindingPath = "IIS:\SslBindings\$ipAddress!" + $SitePort
	if(Get-Item -Path "IIS:\SslBindings\*" | where { ($_.Port -eq $SitePort) -and ($_ -match "$ipAddress") } )
	{ 
	  Remove-Item -Path $bindingPath   
	}

	$cert = Get-ChildItem CERT:\LocalMachine\My |where {$_.FriendlyName -match $CertName} | select -first 1 -erroraction STOP 
	New-Item -Path "${bindingPath}" -Value $cert
}

function global:CommandExist($commandName)
{
	if (Get-Command $commandName -errorAction SilentlyContinue)
	{
		return $true
	}
	return $false
}

#Sites

function global:AddSite($site, $certName)
{ 
	Import-Module servermanager
	if(!(Test-Path "IIS:\AppPools\$($site.ApplicationPool)"))
	{
		Write-Host "Adding App pool: " $site.ApplicationPool
		New-WebAppPool -Name $site.ApplicationPool
		if($site.SslCertName)
		{
			Write-Host "Adding Cert to app pool" $certName
			Set-CertPermission -CertName $certName -User "iis apppool\$($site.ApplicationPool)"
		}
	}

	if(!(Test-Path "IIS:\Sites\$($site.Name)"))
	{
		Write-Host "Adding Site: `"" + $site.Name + "`""
		
		$NewSiteCmd = "New-Website -Name `"" + $site.Name + "`""
		if($site.ApplicationPool) {$NewSiteCmd += " -ApplicationPool " + $($site.ApplicationPool)}
		if($site.PhysicalPath) 
		{
			MakeDirectory($site.PhysicalPath.ToString())
			$NewSiteCmd += " -PhysicalPath " + $site.PhysicalPath.ToString()
		}
		if($site.Port) {$NewSiteCmd += " -Port " + $site.port}
		if($site.Host) {$NewSiteCmd += " -HostHeader " + $site.host}
		if($site.IpAddress) {$NewSiteCmd += " -IPAddress " + $site.IpAddress}
		Write-Host $NewSiteCmd
		Invoke-Expression $NewSiteCmd
		
		New-WebBinding -Name $site.Name -Protocol https -HostHeader $site.host -IPAddress $site.IpAddress
		if($site.SslCertName)
		{
			Write-Host "Adding Cert to site" $site.SslCertName
			Set-CertPermission -CertName $site.SslCertName -User "iis apppool\$($site.ApplicationPool)"
			Assign-IISCertToPort -Hostname $site.host -CertName $site.SslCertName -SitePort 443 -IpAddress $site.IpAddress
		}
	}

	foreach($app in $site.App)
	{
		if(!(Test-Path "IIS:\AppPools\$($app.ApplicationPool)"))
		{
			Write-Host "Adding App pool: " $site.ApplicationPool
			New-WebAppPool -Name $app.ApplicationPool
			if($site.SslCertName)
			{
				Write-Host "Adding Cert to app pool" $certName
				Set-CertPermission -CertName $certName -User "iis apppool\$($app.ApplicationPool)"
			}
		}
		if(!(Test-Path "IIS:\Sites\$($site.Name)\$($app.Name)"))
		{
			Write-Host "Test!Adding App" $app.Name
			New-WebApplication -Site $site.Name -Name $app.Name -PhysicalPath $site.PhysicalPath -ApplicationPool $app.ApplicationPool
		}
	}
}

function global:BuildNewSiteCommand($site)
{
	$NewSiteCmd = "New-Website -Name `"" + $site.Name + "`""
	if($site.ApplicationPool) {$NewSiteCmd += " -ApplicationPool " + $($site.ApplicationPool)}
	if($site.PhysicalPath) 
	{
		MakeDirectory($site.PhysicalPath.ToString())
		$NewSiteCmd += " -PhysicalPath " + $site.PhysicalPath.ToString()
		Write-Host $NewSiteCmd
	}
	if($site.Port) {$NewSiteCmd += " -Port " + $site.port}
	if($site.Host) {$NewSiteCmd += " -HostHeader " + $site.host}
	if($site.IpAddress) {$NewSiteCmd += " -IPAddress " + $site.IpAddress}
	Write-Host $NewSiteCmd
	return $NewSiteCmd
}

function global:DeleteSite($site)
{
	if(Test-Path "IIS:\Sites\$($site.Name)")
	{
		Write-Host "Remove site: " $site.name
		Get-WebBinding $site.Name | Remove-WebBinding
		Remove-Website -Name $site.Name
	}

	if(Test-Path "IIS:\AppPools\$($site.ApplicationPool)")
	{
		Write-Host "Remove app pool: " $site.ApplicationPool
		Remove-WebAppPool -Name $site.ApplicationPool
	}
	foreach($app in $site.App)
	{
		if(Test-Path "IIS:\AppPools\$($app.ApplicationPool)")
		{
			Remove-WebAppPool -Name $app.ApplicationPool
		}
	}
}

function global:TestSite($site)
{
	Write-Host "Test Site $($site.Name)"
	AssertEqual $true (Test-Path "IIS:\Sites\$($site.Name)") "Site: $($site.Name)"
	AssertEqual $true (Test-Path "IIS:\AppPools\$($site.ApplicationPool)") "App Pool: $($site.ApplicationPool)"
	foreach($app in $site.App)
	{
		AssertEqual $true (Test-Path "IIS:\Sites\$($site.Name)\$($app.Name)") "App: $($app.Name)"
		AssertEqual $true (Test-Path "IIS:\AppPools\$($app.ApplicationPool)") "App App Pool: $($app.ApplicationPool)"
	}
	RaiseAssertions
}

function global:ExecuteSites($sites)
{
	if($Sites) {
		foreach ($site in $sites) 
		{
			if($delete) { DeleteSite($site)}
			if($creat) { AddSite($site, $Config.Config.TokenCertName)}
			if($test) { TestSite($site)}
		}
	}
}

function global:ExecuteWebServer($webServer)
{
	ExecuteSites($webServer.Site)
}

#Local Users

function global:AddLocalUser($user)
{
	$UserExist = LocalUserExist($user.UserName)
	if($UserExist -eq $false)
	{
		Write-Host "Adding User, user name: $($user.UserName)"
		$cn = [ADSI]"WinNT://$env:ComputerName,Computer"
		$luser = $cn.Create("User",$user.UserName)
		$luser.SetPassword($user.Password)
		$luser.setinfo()
	
		Write-Host "Set Password properties"
		$luser = Get-WmiObject Win32_UserAccount -Filter ("Domain='{0}' and Name='{1}'" -f $env:ComputerName,$user.UserName)
		$luser.PasswordChangeable = $user.PasswordChangeable
		$luser.PasswordExpires = $user.PasswordExpires
		$luser.Put()
		
		foreach($group in $user.Group)
		{
			Write-Host "Adding user: $($user.UserName) to group: $($group.Name)"
			$group = [ADSI]"WinNT://$env:ComputerName/$($group.Name),group"
			$group.Add("WinNT://$env:ComputerName/$($user.UserName),user")
		}
	}	
}

function global:DeleteLocalUser($user)
{
	$UserExist = LocalUserExist($user.UserName)
	if($UserExist -eq $true)
	{
		Write-Host "Deleting User, user name: $($user.UserName)"
		$server = [ADSI]"WinNT://$env:ComputerName,Computer"
		$server.delete("user",$user.UserName)
	}
}

function global:TestLocalUser($user)
{
	AssertEqual True (LocalUserExist($user.UserName)) "User exist, user name: $($user.UserName)"
		
	foreach($group in $user.Group)
	{
		#AssertEqual True (UserHasMembership $user.UserName, $group.Name) "User membership, user name: $($user.UserName), group name: $($group.Name)"
	}
	RaiseAssertions
}

function UserHasMembership
{   
    # Added the Param Switch 
    Param(
        [string]$user,
        [string]$group
    )

    $cname = gc env:computername
    $objUser = [ADSI]("WinNT://$user")
    $objGroup = [ADSI]("WinNT://$cname/$group,group")
    $members = $objGroup.Invoke('Members')
    $found = $false

    foreach($m in $members)
    {
        if($m.GetType().InvokeMember('Name', 'GetProperty', $null, $m, $null) -eq $user)
        {
            $found = $true
        }
    }
    return $found
}

function global:ExecuteLocalUser($users)
{
	foreach ($user in $users) 
	{
		if($delete) { DeleteLocalUser($user)}
		if($creat) { AddLocalUser($user)}
		if($test) { TestLocalUser($user)}
	}
}	

#Windows Features

function global:AddWindowsFeatrues($feature)
{
	$featureNames = ""
	if(((Get-WindowsFeature -name $feature.Name).Installed) -eq $false)
	{
		$featureNames = $feature.Name
		foreach($subFeature in $feature.SubFeature) { $featureNames += ", $($subFeature.Name)"}
	} 
	foreach($subFeature in $feature.SubFeature) 
	{ 
		if(((Get-WindowsFeature -name $subFeature.Name).Installed) -eq $false)
		{
			if($featureNames -eq "") { $featureNames += "$($subFeature.Name)"}
			else {$featureNames += ", $($subFeature.Name)"}
		}
	}
	if($featureNames -ne "")
	{
		Write-Host "Installing features: $featureNames"
		$OsVersion = "$([environment]::OSVersion.Version.Major).$([environment]::OSVersion.Version.Minor)"
		if($OsVersion -eq "6.1") {Invoke-Expression "Add-WindowsFeature -name $($featureNames)"}
		else{Invoke-Expression "Install-WindowsFeature -name $($featureNames)"}
	}
}

function global:DeleteWindowsFeatrues($feature)
{
	if(((Get-WindowsFeature -name $feature.Name).Installed) -eq $true)
	{
		Write-Host "Removeing feature: $($feature.Name)"
		Remove-WindowsFeature -name $feature.Name
	}
}

function global:TestWindowsFeatrues($feature)
{
	AssertEqual True (Get-WindowsFeature -name $feature.Name).Installed "Windows feature $($feature.Name)"
	foreach($subFeature in $feature.SubFeature) { AssertEqual True (Get-WindowsFeature -name $subFeature.Name).Installed "Windows feature $($subFeature.Name)" }
	RaiseAssertions
}

function global:ExecuteWindowsFeature($features)
{
	foreach ($feature in $features) 
	{
		#if($delete) { DeleteWindowsFeatrues($feature)}
		if($creat) { AddWindowsFeatrues($feature)}
		if($test) { TestWindowsFeatrues($feature)}
	}
}

#Installs

function global:AddInstall($install)
{
	if(Installed($install))
	{
		Write-Host "Install already present: $($install.name)"
		return
	}
	$installDir = "C:\TempInstall"
	$filename = ""
	MakeDirectory($installDir)
	if($install.InstallerUrl) 
	{
		$filename = $install.InstallerUrl.Substring($install.InstallerUrl.LastIndexOf("/") + 1)
		(New-Object System.Net.WebClient).DownloadFile($install.InstallerUrl, "$installDir\$filename")
	}
	if($install.InstallerPath)
	{
		$filename = $install.InstallerPath.Substring($install.InstallerPath.LastIndexOf("\") + 1)
		Copy $($install.InstallerPath) $installDir\$filename
	}
	switch ($install.InstallType) 
	{
		"EXE" { 
			StartProcess -command:$installDir\$filename -wait:$true -parameters:" /q /norestart /log logs\VisualCPlusPlusRedistributableInstall.log"
			break     
		}
		"MSI" {
			StartProcess -command:msiexec.exe -wait:$true -parameters:"/i $installDir\$filename /qn /l* logs\$filenameInstall.log"
			break
		 }
		 "MSU" {
			StartProcess -command:wusa.exe -wait:$true -parameters:"$installDir\$filename /quiet /norestart /log:logs\$filenameInstall.log"
			break
		 }
		"Custom" {
			StartProcess -command:$installDir\$filename -wait:$true -parameters: $install.Parameters
			break
		 }
		default {
		 throw "Not a valid install type"
		 }
	}
}

function global:TestInstall($install)
{
	AssertEqual $true (Installed($install)) "Installed: $($install.Name)"
	RaiseAssertions
}

function global:Installed($install)
{

	if($install.Verify.VerifyType -eq "UnInstall")
	{
		return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | ?{$_.DisplayName -like "$($install.Verify.DisplayName)"}) -ne $null)
	}
	if($install.Verify.VerifyType -eq "WinService")
	{
		return ((Get-WmiObject -Class Win32_Service -Filter "Name='$($install.Verify.ServiceName)'") -ne $null)
	}
	if($install.Verify.VerifyType -eq "HotFix")
	{
		return ((Get-Hotfix "$($install.Verify.Id)" -errorAction SilentlyContinue) -ne $null)
	}
}

function global:ExecuteInstall($installs)
{
	foreach ($install in $installs) 
	{
		#if($delete) { DeleteInstall($user)} not supported
		if($creat) { AddInstall($install)}
		if($test) { TestInstall($install)}
	}
}

#Set Registry

function global:SetRegistry($registry)
{
	if($registry.Value -ne ((Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system).GetValue($registry.Key)))
	{
		Set-itemproperty $registry.Path -name $registry.Key -value $registry.Value
	}
}

function global:TestRegistry($registry)
{
	AssertEqual $registry.Value ((Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system).GetValue($registry.Key)) $registry.Name
	RaiseAssertions
}

function global:ExecuteSetRegistry($registries)
{
	foreach ($registry in $registries) 
	{
		if($creat) { SetRegistry($registry)}
		if($test) { TestRegistry($registry)}
	}
}

#PowerShell

function global:RunPowershell($powerShell)
{
	if((Invoke-Expression $powershell.Verify.Command) -ne $true)
	{
		Write-Host "$($powershell.Command)"
		Invoke-Expression "$($powershell.Command)"
	}
}

function global:TestPowerShell($powerShell)
{
	AssertEqual $true (Invoke-Expression $powershell.Verify.Command) $powershell.Verify.Message
	RaiseAssertions
}

function global:ExecutePowerShell($powerShells)
{
	foreach ($powerShell in $powerShells | Sort Order) 
	{
		if($creat) { RunPowershell($powerShell)}
		if($test) { TestPowerShell($powerShell)}
	}
}

#SetEnviromentVariable

function global:SetVariable($variable)
{
	if([environment]::GetEnvironmentVariable($variable.Name,$variable.Level) -ne $variable.Value )
	{
		Write-Host "Setting Environment variable: $($variable.Name)"
		[Environment]::SetEnvironmentVariable($variable.Name,$variable.Value,$variable.Level)
	}
}

function global:TestVariable($variable)
{
	AssertEqual $variable.Value [environment]::GetEnvironmentVariable($variable.Name,$variable.Level) "Environment variable: $($variable.Name)"
	RaiseAssertions
}

function global:ExecuteEnviromentVariable($variables)
{
	foreach ($variable in $variables ) 
	{
		if($creat) { SetVariable($variable)}
		if($test) { TestVariable($variable)}
	}
}

#Directory access 

function global:SetAcl($acl)
{
Write-Host "Set the Acl for, user: $($acl.User), directory: $($acl.Directory)"
	if(((Get-Acl "$($acl.Directory)").AccessToString | findstr "$env:ComputerName\$($acl.User)") -eq $null)
	{
		Write-Host "Set the Acl for, user: $($acl.User), directory: $($acl.Directory)"
		$aclDir = Get-Acl $acl.Directory						
		$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($acl.User, $acl.Rights, $acl.InheritanceFlag, $acl.PropagationFlag, $acl.AccessControlType)
		$aclDir.AddAccessRule($rule)
		Set-Acl $acl.Directory $aclDir
	}
}

function global:TestAcl($acl)
{
	AssertEqual $true (((Get-Acl "$($acl.Directory)").AccessToString | findstr "$env:ComputerName\$($acl.User)") -ne $null) "Set ACL, Directory: $($acl.Name)"
	RaiseAssertions
}

function global:ExecuteAcl($Acls)
{
	foreach ($acl in $Acls ) 
	{
		if($creat) { SetAcl($acl)}
		if($test) { TestAcl($acl)}
	}
}

#Special scripts

function global:RenameAdminUser($userName,$password)
{
	$userName = $args[0]
	$password = $args[1]
	Write-Host "args $args"
	Write-Host "userName $userName"
	Write-Host "password $password"
	$AdminUserExist = LocalUserExist($userName)
	if($AdminUserExist -eq $false)
	{
		$UserExist = LocalUserExist("administrator")
		if($UserExist -eq $false)
		{
			Write-Host "Add User"
			$cn = [ADSI]"WinNT://$env:ComputerName,Computer"
			$user = $cn.Create("User",$userName)
			$user.SetPassword($password)
			$user.setinfo()

			Write-Host Set Password to never expire
			$user = Get-WmiObject Win32_UserAccount -Filter ("Domain='{0}' and Name='{1}'" -f $env:ComputerName,$userName)
			$user.PasswordChangeable = $false
			$user.PasswordExpires = $false
			$user.Put()
			$group = [ADSI]"WinNT://$env:ComputerName/Administrators,group"
			$group.Add("WinNT://$env:ComputerName/$userName,user")
		} else
		{
			Write-Host Rename administrator user and set passord
			$admin=[adsi]("WinNT://$env:ComputerName/administrator, user")
			$admin.psbase.rename($userName)
			$admin.psbase.invoke("SetPassword", $password)
		}
	}
}

#WinService

function global:SetWinService($service)
{
	$ServiceAccount = ((Get-WmiObject win32_service -Filter "Name='$($service.Name)'").StartName)
	if(".\$($service.ServiceAccount.UserName)" -ne $ServiceAccount)
	{
		Write-Host "Set the user account for the: $($service.Name)"
		$JobProc = Get-WmiObject Win32_service -filter "name='$($service.Name)'"
		$JobProc.Change($null,$null,$null,$null,$null,$false,".\$($service.ServiceAccount.UserName)",$service.ServiceAccount.Password)
	}
}

function global:TestWinService($service)
{
	AssertEqual $true (((Get-WmiObject win32_service -Filter "Name='$($service.Name)'").StartName) -eq ".\$($service.ServiceAccount.UserName)") "Configure service: $($service.Name)"
	RaiseAssertions
}

function global:ExecuteWinService($services)
{
	foreach ($service in $services ) 
	{
		if($creat) { SetWinService($service)}
		if($test) { TestWinService($service)}
	}
}

#scheduled Task

function global:AddScheduledTask($task)
{
	$sTask = (Get-ScheduledTask  | Where-Object {$_.TaskName -like "$($task.Name)" })
	if($sTask -eq $null)
	{
		Write-Host "Add scheduled task $($task.Name)"
		$TaskAction = New-ScheduledTaskAction -Execute "$($task.TaskAction.Execute)" 
		$TaskTrigger = Invoke-Expression "New-ScheduledTaskTrigger $($task.TaskTrigger.Arguments)"
		Register-ScheduledTask -Action $TaskAction -Trigger $Tasktrigger -TaskName $($task.Name) -User "$($task.UserName)" -RunLevel Highest
	}
}

function global:TestScheduledTask($task)
{
	AssertNotNull (Get-ScheduledTask  | Where-Object {$_.TaskName -like "$($task.Name)" }) "Task named: $($task.Name)"
	RaiseAssertions
}

function global:ExecuteScheduledTask($scheduledTasks)
{
	$OsVersion = "$([environment]::OSVersion.Version.Major).$([environment]::OSVersion.Version.Minor)"
	Write-Host "OS Version: $OsVersion"
	if($OsVersion -eq "6.2" -Or $OsVersion -eq "6.1")
	{
		Write-Error "Scheduled tasks not supported in this version of windows"
		Return
	}
	
	foreach ($task in $scheduledTasks ) 
	{
		if($creat) { AddScheduledTask($task)}
		if($test) { TestScheduledTask($task)}
	}
}

#Font

function global:AddFont($font)
{
	$ArialUnicode = Get-Font -font "$($font.Name)"
	if($ArialUnicode -eq $null)
	{
		Write-Host "Installing font: $($font.Name)"
		$installDir = "C:\TempInstall"
		$filename = $font.FontPath.Substring($font.FontPath.LastIndexOf("\") + 1)
		MakeDirectory($installDir)
		
		Copy $font.FontPath $installDir\$filename
		$FONTS = 0x14
		$objShell = New-Object -ComObject Shell.Application
		$objFolder = $objShell.Namespace($FONTS)
		$objFolder.CopyHere("$installDir\$filename")
	}
}

function global:TestFont($font)
{
	Write-Host "font  $($font.Name))"
	AssertNotNull (Get-Font -font "$($font.Name)") "Font named: $($font.Name)"
	RaiseAssertions
}

function global:ExecuteFont($Fonts)
{
	foreach ($font in $Fonts ) 
	{
		if($creat) { AddFont($font)}
		if($test) { TestFont($font)}
	}
}

#Certs

function global:AddCert($cert)
{
	$findCert = (Get-ChildItem $cert.StoreLocation | Where-Object {$_.FriendlyName -eq "$($cert.FriendlyName)"} | Format-List -Property *)
	if ($findCert -ne $null)
	{
		Write-Host "Adding Cert: $($cert.Name)"
		$pwd = ConvertTo-SecureString -String $cert.Password -Force –AsPlainText
		Import-PfxCertificate –FilePath $cert.Path -CertStoreLocation $cert.StoreLocation -Password $pwd
	}
}

function global:DeleteCert($cert)
{
	$findCert = (Get-ChildItem $cert.StoreLocation | Where-Object {$_.FriendlyName -eq "$($cert.FriendlyName)"} | Format-List -Property *)
	if ($findCert -ne $null)
	{
		Write-Host "Removing Cert: $($cert.Name)"
		$findCert = (Get-ChildItem $cert.StoreLocation | Where-Object {$_.FriendlyName -eq "Local Cert"} | select -first 1 -erroraction STOP)
		Remove-Item -Path "$($cert.StoreLocation)\$($findCert.Thumbprint)" -Force -Confirm:$false
	}
}

function global:TestCert($cert)
{
	$findCert = (Get-ChildItem $cert.StoreLocation | Where-Object {$_.FriendlyName -eq "$($cert.FriendlyName)"} | Format-List -Property *)
	AssertNotNull ($findCert) "Cert named: $($cert.Name)"
	RaiseAssertions
}

function global:ExecuteCert($certs)
{
	foreach ($cert in $certs ) 
	{
		if($creat) { AddCert($cert)}
		#if($delete) { DeleteCert($cert)}
		if($test) { TestCert($cert)}
	}
}

