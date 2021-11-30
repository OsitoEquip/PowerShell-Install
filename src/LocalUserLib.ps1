#++++++++++++++ Local Users ++++++++++++++++++++

function global:AddLocalUser($user)
{
	$UserExist = LocalUserExist($user.UserName)
	if($UserExist -eq $false)
	{
		New-LocalUser -Name "$($user.UserName)" -Password (ConvertTo-SecureString $user.Password -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires

		foreach($group in $user.Group)
		{
			Write-Host "Adding user: $($user.UserName) to group: $($group.Name)"
			$group = [ADSI]"WinNT://$env:ComputerName/$($group.Name),group"
			$group.Add("WinNT://$env:ComputerName/$($user.UserName),user")
		}
	}	

	foreach($Language in $user.Language)
	{
		if((LanguagePresent $Language.EnglishName) -ne $true)
		{
			Write-Host "Adding Language: $($Language.LanguageTag) to user: $($user.UserName)"
			AddLanguage $($Language.LanguageTag)
		}
	}
}

function global:AddLanguage
{   
    Param(
		[string]$LanguageTag
	)
	$lanList = Get-WinUserLanguageList
	$lanList.Add("$LanguageTag")
	Set-WinUserLanguageList $lanList -Force
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
	AssertEqual $True (LocalUserExist($user.UserName)) "User exist, user name: $($user.UserName)"
	AssertEqual $True (((Get-LocalUser -name $user.UserName).PasswordExpires -eq $null)) "Password never expires, user name: $($user.UserName)"
		
	foreach($group in $user.Group)
	{
		Write-Debug (Get-LocalGroupMember -Name $group.Name -Member $user.UserName).Name
		AssertEqual $true (Get-LocalGroupMember -Name $group.Name -Member $user.UserName).Name.Contains($user.UserName) "User membership, user name: $($user.UserName), group name: $($group.Name)"
	}

	foreach($Language in $user.Language)
	{
		AssertEqual $true (LanguagePresent $Language.EnglishName) "Keyboard language: '$($Language.EnglishName)'"
	}
}

function global:LanguagePresent($EnglishName)
{
	return ((Get-WinUserLanguageList | where {$_.EnglishName -eq "$EnglishName"}).Count -gt 0)
}

function global:LocalUserExist([string] $UserName)
{
	$objComputer = [ADSI]("WinNT://$env:ComputerName,computer")
	$colUsers = ($objComputer.psbase.children | Where-Object {$_.psBase.schemaClassName -eq "User"} | Select-Object -expand Name)
	return $colUsers -contains $UserName
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
