# ++++++++++++++++++++ SQL Scripts  ++++++++++++++++++++++++++++++++++


function global:SetSqlScript($SqlScript)
{
	if([System.IO.File]::Exists($SqlScript.File -eq $false)) {throw {"SQL scrip file did not exists"}}
	Invoke-Sqlcmd -inputFile $SqlScript.File -ServerInstance $SqlScript.ServerInstance -verbose  
}

function global:TestSqlScript($SqlScript)
{
	if($SqlScript.Verify)
	{
		$result = Invoke-Sqlcmd -Query $SqlScript.Verify.Query -ServerInstance $SqlScript.ServerInstance -verbose  
		AssertEqual $SqlScript.Verify.QueryReturn $result[0] "Sql Verify query, $($SqlScript.Verify.Message)"
	}
}

function global:ExecuteSqlScript($SqlScripts)
{
	foreach ($SqlScript in $SqlScripts) 
	{
		#if($delete) { }
		if($creat) { SetSqlScript($SqlScript)}
		if($test) { TestSqlScript($SqlScript)}
	}
}


# ++++++++++++++++++++ SQL Users  ++++++++++++++++++++++++++++++++++

function global:SetSqlLogin($SqlLogin)
{
	$sql=$null
	if((SqlLoginExist $SqlLogin) -eq $false)
	{
		if($SqlLogin.WindowsUser -eq $true)
		{
			Write-Host "Adding Windows user, Sql Login, for: $($SqlLogin.Name)"
			$sql ="USE [master]
			GO
			CREATE LOGIN [$env:ComputerName\$($SqlLogin.Login)] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english];  
			GO"
		}else 
		{
			Write-Host "Adding Sql Login, for: $($SqlLogin.Name)"
			$sql ="USE [master]
			GO
			CREATE LOGIN [$($SqlLogin.Login)] WITH PASSWORD=N'$($SqlLogin.Password)', DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english], CHECK_EXPIRATION=OFF, CHECK_POLICY=ON
			GO"
		}
	}
	foreach($role in $SqlLogin.SRole)
	{
		Write-Host "Setting Sql Login Role, user name: $($SqlLogin.Name)"
		if($SqlLogin.WindowsUser -eq $true)
		{
			$sql ="$sql
			ALTER SERVER ROLE [$($role.RoleName)] ADD MEMBER [$env:ComputerName\$($SqlLogin.Login)]
			GO"
		}else
		{
			$sql ="$sql
			ALTER SERVER ROLE [$($role.RoleName)] ADD MEMBER [$($SqlLogin.Login)]
			GO"
		}
	}
	Invoke-Sqlcmd -Query $sql -ServerInstance $SqlLogin.ServerInstance -verbose  	
}

function global:DeleteSqlLogin($SqlLogin)
{
	if($SqlLogin.Login -eq "sq"){throw{"Disabled deleting sa account"}}
	$script ="USE [master]
	GO
	DROP LOGIN [$($SqlLogin.Login)]
	GO"
	if($true -eq (SqlLoginExist $SqlLogin))
	{
		Write-Host "Deleteing Sql Login, Login name: $($SqlLogin.Name)"
		Invoke-Sqlcmd -Query $script -ServerInstance $SqlLogin.ServerInstance -verbose  
	}
}

function global:TestSqlLogin($SqlLogin)
{
	AssertEqual $true (SqlLoginExist $SqlLogin) "Sql Login, Login name: $($SqlLogin.Login)"
	foreach($role in $SqlLogin.SRole)
	{
		if($SqlLogin.WindowsUser -eq $true)
		{
			$sqlRole ="SELECT IS_SRVROLEMEMBER('$($role.RoleName)', '$env:ComputerName\$($SqlLogin.Login)')
			GO"
		}else
		{
			$sqlRole ="SELECT IS_SRVROLEMEMBER('$($role.RoleName)', '$($SqlLogin.Login)')
			GO"
		}
		$result = Invoke-Sqlcmd -Query $sqlRole -ServerInstance $SqlLogin.ServerInstance -verbose
		AssertEqual 1 $result[0] "Sql Role $($role.RoleName) for user $($SqlLogin.Login)"
	}
}

function global:SqlUserExist($SqlUser)
{
	$script = "SELECT *
	FROM sys.database_principals
	WHERE name = '$($SqlUser.Login)'"
	
	$users = Invoke-Sqlcmd -Query $script -ServerInstance $SqlUser.ServerInstance -verbose  
	return ($users.Count -eq 1)
}

function global:SqlLoginExist($SqlLogin)
{
	if($SqlLogin.WindowsUser -eq $true)
	{
		$script = "SELECT * from master.dbo.syslogins
		WHERE name = '$env:ComputerName\$($SqlLogin.Login)'"
	}else
	{
		$script = "SELECT * from master.dbo.syslogins
		WHERE name = '$($SqlLogin.Login)'"
	}
	$users = Invoke-Sqlcmd -Query $script -ServerInstance $SqlLogin.ServerInstance -verbose  
	return ($users.Count -eq $null)
}

function global:ExecuteSqlLogin($SqlLogins)
{
	foreach ($SqlLogin in $SqlLogins) 
	{
		if($delete) { DeleteSqlLogin($SqlLogin)}
		if($creat) { SetSqlLogin($SqlLogin)}
		if($test) { TestSqlLogin($SqlLogin)}
	}
}