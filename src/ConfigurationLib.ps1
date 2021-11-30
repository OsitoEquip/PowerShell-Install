# ++++++++++++++++++++ Registry ++++++++++++++++++++++++++++++++++

function global:Registry($registry)
{
	if($registry.Value -ne ((Get-Item "Registry::$($registry.Path)").GetValue($registry.Key)))
	{
        Write-Host "Setting registry for: $($registry.Name)"
        Set-itemproperty "Registry::$($registry.Path)" -name $registry.Key -value $registry.Value
        if($registry.Type -eq "DWord")
        {
            Set-itemproperty "Registry::$($registry.Path)" -name $registry.Key -value $registry.Value -Type DWord
        }
	}
}

function global:TestRegistry($registry)
{
    $TempReg = ((Get-Item "Registry::$($registry.Path)"))
    if($TempReg -eq $null){	AssertEqual $true $false "$($registry.Name)"}
	AssertEqual $registry.Value ((Get-Item "Registry::$($registry.Path)").GetValue($registry.Key)) "Registry setting for: $($registry.Name)"
}

function global:ExecuteRegistry($registries)
{
	foreach ($registry in $registries) 
	{
		if($creat) { Registry($registry)}
		if($test) { TestRegistry($registry)}
	}
}

# ++++++++++++++++++ SetEnviromentVariable ++++++++++++++++++++++++++++++

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