# ++++++++++++++++++ Folders ++++++++++++++++++++++

function global:AddFolder($folder)
{
    if(!(Test-Path ($folder.Path)))
    {
        Write-Host "Adding folder: folder name " $folder.Name
        Make-Directory($folder.Path)
    }
}

function global:DeleteFolder($folder)
{
    if((Test-Path ($folder.Path)))
    {
        Write-Host "Deleting folder: folder name: '$($folder.Name)', folder path: '$($folder.Path)'"-ForegroundColor Cyan
        Delete-Directory($folder.Path)
    }
}

function global:TestFolder($folder)
{
	AssertEqual True (Test-Path ($folder.Path)) "Folder exist, Folder name: $($folder.Name), Folder path: $($folder.Path)"
	RaiseAssertions
}

function global:ExecuteFolder($folders)
{
    foreach ($folder in $folders) 
    {
        if($delete) { DeleteFolder($folder)}
        if($creat) { AddFolder($folder)}
        if($test) { TestFolder($folder)}
    }
}

function global:Delete-Directory
{
    param([string]$source)
    if((Test-Path $source) -eq $false) {return; }
    Remove-Item $source -Force -Recurse
}

function global:Make-Directory
{
    param(
        [string]$directory
    )
    if((Test-Path "$directory") -eq $false)
	{
		Write-Host "Creating $directory"
		mkdir "$directory"
	}
}

#++++++++++++++++++++ Directory Access ++++++++++++++++++++++++++++++
function global:SetAcl($acl)
{
	$colRights = [System.Security.AccessControl.FileSystemRights]$acl.Rights 

	$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]$acl.InheritanceFlag 
	$PropagationFlag = [System.Security.AccessControl.PropagationFlags]$acl.PropagationFlag 

	$objType =[System.Security.AccessControl.AccessControlType]$acl.AccessControlType 

	$objUser = New-Object System.Security.Principal.NTAccount($acl.User) 

	$objACE = New-Object System.Security.AccessControl.FileSystemAccessRule($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType) 

	$objACL = Get-ACL "$($acl.Directory)" 
	$objACL.AddAccessRule($objACE) 

	Set-ACL "$($acl.Directory)" $objACL
}

function global:TestAcl($acl)
{
	#if (Test-Path ($acl.Directory) -eq $false ){ throw "folder dose not  exist" }
	$uAcl = $acls.Access | Where {$_.IdentityReference -match "$($acl.User)"} | Where {$_.FileSystemRights -match "$($acl.Rights)"}

    AssertEqual $true ($uAcl.Count -gt 0) "ACL, Right: $($acl.Rights), Directory: $($acl.Directory), User: $($acl.User)"
}

function global:ExecuteAcl($Acls)
{
    foreach ($acl in $Acls ) 
    {
        if($creat) { SetAcl($acl)}
        if($test) { TestAcl($acl)}
    }
}

# CACLS
function global:SetCacl($cacl)
{
	Write-Host "Set the CACLs for, user: $($cacl.User), directory: $($cacl.Directory)"
	icacls "$($cacl.Directory) /grant $($cacl.User):$($cacl.Rights) /t"
}

function global:ExecuteCacl($Cacls)
{
    foreach ($cacl in $Cacls ) 
    {
        if($creat) { SetCacl($cacl)}
        if($test) { TestAcl($cacl)}
    }
}

# ++++++++++++++++++++ Network Shares  ++++++++++++++++++++++++++++++++++

function global:SetShare($Share)
{
	if((GET-WMIOBJECT Win32_Share -filter "name='$($share.ShareName)'") -eq $null)
	{
		Write-Host "Setting share for: $($Share.Name)"
		if($Share.User)
		{
			$user = "$env:ComputerName\$($share.User.UserName)"
			New-SmbShare -Name $share.ShareName -Path $share.Path -FullAccess $user -ChangeAccess Everyone
		}else{
			$Shares=[WMICLASS]"WIN32_Share"
			$Shares.Create($share.Path,$share.ShareName,0) 
		}
	}
}

function global:TestShare($Share)
{
	AssertEqual $true ((GET-WMIOBJECT Win32_Share -filter "name='$($share.ShareName)'") -ne $null) "Share exists, share name: $($Share.ShareName)"
}

function global:ExecuteShare($Shares)
{
	foreach ($share in $Shares) 
	{
		if($creat) { SetShare($share)}
		if($test) { TestShare($share)}
	}
}