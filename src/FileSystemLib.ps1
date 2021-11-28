# ------------------ Folders -----------------------

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
        Write-Host "Deleting folder: folder name " $folder.Name
        Delete-Directory($folder.Path)
    }
}

function global:TestFolder($folder)
{
	AssertEqual True (Test-Path ($folder.Path)) "Folder exist, Folder name: $($folder.Name), Folder path: $($folder.Path)"
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


#--------------------- Directory Access -------------------------------
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
	$acls = (Get-Acl "$($acl.Directory)")
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