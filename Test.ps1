#Here we choose which ip address that they want to connect to. We also break if they dont enter anything
$address = read-host "Specify the ip address of the machine you want to create a localadmin on"
write-host "This will only work if the machine you are trying to connect to has PSSession enabled"
if ($address -eq "") {
    break
}

#Here we trust the host address that they entered above start the PSSession service
winrm quickconfig
Set-Item wsman:\localhost\Client\TrustedHosts -Value "$address" -force
Get-Item wsman:\localhost\Client\TrustedHosts 
Restart-Service WinRM
$session = New-PSSession -ComputerName "$address" -Credential Administrator

#Here we give them options of what they want to do
$choice = Read-Host "If you want to create a Local-admin, Type Locala. If you want to create a AD User type aduser. If you want to quit type -Exit"
if ($choice -eq "Locala") {
    $Localadmin
}
if ($choice -eq "aduser") {
    $newUser
}
if ($choice -eq "exit") {
    break
}


#The script of creating a local admin
Invoke-Command -Session $session -ScriptBlock {
function Create-NewLocalAdmin {
    [CmdletBinding()]
    param (
        [string] $NewLocalAdmin,
        [securestring] $Password
    )
    begin {
    }
    process {
        New-LocalUser "$NewLocalAdmin" -Password $Password -FullName "$NewLocalAdmin" -Description "Temporary local admin"
        Write-Verbose "$NewLocalAdmin local user created"
        Add-LocalGroupMember -Group "Administrators" -Member "$NewLocalAdmin"
        Write-Verbose "$NewLocalAdmin added to the local administrator group"
    }
    end {
    }
}
$NewLocalAdmin = Read-Host "New local admin username:"
$Password = Read-Host -AsSecureString "Create a password for $NewLocalAdmin"
$Localadmin = Create-NewLocalAdmin -NewLocalAdmin $NewLocalAdmin -Password $Password -Verbose
net localgroup "Administrators"



function Create-adNewUser {
    [cmdletBinding()]
    param (
        [string] $adName,
        [string] $adGivenName,
        [string] $adsurname,
        [string] $adsamaccountname,
        [string] $aduserprincipalname,
        [string] $adOU,
        [securestring] $adaccountPassword
    )
    begin {
    }
    process {
        # Create the new Active Directory user
        New-ADUser -Name "$adName" `
                   -GivenName "$adGivenName" `
                   -Surname "$adsurname" `
                   -SamAccountName "$adsamaccountname" `
                   -UserPrincipalName "$aduserprincipalname" `
                   -Path "$adOU" `
                   -AccountPassword $adaccountPassword `
                   -Enabled $true `
                   -Verbose
        
        Write-Verbose "$adsamaccountname was created successfully"
    }
}

# User input prompts
$adName = Read-Host "The name of the user"
$adGivenName = Read-Host "The user's first name"
$adsurname = Read-Host "The user's surname"
$adLetteroffirstname = Read-Host "The first letter of the user's first name"
$adsamaccountname = "$adLetteroffirstname$adsurname"
$aduserprincipalname = Read-Host "User's Full Domain Name/SMTP Mail"
$adOU = Read-Host "Specify the OU path (use OU=<Path>)"
$adaccountPassword = Read-Host "The user's temporary password" | ConvertTo-SecureString -AsPlainText -Force

# Create the new user
$newUser = Create-adNewUser -adName $adName `
                             -adGivenName $adGivenName `
                             -adsurname $adsurname `
                             -adsamaccountname $adsamaccountname `
                             -aduserprincipalname $aduserprincipalname `
                             -adOU $adOU `
                             -adaccountPassword $adaccountPassword

}