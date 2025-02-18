# Here we choose which IP address that they want to connect to. We also break if they don't enter anything.
$address = Read-Host "Specify the IP address of the machine you want to connect to"
Write-Host "This will only work if the machine you are trying to connect to has PSSession enabled"
if ($address -eq "") {
    exit
}

# Trust the host and start the PSSession service
winrm quickconfig
Set-Item wsman:\localhost\Client\TrustedHosts -Value "$address" -Force
Get-Item wsman:\localhost\Client\TrustedHosts
$session = New-PSSession -ComputerName "$address" -Credential Administrator

# Function to create a Local Admin
function Create-NewLocalAdmin {
    [CmdletBinding()]
    param (
        [string] $NewLocalAdmin,
        [securestring] $Password
    )
    process {
        Invoke-Command -Session $session -ScriptBlock {
            param ($NewLocalAdmin, $Password)
            New-LocalUser "$NewLocalAdmin" -Password $Password -FullName "$NewLocalAdmin" -Description "Temporary local admin"
            Add-LocalGroupMember -Group "Administrators" -Member "$NewLocalAdmin"
            Write-Output "$NewLocalAdmin has been created and added to Administrators group."
        } -ArgumentList $NewLocalAdmin, $Password
    }
}

# Function to create an AD user
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
    process {
        Invoke-Command -Session $session -ScriptBlock {
            param ($adName, $adGivenName, $adsurname, $adsamaccountname, $aduserprincipalname, $adOU, $adaccountPassword)
            New-ADUser -Name "$adName" `
                       -GivenName "$adGivenName" `
                       -Surname "$adsurname" `
                       -SamAccountName "$adsamaccountname" `
                       -UserPrincipalName "$aduserprincipalname" `
                       -Path "$adOU" `
                       -AccountPassword $adaccountPassword `
                       -Enabled $true
            Write-Output "$adsamaccountname has been successfully created."
        } -ArgumentList $adName, $adGivenName, $adsurname, $adsamaccountname, $aduserprincipalname, $adOU, $adaccountPassword
    }
}

# Menu to choose an action
while ($true) {
    $choice = Read-Host "Choose an option: (Locala - Create Local Admin, aduser - Create AD User, exit - Quit)"
    
    if ($choice -eq "Locala") {
        $NewLocalAdmin = Read-Host "Enter new local admin username"
        $Password = Read-Host -AsSecureString "Enter password for $NewLocalAdmin"
        Create-NewLocalAdmin -NewLocalAdmin $NewLocalAdmin -Password $Password
    }
    elseif ($choice -eq "aduser") {
        $adName = Read-Host "Enter the name of the user"
        $adGivenName = Read-Host "Enter the user's first name"
        $adsurname = Read-Host "Enter the user's surname"
        $adLetteroffirstname = Read-Host "Enter the first letter of the user's first name"
        $adsamaccountname = "$adLetteroffirstname$adsurname"
        $aduserprincipalname = Read-Host "Enter user's full domain name/SMTP mail"
        $adOU = Read-Host "Enter the OU path (use OU=<Path>)"
        $adaccountPassword = Read-Host "Enter the user's temporary password" | ConvertTo-SecureString -AsPlainText -Force

        Create-adNewUser -adName $adName `
                         -adGivenName $adGivenName `
                         -adsurname $adsurname `
                         -adsamaccountname $adsamaccountname `
                         -aduserprincipalname $aduserprincipalname `
                         -adOU $adOU `
                         -adaccountPassword $adaccountPassword
    }
    elseif ($choice -eq "exit") {
        Write-Host "Exiting script..."
        break
    }
    else {
        Write-Host "Invalid choice. Please try again."
    }
}
