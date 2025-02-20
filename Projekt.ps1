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
    $choice = Read-Host "Choose an option: (Locala - Create Local Admin, aduser - Work with AD Users, exit - Quit)"
    
    if ($choice -eq "Locala") {
        $NewLocalAdmin = Read-Host "Enter new local admin username"
        $Password = Read-Host -AsSecureString "Enter password for $NewLocalAdmin"
        Create-NewLocalAdmin -NewLocalAdmin $NewLocalAdmin -Password $Password
    }
    elseif ($Choice -eq "aduser") {
        $Userchoice = Read-host "Choose an option: (1 - List users in OU, 2 - Create a new Users, 3 - Change the password of a user, 4 - Delete a user, 5 - Import users from a csv file)"
        
        # List users in an OU
        if ($Userchoice -eq "1") {
            $adOU = Read-Host "Enter the OU path (use OU=<UsersOU>)"
            Invoke-Command -Session $session -ScriptBlock {
                param ($adOU)
                Get-ADUser -Filter * -SearchBase "$adOU" | Select-Object Name, SamAccountName, UserPrincipalName
            } -ArgumentList $adOU
        }
        # Create a new user
        if ($Userchoice -eq "2") {
            $adName = Read-Host "Enter the name of the user"
            $adGivenName = Read-Host "Enter the user's first name"
            $adsurname = Read-Host "Enter the user's surname"
            $adLetteroffirstname = Read-Host "Enter the first letter of the user's first name"
            $adsamaccountname = "$adLetteroffirstname$adsurname"
            $aduserprincipalname = Read-Host "Enter user's full domain name/SMTP mail"
            $adOU = Read-Host "Enter the OU path (use OU=<UsersOU>,DC=Gruppe4,DC=lab)"
            $adaccountPassword = Read-Host "Enter the user's temporary password" | ConvertTo-SecureString -AsPlainText -Force
    
            Create-adNewUser -adName $adName `
                             -adGivenName $adGivenName `
                             -adsurname $adsurname `
                             -adsamaccountname $adsamaccountname `
                             -aduserprincipalname $aduserprincipalname `
                             -adOU $adOU `
                             -adaccountPassword $adaccountPassword
        } 
        # Change the password of a user
        if ($Userchoice -eq "3") {
            $aduser = Read-Host "Enter the username of the user"
            $adnewpassword = Read-Host "Enter the new password for the user" | ConvertTo-SecureString -AsPlainText -Force
            Invoke-Command -Session $session -ScriptBlock {
                param ($aduser, $adnewpassword)
                if (Get-ADUser -Identity "$aduser") {
                    Set-ADAccountPassword -Identity "$aduser" -NewPassword $adnewpassword -Reset
                    Write-Output "$aduser's password has been changed."
                } else {
                    Write-Output "User not found."
                }
            } -ArgumentList $aduser, $adnewpassword
        }
        # Delete a user
        if ($Userchoice -eq "4") {
            $aduser = Read-Host "Enter the username of the user"
            Invoke-Command -Session $session -ScriptBlock {
                param ($aduser)
                $ask = Read-Host "Are you sure you want to delete $aduser? (yes/no)"
                if ($ask -eq "yes") {
                    Remove-ADUser -Identity "$aduser" -Confirm:$false
                    Write-Output "$aduser has been deleted."
                }
                if ($ask -eq "no") {
                    Write-Output "User has not been deleted."
                }                
            } -ArgumentList $aduser
        }
        if ($userchoice -eq "5") {
            $csvfile = Read-Host "Enter the path to the csv file"
            $users = Import-Csv $csvfile
            foreach ($user in $users) {
                $adName = $user.Name
                $adGivenName = $user.GivenName
                $adsurname = $user.Surname
                $adLetteroffirstname = $user.FirstLetter
                $adsamaccountname = "$adLetteroffirstname$adsurname"
                $aduserprincipalname = $user.UserPrincipalName
                $adOU = $user.OU
                $adaccountPassword = $user.Password | ConvertTo-SecureString -AsPlainText -Force
                Create-adNewUser -adName $adName `
                                 -adGivenName $adGivenName `
                                 -adsurname $adsurname `
                                 -adsamaccountname $adsamaccountname `
                                 -aduserprincipalname $aduserprincipalname `
                                 -adOU $adOU `
                                 -adaccountPassword $adaccountPassword
            
            }
        }
    }
    elseif ($choice -eq "exit") {
        Write-Host "Exiting script..."
        break
    }
    else {
        Write-Host "Invalid choice. Please try again."
    }
}
