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
            New-ADUser -Name "$adName" -CannotChangePassword $true -PasswordNeverExpires $true `
                       -GivenName "$adGivenName" `
                       -Surname "$adsurname" `
                       -SamAccountName "$adsamaccountname" `
                    -UserPrincipalName "$($adsamaccountname)@Gruppe4.lab" `
                    -Path $adOU `
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
            $aduserprincipalname = "$adsamaccountname@Gruppe4.lab"
            $adOU = Read-Host "Enter the OU path (use OU=<UsersOU>,DC=Gruppe4,DC=lab)"
            $adOU = "OU=$adOU,DC=Gruppe4,DC=lab"
            $adaccountPassword = Read-Host "Enter the user's temporary password" | ConvertTo-SecureString -AsPlainText -Force
    
            Create-adNewUser -adName $adName `
                             -adGivenName $adGivenName `
                             -adsurname $adsurname `
                             -adsamaccountname $adsamaccountname `
                             -aduserprincipalname $aduserprincipalname `
                             -adOU $adOU `
            }
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
            $csvPath = Read-Host "Enter the path to the CSV file"
            $users = Import-Csv -Path $csvPath
        
            Write-Host "DEBUG: Users Imported from CSV:"
            $users | ForEach-Object { Write-Host "Username: $($_.Username), OU: $($_.OU), Password: $($_.Password)" }
        
            foreach ($user in $users) {
                try {
                    # Ensure OU is trimmed and remove potential extra quotes
                    $user.OU = $user.OU.Trim() -replace '^"|"$', ''  # Removes leading/trailing double quotes
                    
                    if (-not $user.OU -or [string]::IsNullOrEmpty($user.OU)) {
                        Write-Error "OU is null or empty for user $($user.Username). Skipping user."
                        continue
                    }
        
                    if (-not $user.Password) {
                        Write-Error "Password is null for user $($user.Username). Skipping user."
                        continue
                    }
        
                    Write-Host "Processing user: $($user.Username), OU: $($user.OU)"
        
                    try {
                        # Check if OU exists
                        $ouExists = Invoke-Command -Session $session -ScriptBlock {
                            param ($ou)
                            Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'" -ErrorAction SilentlyContinue
                        } -ArgumentList $user.OU
        
                        # Create OU only if it does not exist
                        if (-not $ouExists) {
                            Invoke-Command -Session $session -ScriptBlock {
                                param ($ou)
                                New-ADOrganizationalUnit -Name ($ou -split ',')[0].Replace("OU=", "") -Path ($ou -replace "OU=.*?,") -ErrorAction Stop
                            } -ArgumentList $user.OU
                        }
        
                        # Convert password to secure string
                        $securePassword = $user.Password | ConvertTo-SecureString -AsPlainText -Force
                    } catch {
                        Write-Error "Failed to process user $($user.Username): $_"
                        continue
                    }
        
                    # Create the user
                    Invoke-Command -Session $session -ScriptBlock {
                        param ($user, [SecureString]$securePassword)
                        
                        Write-Host "Creating user in OU: $($user.OU)"
        
                        try {
                            New-ADUser `
                                -Name "$($user.FirstName) $($user.LastName)" `
                                -GivenName $user.FirstName `
                                -Surname $user.LastName `
                                -SamAccountName $user.Username `
                                -UserPrincipalName "$($user.Username)@Gruppe4.lab" `
                                -Path $user.OU `
                                -AccountPassword $securePassword `
                                -Enabled $true `
                                -CannotChangePassword $true `
                                -PasswordNeverExpires $true 
        
                            Write-Output "$($user.Username) has been successfully created."
                        } catch {
                            Write-Error "Failed to create user $($user.Username): $_"
                        }
                    } -ArgumentList $user, $securePassword
                } 
                catch {
                    Write-Error "Failed to process user $($user.Username): $_"
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
