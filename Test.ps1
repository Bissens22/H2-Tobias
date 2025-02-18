$Address = Read-Host "Specify the ip address of the machine you want to establish a connection with"

winrm quickconfig
Set-Item wsman:\localhost\Client\TrustedHosts -Value "$Address"
Get-Item wsman:\localhost\Client\TrustedHosts
Restart-Service WinRM
$Session = New-PSSession -ComputerName "$Address" -Credential Administrator



Invoke-command -Session $Session -ScriptBlock {
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
        Write-Verbose "$NewLocalAdmin local user crated"
        Add-LocalGroupMember -Group "Administrators" -Member "$NewLocalAdmin"
        Write-Verbose "$NewLocalAdmin added to the local administrator group"
    }    
    end {
    }
}
$NewLocalAdmin = Read-Host "New local admin username:"
$Password = Read-Host -AsSecureString "Create a password for $NewLocalAdmin"
Create-NewLocalAdmin -NewLocalAdmin $NewLocalAdmin -Password $Password -Verbose
net localgroup "Administrators"
}