$Address = Read-Host "Specify the ip address of the machine you want to establish a connection with"
if ($Address -eq "") {
    Break
}

winrm quickconfig
Set-Item wsman:\localhost\Client\TrustedHosts -Value "$Address" -Force
Get-Item wsman:\localhost\Client\TrustedHosts
Restart-Service WinRM
$Session = New-PSSession -ComputerName "$Address" -Credential Administrator

$choice = Read-Host "If you want to create a Local-admin, Type -Locala, If you want to do nothing type -Exit"
if ($choice -eq "Locala") {
    $Localadmin
}
if ($choice -eq "Exit") {
    break
}
if ($Choice -ne "Exit", "Locala") {
    Break
}

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
$Localadmin = Create-NewLocalAdmin -NewLocalAdmin $NewLocalAdmin -Password $Password -Verbose
net localgroup "Administrators"
}