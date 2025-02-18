#Password generator


$passwordgenerator 
    $Answer = Read-Host "Do you want to create your own password? Please answer -Yes or -No"
    if ($Answer -eq "Yes" ) { 
        $Custom = Read-Host "Input your password"  #-AsSecureString
        $plaintext = Read-Host "Do you want your password in plaintext? Please answer -Yes or -No" 
        if ($plaintext -eq "Yes") {
            Read-Host $Custom  
        }
        if ($plaintext -ne "Yes") {
            Write-Host "Alright, better remember it then. Have an amazing day"
            Break
        }      
        
    }
    if ($Answer -eq "Yes") {
        $Lenght = [int](Read-Host "Alright how long do you want your password?")
        $Array = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8','9','0', '!', '@', '#', '$', '%', '^', '&', '*')
        $randomString = ""
        for(($counter=0); $counter -lt $Lenght; $counter++)
        {
        $randomCharacter = get-random -InputObject $Array
        $randomString = $randomString + $randomCharacter
        }
        Write-Host "Here is your new password $randomString"
    }
