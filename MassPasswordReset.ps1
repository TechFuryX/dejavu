# Script Name: MassPasswordReset.ps1
# Version: 1.1
# Date: 2023-12-15
# Description: Used to facilitate a mass password reset of user class objects in a traditional Active Directory Domain Services environment following a systemic identity compromise.

# Initialize log file
$logFilePath = Join-Path $PSScriptRoot ("MassPasswordReset_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

# Function to write color-coded log messages
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [bool]$Display = $true
    )
    $colors = @{
        "SOS" = "Green";
        "ERROR" = "Red";
        "INFO" = "White";
        "WARNING" = "Yellow";
        "IMPORTANT" = "Cyan";
    }
    $logEntry = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logFilePath -Value $logEntry
    if ($Display -and $colors.ContainsKey($Level)) {
        Write-Host -ForegroundColor $colors[$Level] $logEntry
    } elseif ($Display) {
        Write-Host $logEntry
    }
}

# Function to exclude the current logged-on user
function Exclude-CurrentUser {
    $cUSamAccountName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[-1]
    $currentUser = Get-ADUser -Filter "SamAccountName -eq '$cUSamAccountName'" -Properties DistinguishedName
    if ($currentUser) {
        $script:excludedUsers += $currentUser.DistinguishedName
       # Write-Log -Message "[EXCLUSION] Excluded Account: $($currentUser.DistinguishedName)" -Level "IMPORTANT" -Display $false
    } else {
        Write-Log -Message "Current logged-on user not found in Active Directory." -Level "WARNING" -Display $true
    }
}

# Function to exclude the MSOL account
function Exclude-MSOLAccount {
    $msolAccount = Get-ADUser -Filter 'SamAccountName -like "MSOL_*"' -Properties DistinguishedName
    if ($msolAccount) {
        $script:excludedUsers += $msolAccount.DistinguishedName
        # Write-Log -Message "[EXCLUSION] Excluded Account: $($msolAccount.DistinguishedName)" -Level "IMPORTANT" -Display $false
    } else {
        Write-Log -Message "MSOL account not found in Active Directory." -Level "WARNING" -Display $true
    }
}

# Function to exclude Admin Account
function Exclude-BuiltinAdmin {
    $Domain = Get-ADDomain
    $RID = (New-Object Security.Principal.SecurityIdentifier $Domain.DomainSID.Value).AccountDomainSid.Value
    $AdminSID = $RID + "-500"
    $adminUser = Get-ADUser -Filter { SID -eq $AdminSID } -ErrorAction SilentlyContinue
    if ($adminUser) {
        $script:excludedUsers += $adminUser.DistinguishedName
        # Write-Log -Message "[EXCLUSION] Excluded Account: $($adminUser.DistinguishedName)" -Level "IMPORTANT" -Display $false
    } else {
        Write-Log -Message "Admin account not found in Active Directory." -Level "WARNING" -Display $true
    }
}

function Exclude-SpecialAccounts {
    # Search for KRBTGT account
    $krbtgtAccount = Get-ADUser -Filter 'SamAccountName -like "krbtgt"' -Properties DistinguishedName
    if ($krbtgtAccount) {
        $script:excludedUsers += $krbtgtAccount.DistinguishedName
        # Write-Log -Message "[EXCLUSION] Excluded Account: $($krbtgtAccount.DistinguishedName)" -Level "IMPORTANT" -Display $false
    } else {
        Write-Log -Message "KRBTGT account not found in Active Directory." -Level "WARNING" -Display $true
    }

    # Search for GUEST account
    $guestAccount = Get-ADUser -Filter 'SamAccountName -like "Guest"' -Properties DistinguishedName
    if ($guestAccount) {
        $script:excludedUsers += $guestAccount.DistinguishedName
        # Write-Log -Message "[EXCLUSION] Excluded Account: $($guestAccount.DistinguishedName)" -Level "IMPORTANT" -Display $false
    } else {
        Write-Log -Message "GUEST account not found in Active Directory." -Level "WARNING" -Display $true
    }
}

# Function to exclude OUs and their child OUs
function Exclude-OUs {
    $excludedOUs = @()
    do {
        $ou = Read-Host "Enter the DistinguishedName of the OU to exclude (e.g., OU=YourOrganizationalUnit,DC=YourDomain,DC=com). Enter 'Q' to stop."
        if ($ou -ne 'q' -and $ou -ne '') {
            $excludedOUs += $ou
        }
    } while ($ou -ne 'q')

    $usersInOUs = @()
    foreach ($excludedOU in $excludedOUs) {
        $usersInOUs += Get-ADUser -Filter * -SearchBase $excludedOU -SearchScope Subtree | Select-Object -ExpandProperty DistinguishedName
    }
    $script:excludedUsers += $usersInOUs
}

CLS
# Log script start
Write-Log -Message "Script started." -Level "SOS"

# Ensure RSAT tools are installed before proceeding
function Check-RSATInstallation {
    try {
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($OSInfo.ProductType -eq 1) {
            $rsatStatus = Get-WindowsCapability -Name "Rsat.ActiveDirectory*" -Online -ErrorAction Stop
            if ($rsatStatus.State -ne "Installed") {
                Write-Log -Message "RSAT tools are not installed on this Workstation. Exiting." -Level "ERROR" -Display $true
                return $false
            } else {
                Write-Log -Message "RSAT tools installed on Workstation." -Level "INFO"
                return $true
            }
        } elseif ($OSInfo.ProductType -eq 2 -or $OSInfo.ProductType -eq 3) {
            $rsatStatus = Get-WindowsFeature -Name "RSAT-AD-Tools" -ErrorAction Stop
            if (-not $rsatStatus.Installed) {
                Write-Log -Message "RSAT tools are not installed on this Domain Controller/Server. Exiting." -Level "ERROR" -Display $true
                return $false
            } else {
                Write-Log -Message "RSAT tools installed on Domain Controller or Server." -Level "INFO"
                return $true
            }
        } else {
            Write-Log -Message "Unsupported system type for this operation." -Level "WARNING" -Display $true
            return $false
        }
    } catch {
        Write-Log -Message "An error occurred while retrieving system information: $_" -Level "ERROR" -Display $true
        return $false
    }
}

# Check RSAT installation and exit if not installed
$rsatInstalled = Check-RSATInstallation
if (-not $rsatInstalled) {
    exit
}

# Initialize excluded users and populate them
$script:excludedUsers = @()
Exclude-CurrentUser
Exclude-MSOLAccount
Exclude-BuiltinAdmin
Exclude-SpecialAccounts
Exclude-OUs

# Sort and remove duplicates from excludedUsers
$script:excludedUsers = $script:excludedUsers | Sort-Object -Unique

# Log excluded accounts
foreach ($excludedUser in $script:excludedUsers) {
    Write-Log -Message "[EXCLUSION] Excluded Account: $excludedUser" -Level "IMPORTANT" -Display $false
}

# Confirm operation
$consent = Read-Host "Do you want to proceed with Mass Password Reset? (Type 'Y' or 'Yes' to continue, any other key to exit)"
if ($consent -notin @('Y', 'Yes')) {
    Write-Log -Message "Operation aborted. No changes were made." -Level "SOS" -Display $true
    Write-Log -Message "Script Completed." -Level "SOS" -Display $true
    exit
}

Function Generate-RandomPassword {
    $PasswordLength = 24 # Adjust within the 8-256 range as needed
    # Define character sets
    $Lowercase = "abcdefghijkmnopqrstuvwxyz"
    $Uppercase = "ABCDEFGHJKLMNOPQRSTUVWXYZ"
    $Numbers = "0123456789"
    $Symbols = '@#$%^&*-_=+[]{}|:,''.?/`~";()<>'

    # Concatenate all characters
    $AllChars = $Lowercase + $Uppercase + $Numbers + $Symbols

    # Ensure the password includes at least one character from each required set
    $Password = [System.Text.StringBuilder]::new()
    $Password.Append($Lowercase[(Get-Random -Maximum $Lowercase.Length)]) | Out-Null
    $Password.Append($Uppercase[(Get-Random -Maximum $Uppercase.Length)]) | Out-Null
    $Password.Append($Numbers[(Get-Random -Maximum $Numbers.Length)]) | Out-Null
    $Password.Append($Symbols[(Get-Random -Maximum $Symbols.Length)]) | Out-Null

    # Fill the rest of the password
    For ($i = $Password.Length; $i -lt $PasswordLength; $i++) {
        $randomChar = $AllChars[(Get-Random -Maximum $AllChars.Length)]
        $Password.Append($randomChar) | Out-Null
    }

    # Convert StringBuilder to string and shuffle
    $PasswordString = $Password.ToString()
    $charArray = $PasswordString.ToCharArray()
    $shuffledArray = $charArray | Get-Random -Count $charArray.Length
    $shuffledPassword = -join $shuffledArray

    return $shuffledPassword
}

# Process all user accounts excluding excluded users
$usersToProcess = Get-ADUser -Filter * -Properties PasswordNeverExpires | Where-Object { $_.DistinguishedName -notin $script:excludedUsers }
$totalUsers = $usersToProcess.Count
$currentCount = 0

foreach ($user in $usersToProcess) {
    $currentCount++
    $newPassword = Generate-RandomPassword
    for ($i = 1; $i -le 2; $i++) {  # Loop to reset password twice
        try {
            Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force)
            if ($i -eq 1) {  
                Set-ADUser -Identity $user -PasswordNeverExpires $false
            }
            Write-Log -Message "[USER] User Update Round $i for $($user.DistinguishedName) completed." -Level "INFO" -Display $false
        } catch {
            Write-Log -Message "Error resetting password for $($user.DistinguishedName) on attempt ${i}: $($_.Exception.Message)" -Level "ERROR" -Display $true
        }
    }
    # Update progress bar for each user processed
    $percentComplete = ($currentCount / $totalUsers) * 100
    $statusMessage = "You now have positive control of $currentCount of $totalUsers Users after two password resets."
    Write-Progress -Activity "Resetting User Passwords" -Status $statusMessage -PercentComplete $percentComplete
}

# Log script complete
Write-Log -Message "Script finished." -Level "SOS"
