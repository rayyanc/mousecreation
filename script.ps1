# CyberPatriot Scripts - Scripts and checklists for use in CyberPatriot.
# Copyright (C) 2022  Adam Thompson-Sharpe
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

<#
    .SYNOPSIS
    Scripts and checklists for use in CyberPatriot.

    .DESCRIPTION
    A script for use on either Windows 10 or Windows Server
    to automatically do some easily-automated tasks.
#>

### Self-elevate ###
if (-not (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator') `
            -or (([Environment]::UserName) -eq "system"))) {
    Start-Process powershell.exe '-ExecutionPolicy', 'Bypass', '-Command', "cd $PWD; . '$PSCommandPath'" -Verb RunAs
    exit
}

# Function taken from https://gitlab.com/MysteryBlokHed/powershell-tools,
# dual-licensed under the Apache 2.0 and MIT licenses
function Get-Prompt {
    <#
        .SYNOPSIS
        Shows a confirmation prompt to the user.

        .DESCRIPTION
        An abstraction for $Host.UI.PromptForChoice to make it much more concise
        to get prompts from the user.

        .PARAMETER Title
        The title of the prompt

        .PARAMETER Prompt
        The prompt to show the user

        .PARAMETER Options
        The options (eg. ('Yes', 'No')).

        .PARAMETER Default
        The default option. Should be an index of the Options array

        .PARAMETER Help
        Help messages to show for each option. Should be the same length as Options

        .PARAMETER StringReturn
        Returns the original options instead of the index.
        More info available in OUTPUTS documentation

        .OUTPUTS
        Returns the index of the user's chosen option by default.
        If -StringReturn is passed, returns the actual string option chosen instead,
        as it was originally passed. For example, if the original option chosen was 'Yes'
        and the user wrote 'y', the return value is 'Yes'.

        .EXAMPLE
        PS> Get-Prompt 'Confirmation' 'Are you sure you want to do that?' 'Yes','No' 0 'Do that','Do not do that'

        Confirmation
        Are you sure you want to do that?
        [Y] Yes  [N] No  [?] Help (default is "Y"): ?
        Y - Do that
        N - Do not do that
        [Y] Yes  [N] No  [?] Help (default is "Y"): Y
        0

        .EXAMPLE
        PS> Get-Prompt 'Confirmation' 'Are you sure you want to do that?' 'Yes','No' 0 'Do that','Do not do that' -StringReturn

        Confirmation
        Are you sure you want to do that?
        [Y] Yes  [N] No  [?] Help (default is "Y"): ?
        Y - Do that
        N - Do not do that
        [Y] Yes  [N] No  [?] Help (default is "Y"): Y
        Yes

        .NOTES
        Written by Adam Thompson-Sharpe.
        Licensed under either of the Apache License, Version 2.0,
        or the MIT license, at your option.

        Source: <https://gitlab.com/MysteryBlokHed/powershell-tools>
    #>

    param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string]$Title,
        [Parameter(Mandatory = $True, Position = 2)]
        [string]$Prompt,
        [Parameter(Mandatory = $True, Position = 3)]
        [string[]]$Options,
        [Parameter(Mandatory = $True, Position = 4)]
        [int]$Default,
        [Parameter(Position = 5)]
        [string[]]$Help,
        [switch]$StringReturn
    )

    if ($Help -and $Options.Length -ne $Help.Length) {
        throw 'Options and Help must be of the same size'
    }

    if ($Default -gt $Options.Length -or $Default -lt 0) {
        throw 'Default exceeds the bounds of the Options array'
    }

    $OptionsChoices = @()

    for ($i = 0; $i -lt $Options.Length; $i++) {
        if (-not $Options[$i].Contains('&')) {
            $Option = "&$($Options[$i])"
        }
        else {
            $Option = $Options[$i]
        }

        if ($Help) {
            $OptionsChoices += New-Object System.Management.Automation.Host.ChoiceDescription $Option, $Help[$i]
        }
        else {
            $OptionsChoices += New-Object System.Management.Automation.Host.ChoiceDescription $Option
        }
    }

    $Response = $Host.UI.PromptForChoice($Title, $Prompt, $OptionsChoices, $Default)

    if ($StringReturn) {
        return $Options[$Response]
    }
    else {
        return $Response
    }
}

# Function taken from https://gitlab.com/MysteryBlokHed/powershell-tools,
# dual-licensed under the Apache 2.0 and MIT licenses
function Get-ReusedVar {
    <#
        .SYNOPSIS
        Prompt the user for a variable while remembering the last value.

        .DESCRIPTION
        Provide a prompt to show to the user as well as the name of the variable to save to.
        If the user provides a value, update the variable.
        If the user provides nothing, use the existing value.
        Be careful not to use the names of variables created inside this function for the -Name parameter.

        .PARAMETER Prompt
        The prompt to show the user.

        .PARAMETER Name
        The name of the variable to check/update.
        The variable with this name is automatically modified based on the user's response.

        .PARAMETER ReturnValue
        Return the variable's value instead of returning nothing.

        .NOTES
        Written by Adam Thompson-Sharpe.
        Licensed under either of the Apache License, Version 2.0,
        or the MIT license, at your option.

        Source: <https://gitlab.com/MysteryBlokHed/powershell-tools>
    #>
    param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string]$Prompt,
        [Parameter(Mandatory = $True, Position = 2)]
        [string]$Name,
        [switch]$ReturnValue
    )

    $Current = Get-Variable $Name -ValueOnly -ErrorAction SilentlyContinue
    if ($Current) {
        $Prompt += " [$Current]"
    }

    while ($True) {
        $Value = Read-Host -Prompt $Prompt

        if ($Value) {
            Set-Variable $Name $Value -Visibility Public -Scope Global
            break
        }
        else {
            if (-not $Current) {
                Write-Output 'A value must be provided!'
            }
            else {
                break
            }
        }
    }

    if ($ReturnValue) { return Get-Variable $Name -ValueOnly }
}

function Get-NormalUsers {
    <#
        .SYNOPSIS
        Get user accounts that are not built into Windows.
    #>

    return (Get-LocalUser).Name | Where-Object { -not ($_ -in $SafeUsers) }
}

function Get-UnsecureString {
    <#
        .SYNOPSIS
        Convert a SecureString to a plaintext string.
    #>
    param(
        [Parameter(Mandatory = $True, Position = 0)]
        [securestring]$SecureString
    )

    return [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
}

Write-Output '
   ______      __
  / ____/_  __/ /_  ___  _____
 / /   / / / / __ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /
\____/\__, /_.___/\___/_/
    _/____/     __       _       __
   / __ \____ _/ /______(_)___  / /_
  / /_/ / __ `/ __/ ___/ / __ \/ __/
 / ____/ /_/ / /_/ /  / / /_/ / /_
/_/    \__,_/\__/_/  /_/\____/\__/

Windows CyberPatriot Script

CyberPatriot Scripts  Copyright (C) 2022  Adam Thompson-Sharpe
Licensed under the GNU General Public License, Version 3.0

Make sure to run this with administrator privileges!'

# Users that probably won't be in the users file provided,
# but that should be allowed on the system
$SafeUsers = ('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')

# Shares available by default
$SafeShares = ('ADMIN$', 'C$', 'IPC$')

### Registry paths ###
$WindowsUpdatePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$AUPath = "$WindowsUpdatePath\AU"
$SystemPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$WinlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$DefenderPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$DefenderRealtimePath = "$DefenderPath\Real-Time Protection"
$DefenderReportingPath = "$DefenderPath\Reporting"
$DefenderScanPath = "$DefenderPath\Scan"
$SecurityCenterPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center'

# Account to disable
$ToDisable = 'Guest'

# Security policy
$PassMin = '7'
$PassMax = '90'
$PassLen = '8'
$LoginAttempts = '10'

$PassExpiryWarn = '7'

$FoundMediaFile = 'media.log'

# Media file extensions
# Mostly from various Wikipedia pages' tables of extensions
# There are probably far more extensions than really necessary here,
# might be worth going through by hand at some point to see what can be removed
$MediaFilesRaw = (
    # Audio formats
    'aa',
    'aac',
    'aax',
    'act',
    'aif',
    'aiff',
    'alac',
    'amr',
    'ape',
    'au',
    'awb',
    'dss',
    'dvf',
    'flac',
    'gsm',
    'iklax',
    'ivs',
    'm4a',
    'm4b',
    'mmf',
    'mp3',
    'mpc',
    'msv',
    'nmf',
    'ogg',
    'oga',
    'mogg',
    'opus',
    'ra',
    'raw',
    'rf64',
    'sln',
    'tta',
    'voc',
    'vox',
    'wav',
    'wma',
    'wv',
    '8svx',
    'cda',
    # Video formats
    'webm',
    'mkv',
    'flv',
    'vob',
    'ogv',
    'ogg',
    'drc',
    'gif',
    'gifv',
    'mng',
    'avi',
    'mts',
    'm2ts',
    'mov',
    'qt',
    'wmv',
    'yuv',
    'rm',
    'rmvb',
    'viv',
    'asf',
    'amv',
    'mp4',
    'm4p',
    'm4v',
    'mpg',
    'mp2',
    'mpeg',
    'mpe',
    'mpv',
    'm2v',
    'svi',
    '3gp',
    '3g2',
    'mxf',
    'roq',
    'nsv',
    'f4v',
    'f4p',
    'f4a',
    'f4b',
    # Picture formats
    'png',
    'jpg',
    'jpeg',
    'jfif',
    'exif',
    'tif',
    'tiff',
    'gif',
    'bmp',
    'ppm',
    'pgm',
    'pbm',
    'pnm',
    'webp',
    'heif',
    'avif',
    'ico',
    'tga',
    'psd',
    'xcf'
)

$MediaFiles = $MediaFilesRaw | ForEach-Object { "*.$_" }

### Regular expressions ###
# Security policy
$PassMaxExp = 'MaximumPasswordAge\s+=\s+\d+'
$PassMinExp = 'MinimumPasswordAge\s+=\s+\d+'
$PassLenExp = 'MinimumPasswordLength\s+=\s+\d+'
$PassComplexExp = 'PasswordComplexity\s+=\s+\d+'
$EnableAdminExp = 'EnableAdminAccount\s+=\s+\d+'
$EnableGuestExp = 'EnableGuestAccount\s+=\s+\d+'
$LoginAttemptsExp = 'LockoutBadCount\s+=\s+\d+'
$ClearPasswordExp = 'ClearTextPassword\s+=\s+\d+'
$LimitBlankExp = 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse\s*=\s*\d+,\d+'
$DisallowPlaintextExp = 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnablePlainTextPassword\s*=\s*\d+,\d+'

$Menu = @{
    # Run updates
    1  = {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            $Response = Get-Prompt 'Updates' 'Third-party PSWindowsUpdate module is not installed. Install to run updates programatically?' 'Yes', 'No' 0 -StringReturn
            if ($Response -eq 'Yes') {
                Install-Module PSWindowsUpdate -Force
            }
        }
    
        # Run check again in case user decided not to install the package
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            Write-Output 'Checking for updates'
            $Updates = Get-WindowsUpdate -AcceptAll
            if ($Updates) {
                Write-Output 'Updates found:' $Updates
                Install-WindowsUpdate -AcceptAll | Out-Null
                Write-Output 'Updates installed'
            }
            else {
                Write-Output 'No updates found'
            }
        }
        else {
            Write-Output 'Skipping updates'
        }
    }

    # Enable automatic updates
    2  = {
        $WUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
        $WUSettings.NotificationLevel = 4
        $WUSettings.save()
        
        # Turn on auto update
        Set-ItemProperty -Path $AUPath -Name 'NoAutoUpdate' -Value 0
        Set-ItemProperty -Path $AUPath -Name 'AUOptions' -Value 4
        Set-ItemProperty -Path $AUPath -Name 'ScheduledInstallDay' -Value 0
        Set-ItemProperty -Path $AUPath -Name 'ScheduledInstallTime' -Value 0
        Set-ItemProperty -Path $AUPath -Name 'AllowMUUpdateService' -Value 1
        Set-ItemProperty -Path $AUPath -Name 'AutomaticMaintenanceEnabled' -Value 1
        # Include other software with updates (NOT feature updates)
        Set-ItemProperty -Path $AUPath -Name 'IncludeRecommendedUpdates' -Value 1
        # Make sure the checks run daily
        Set-ItemProperty -Path $AUPath -Name 'ScheduledInstallEveryWeek' -Value 0
        Set-ItemProperty -Path $AUPath -Name 'ScheduledInstallFirstWeek' -Value 0
        Set-ItemProperty -Path $AUPath -Name 'ScheduledInstallSecondWeek' -Value 0
        Set-ItemProperty -Path $AUPath -Name 'ScheduledInstallThirdWeek' -Value 0
        Set-ItemProperty -Path $AUPath -Name 'ScheduledInstallFourthWeek' -Value 0
        # Enable updates through UI
        Set-ItemProperty -Path $WindowsUpdatePath -Name 'SetDisableUXWUAccess' -Value 0

        Write-Output 'Automatic updates enabled!'
    }

    # Set UAC to highest
    3  = {
        $SystemPolicies = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Set-ItemProperty -Path $SystemPolicies -Name 'ConsentPromptBehaviorAdmin' -Value 2
        Set-ItemProperty -Path $SystemPolicies -Name 'PromptOnSecureDesktop' -Value 1
        Write-Output 'UAC set to highest'
    }

    # Find/remove unauthorized users
    4  = {
        Get-ReusedVar 'Path to list of allowed usernames (normal users and admins)' UsersFile
        $Users = Get-NormalUsers
        $AllowedUsers = Get-Content $UsersFile
        $Unauthorized = @()

        foreach ($User in $Users) {
            if (-not $User) { continue }
            if (-not ($User -in $AllowedUsers)) {
                Write-Output "Unauthorized user: $User"
                $Unauthorized += $User
            }
        }

        if ($Unauthorized) {
            $Response = Get-Prompt 'Unauthorized users' 'Delete found users?' 'Yes', 'No' 0 -StringReturn 'Delete listed users', 'Do nothing'
            if ($Response -eq 'Yes') {
                foreach ($User in $Unauthorized) {
                    Write-Output "Deleting $User"
                    Remove-LocalUser -Name $User
                }
            }
        }

        Write-Output 'Done!'
    }

    # Add missing users
    5  = {
        Get-ReusedVar 'Path to list of allowed usernames (normal users and admins)' UsersFile
        $Users = Get-NormalUsers
        $AllowedUsers = Get-Content $UsersFile

        foreach ($User in $AllowedUsers) {
            if (-not $User) { continue }
            if (-not ($User -in $Users)) {
                Write-Output "Adding missing user $User"
                New-LocalUser $User -NoPassword
            }
        }

        Write-Output 'Added missing users!'
    }

    # Fix administrators
    6  = {
        Get-ReusedVar 'Path to list of administrators' AdminFile
        Get-ReusedVar 'Path to list of normal users' NormalFile
        $Administrators = (Get-LocalGroupMember Administrators).Name | ForEach-Object { $_.Replace("$env:COMPUTERNAME\", '') }

        $Admins = Get-Content $AdminFile
        $Normal = Get-Content $NormalFile

        Write-Output 'Ensuring admins are part of the Administrators group'

        foreach ($User in $Admins) {
            if (-not ($User -in $Administrators)) {
                Write-Output "User $User doesn't have admin perms, fixing"
                Add-LocalGroupMember -Name Administrators -Member $User
            }
        }

        Write-Output 'Ensuring standard users are not part of the Administrators group'

        foreach ($User in $Normal) {
            if ($User -in $Administrators) {
                Write-Output "User $User has admin perms and shouldn't, fixing"
                Remove-LocalGroupMember -Name Administrators -Member $User
            }
        }

        Write-Output 'Done fixing administrators!'
    }

    # Change all passwords
    7  = {
        $Users = Get-NormalUsers
        Write-Output "Changing paswords for the following users:" $Users

        while ($True) {
            $NewPass = Read-Host -Prompt 'New password' -AsSecureString
            $ConfirmNewPass = Read-Host -Prompt 'Confirm' -AsSecureString
            if (-not ((Get-UnsecureString $NewPass) -ceq (Get-UnsecureString $ConfirmNewPass))) {
                Write-Output 'Passwords do not match!'
            }
            else { break }
        }

        foreach ($User in $Users) {
            Write-Output "Changing for $User..."
            Set-LocalUser -Name $User -Password $NewPass
        }

        Write-Output 'Done changing passwords!'
    }

    # Disable/enable user
    8  = {
        $Response = Get-Prompt 'Password Management' 'Enable or disable user?' 'Enable', 'Disable' 1 -StringReturn `
            'Enable the user (username will be entered after)', 'Disable the user (username will be entered after)'
        Get-ReusedVar 'Username' ToDisable

        if ($Response -eq 'Enable') {
            Enable-LocalUser -Name $ToDisable
            Write-Output "User $User has been enabled!"
        }
        else {
            Disable-LocalUser -Name $ToDisable
            Write-Output "User $User has been disabled!"
        }
    }

    # Add new group
    9  = {
        $GroupName = Read-Host -Prompt 'New group to add'
        New-LocalGroup $GroupName

        $Response = Get-Prompt 'Group Management' 'Add members to this group?' 'Yes', 'No' 0 -StringReturn `
            'Add members to the new group', 'Leave the new group empty'
        if ($Response -eq 'Yes') {
            $Users = Read-Host -Prompt 'Users to add (space-separated)'
            $Users = $Users.Split(' ')
            foreach ($User in $Users) {
                Add-LocalGroupMember -Name $GroupName -Member $User
                Write-Output "Added $User to $GroupName"
            }
        }

        Write-Output 'Done creating new group!'
    }

    # Configure remote desktop
    10 = {
        $Response = Get-Prompt 'Remote Desktop' 'Disable or enable remote desktop?' 'Enable', 'Disable' 1 -StringReturn `
            'Allow remote desktop (registry and firewall)', 'Disable remote desktop (registry and firewall)'
        $TerminalServer = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

        if ($Response -eq 'Disable') {
            Set-ItemProperty -Path $TerminalServer -Name 'fDenyTSConnections' -Value 1
            Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'
            Write-Output 'Remote desktop disabled'
        }
        else {
            Set-ItemProperty -Path $TerminalServer -Name 'fDenyTSConnections' -Value 0
            Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
            Write-Output 'Remote desktop enabled'
        }
    }

    # Configure security policy
    11 = {
        $MMC = Get-Process 'mmc' -ErrorAction SilentlyContinue
        if ($MMC) {
            $Response = Get-Prompt 'Security Policy' 'MMC windows (eg. the group policy editor) must be closed before changes can be made. Close them now?' `
                'Yes', 'No' 0 -StringReturn `
                'Close MMC processes', "Don't close and exit"
            if ($Response -eq 'Yes') { $MMC | Stop-Process }
            else { exit }
        }

        # Export current policy
        SecEdit.exe /export /cfg 'cp-secpol.cfg' | Out-Null
        (Get-Item 'cp-secpol.cfg' -Force).Attributes += 'Hidden'
        $Policy = Get-Content -Raw 'cp-secpol.cfg'

        # Ask user how to configure policy
        Get-ReusedVar 'Max password age' PassMax
        Get-ReusedVar 'Minimum password age' PassMin
        Get-ReusedVar 'Minimum password length' PassLen
        $PassComplex = Get-Prompt 'Security Policy' 'Enforce password complexity?' 'Yes', 'No' 0 `
            'Require complex passwords', 'Do not require complex passwords'
        $LockAdmin = Get-Prompt 'Security Policy' 'Lock administrator account?' 'Yes', 'No' 0 `
            'Prevent the use of the Administrator account', 'Allow the Administrator account'
        $LockGuest = Get-Prompt 'Security Policy' 'Lock guest account?' 'Yes', 'No' 0
        Get-ReusedVar 'Max login attempts before lockout' LoginAttempts
        $LimitBlank = Get-Prompt 'Security Policy' 'Prevent remote access with blank passwords?' 'Yes', 'No' 0 `
            'Do not allow users with blank passwords to log in remotely', 'Allow users with blank passwords to log in remotely'
        $DisallowPlaintext = Get-Prompt 'Security Policy' 'Disallow plaintext ("reversible encryption") passwords?' 'Yes', 'No' 0

        if ($PassComplex -eq 0) { $PassComplex = 1 }
        else { $PassComplex = 0 }

        if ($LimitBlank -eq 0) { $LimitBlank = 1 }
        else { $LimitBlank = 0 }

        # $LockAdmin, $LockGuest, and $DisallowPlaintext shouldn't be flipped,
        # since the config option is whether to *enable* them

        # Modify policy
        $Policy = $Policy -replace $PassMaxExp, "MaximumPasswordAge = $PassMax"
        $Policy = $Policy -replace $PassMinExp, "MinimumPasswordAge = $PassMin"
        $Policy = $Policy -replace $PassLenExp, "MinimumPasswordLength = $PassLen"
        $Policy = $Policy -replace $PassComplexExp, "PasswordComplexity = $PassComplex"
        $Policy = $Policy -replace $EnableAdminExp, "EnableAdminAccount = $LockAdmin"
        $Policy = $Policy -replace $EnableGuestExp, "EnableGuestAccount = $LockGuest"
        $Policy = $Policy -replace $LoginAttemptsExp, "LockoutBadCount = $LoginAttempts"
        $Policy = $Policy -replace $LimitBlankExp, "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,$LimitBlank"
        $Policy = $Policy -replace $DisallowPlaintextExp, "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,$DisallowPlaintext"
        $Policy = $Policy -replace $ClearPasswordExp, "ClearTextPassword = $DisallowPlaintext"

        # Write new policy
        $Policy | Out-File -Force 'cp-secpol-new.cfg'
        (Get-Item 'cp-secpol-new.cfg' -Force).Attributes += 'Hidden'
        SecEdit.exe /configure /db 'C:\Windows\security\local.sdb' /cfg 'cp-secpol-new.cfg' /areas SECURITYPOLICY
        Copy-Item -Force 'C:\Windows\security\local.sdb' 'C:\Windows\security\database\secedit.sdb'
        Remove-Item 'cp-secpol.cfg' -Force
        Remove-Item 'cp-secpol-new.cfg' -Force

        Write-Output 'Security policy updated!'
    }

    # List/remove SMB shares
    12 = {
        $Shares = Get-SmbShare | Select-Object -Property Name, Path | Where-Object { -not ($_.Name -in $SafeShares) }
        if ($Shares) {
            Write-Output 'Non-default shares found!'
            foreach ($Share in $Shares) {
                Write-Host "$($Share.Name)`t`t$($Share.Path)"
            }
            $Response = Get-Prompt 'File Shares' 'Remove all found shares?' 'Yes', 'No' 1 -StringReturn `
                'Remove the listed shares', 'Leave the listed shares alone'
            if ($Response -eq 'Yes') {
                foreach ($Share in $Shares) {
                    Remove-SmbShare -Name $Share.Name -Force
                    Write-Output "Removed share $($Share.Name)"
                }
            }
            Write-Output 'Done listing shares!'
        }
        else {
            Write-Output 'No non-default shares found'
        }
    }

    # List services
    13 = {
        $Services = Get-Service
        $Response = Get-Prompt 'Services' 'Only show running services?' 'Yes', 'No' 0 -StringReturn
        if ($Response -eq 'Yes') {
            $Services = $Services | Where-Object { $_.Status -eq 'Running' }
        }
        Write-Output $Services
    }

    # List media files
    14 = {
        Get-ReusedVar 'Output file' FoundMediaFile
        Get-ReusedVar 'Path to search' MediaPath

        Get-ChildItem -Path $MediaPath -Include $MediaFiles -Recurse -File `
        | ForEach-Object { $_.FullName } `
        | Out-File $FoundMediaFile

        Write-Output "Found $((Get-Content $FoundMediaFile).Length) media files!"
    }

    # Configure firewall
    15 = {
        $Response = Get-Prompt 'Windows Firewall' 'Enable or disable firewall?' 'Enable', 'Disable' 0 -StringReturn
        if ($Response -eq 'Enable') {
            Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
            Write-Output 'Firewall enabled'
            $Response = Get-Prompt 'Windows Firewall' 'Configure settings now?' 'Yes', 'No' 0 -StringReturn
            $ToConfigure = Read-Host -Prompt 'Which profiles to configure? (Space-separated list of: Public, Domain, and/or Private)'
            $ToConfigure = $ToConfigure.Split(' ') | Where-Object { $_.ToLower() -in ('Public', 'Domain', 'Private') }
            if ($Response -eq 'Yes') {
                $BlockInbound = Get-Prompt 'Windows Firewall' 'What to do with inbound connections by default?' 'Allow', 'Block' 1 -StringReturn `
                    'Block external connections by default', 'Allow external connections by default'
                $BlockOutbound = Get-Prompt 'Windows Firewall' 'What to do with outbound connections by default?' 'Allow', 'Block' 0 -StringReturn
                $LogAllowed = Get-Prompt 'Windows Firewall' 'Log allowed connections?' 'True', 'False' 1 -StringReturn
                $LogBlocked = Get-Prompt 'Windows Firewall' 'Log blocked connections?' 'True', 'False' 0 -StringReturn

                Set-NetFirewallProfile -Profile $ToConfigure -DefaultInboundAction $BlockInbound
                Set-NetFirewallProfile -Profile $ToConfigure -DefaultOutboundAction $BlockOutbound
                Set-NetFirewallProfile -Profile $ToConfigure -LogAllowed $LogAllowed
                Set-NetFirewallProfile -Profile $ToConfigure -LogBlocked $LogBlocked
            }
        }
        else {
            Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
            Write-Output 'Firewall disabled'
        }

        Write-Output 'Done configuring firewall!'
    }

    # Configure interactive logon policies
    16 = {
        $RequireCAD = Get-Prompt 'Interactive Logon' 'Require Ctrl+Alt+Delete for logon?' 'Yes', 'No' 0 `
            'Require Ctrl+Alt+Delete to be pressed before a user can log on', 'Do not require Ctrl+Alt+Delete'
        $DisplayUsernameLogon = Get-Prompt 'Interactive Logon' 'Display username at logon?' 'Yes', 'No' 1 `
            'Display the username at logon', 'Require the username to be typed at logon'
        $DisplayUsernameLocked = Get-Prompt 'Interactive Logon' 'Display username when locked?' 'Yes', 'No' 1
        'Display the username when the system is locked', 'Require the username to be typed when the system is locked'
        Get-ReusedVar 'Days to warn user before password expiry (0 to disable)' PassExpiryWarn

        if ($DisplayUsernameLocked -eq 0) { $DisplayUsernameLocked = 1 }
        else { $DisplayUsernameLocked = 3 }

        Set-ItemProperty -Path $SystemPath -Name 'DisableCAD' -Value $RequireCAD
        Set-ItemProperty -Path $SystemPath -Name 'DontDisplayLastUserName' -Value $DisplayUsernameLogon
        Set-ItemProperty -Path $SystemPath -Name 'DontDisplayLockedUserId' -Value $DisplayUsernameLocked
        Set-ItemProperty -Path $WinlogonPath -Name 'PasswordExpiryWarning' -Value $PassExpiryWarn

        Write-Output 'Done configuring interactive logon policies!'
    }

    # Configure Windows Defender
    17 = {
        $Response = Get-Prompt 'Windows Defender' 'Enable Windows Defender?' 'Yes', 'No' 0 -StringReturn
        if ($Response -eq 'Yes') {
            Set-ItemProperty -Path $DefenderPath -Name 'DisableAntiSpyware' -Value 0

            $ConfigureGeneral = Get-Prompt 'Windows Defender' 'Configure general settings?' 'Yes', 'No' 0 -StringReturn
            if ($ConfigureGeneral -eq 'Yes') {
                # Create registry folders if they don't exist
                New-Item -Path $DefenderRealtimePath -Force
                New-Item -Path $DefenderReportingPath -Force
                New-Item -Path $DefenderScanPath -Force

                # Ask for preferences
                $RoutineRemediation = Get-Prompt 'Windows Defender' 'Routinely take action on threats?' 'Yes', 'No' 0
                $KeepAlive = Get-Prompt 'Windows Defender' 'Keep the Defender service alive at all times?' 'Yes', 'No' 0
                $PUA = Get-Prompt 'Windows Defender' 'Detect potentially unwanted programs?' 'Yes', 'No' 0
                $Behavioral = Get-Prompt 'Windows Defender' 'Enable behaviour monitoring?' 'Yes', 'No' 0
                $IOAV = Get-Prompt 'Windows Defender' 'Scan all downloads and attachments?' 'Yes', 'No' 0
                $MonitorFiles = Get-Prompt 'Windows Defender' 'Monitor file activity?' 'Yes', 'No' 0
                $NotifyRawVolume = Get-Prompt 'Windows Defender' 'Notify about raw writes to disk?' 'Yes', 'No' 0
                $Realtime = Get-Prompt 'Windows Defender' 'Enable realtime protection?' 'Yes', 'No' 0
                $ProcessScanning = Get-Prompt 'Windows Defender' 'Enable process scanning (requires realtime protection)?' 'Yes', 'No' 0
                $EnhancedNotifications = Get-Prompt 'Windows Defender' 'Enable enhanced notifications?' 'Yes', 'No' 0
                $AllowPause = Get-Prompt 'Windows Defender' 'Allow users to pause scans?' 'Yes', 'No' 1
                $UpdateBeforeScan = Get-Prompt 'Windows Defender' 'Update definitions before a scan?' 'Yes', 'No' 0
                $Heuristics = Get-Prompt 'Windows Defender' 'Enable heuristics?' 'Yes', 'No' 0

                # Flip values to match what the registry keys configure
                # (Some are whether to disable, others are whether to enable)
                If ($KeepAlive -eq 0) { $KeepAlive = 1 }
                else { $KeepAlive = 0 }

                if ($PUA -eq 0) { $PUA = 1 }
                else { $PUA = 0 }

                if ($UpdateBeforeScan -eq 0) { $UpdateBeforeScan = 1 }
                else { $UpdateBeforeScan = 0 }

                # Apply settings
                Set-ItemProperty -Path $DefenderPath -Name 'DisableRoutinelyTakingAction' -Value $RoutineRemediation
                Set-ItemProperty -Path $DefenderPath -Name 'ServiceKeepAlive' -Value $KeepAlive
                Set-ItemProperty -Path $DefenderPath -Name 'PUAProtection' -Value $PUA
                Set-ItemProperty -Path $DefenderRealtimePath -Name 'DisableBehaviorMonitoring' -Value $Behavioral
                Set-ItemProperty -Path $DefenderRealtimePath -Name 'DisableIOAVProtection' -Value $IOAV
                Set-ItemProperty -Path $DefenderRealtimePath -Name 'DisableOnAccessProtection' -Value $MonitorFiles
                Set-ItemProperty -Path $DefenderRealtimePath -Name 'DisableRawWriteNotification' -Value $NotifyRawVolume
                Set-ItemProperty -Path $DefenderRealtimePath -Name 'DisableRealtimeMonitoring' -Value $Realtime
                Set-ItemProperty -Path $DefenderRealtimePath -Name 'DisableScanOnRealtimeEnable' -Value $ProcessScanning
                Set-ItemProperty -Path $DefenderReportingPath -Name 'DisableEnhancedNotifications' -Value $EnhancedNotifications
                Set-ItemProperty -Path $DefenderScanPath -Name 'AllowPause' -Value $AllowPause
                Set-ItemProperty -Path $DefenderScanPath -Name 'CheckForSignaturesBeforeRunningScan' -Value $UpdateBeforeScan
                Set-ItemProperty -Path $DefenderScanPath -Name 'DisableHeuristics' -Value $Heuristics
            }

            $ConfigureSecurityCenter = Get-Prompt 'Windows Defender' 'Configure Security Center settings?' 'Yes', 'No' 0 -StringReturn
            if ($ConfigureSecurityCenter -eq 'Yes') {
                New-Item -Path $SecurityCenterPath -Force
                New-Item -Path "$SecurityCenterPath\Virus and threat protection" -Force
                New-Item -Path "$SecurityCenterPath\Firewall and network protection" -Force
                New-Item -Path "$SecurityCenterPath\App and Browser protection" -Force
                New-Item -Path "$SecurityCenterPath\Device performance and health" -Force
                New-Item -Path "$SecurityCenterPath\Account protection" -Force
                New-Item -Path "$SecurityCenterPath\Device security" -Force
                New-Item -Path "$SecurityCenterPath\Systray" -Force

                $HideVirusArea = Get-Prompt 'Windows Defender' 'Hide the virus and threat protection area?' 'Yes', 'No' 1
                $HideRansomArea = Get-Prompt 'Windows Defender' 'Hide the ransomware recovery area?' 'Yes', 'No' 1
                $HideFirewallArea = Get-Prompt 'Windows Defender' 'Hide the firewall and network protection area?' 'Yes', 'No' 1
                $HideAppBrowserArea = Get-Prompt 'Windows Defender' 'Hide the app and browser protection area?' 'Yes', 'No' 1
                $HidePerformanceArea = Get-Prompt 'Windows Defender' 'Hide the device performance and health area?' 'Yes', 'No' 1
                $HideAccountArea = Get-Prompt 'Windows Defender' 'Hide the account protection area?' 'Yes', 'No' 1
                $HideDeviceArea = Get-Prompt 'Windows Defender' 'Hide the device security area?' 'Yes', 'No' 1
                $HideSecureBootArea = Get-Prompt 'Windows Defender' 'Hide the secure boot area?' 'Yes', 'No' 1
                $NoUserModifySettings = Get-Prompt 'Windows Defender' 'Prevent users from modifying settings?' 'Yes', 'No' 0
                $HideSystray = Get-Prompt 'Windows Defender' 'Hide the system tray icon?' 'Yes', 'No' 1

                # Flip values to match what the registry keys configure
                if ($HideVirusArea -eq 0) { $HideVirusArea = 1 }
                else { $HideVirusArea = 0 }

                if ($HideRansomArea -eq 0) { $HideRansomArea = 1 }
                else { $HideRansomArea = 0 }

                if ($HideFirewallArea -eq 0) { $HideFirewallArea = 1 }
                else { $HideFirewallArea = 0 }

                if ($HideAppBrowserArea -eq 0) { $HideAppBrowserArea = 1 }
                else { $HideAppBrowserArea = 0 }

                if ($HidePerformanceArea -eq 0) { $HidePerformanceArea = 1 }
                else { $HidePerformanceArea = 0 }

                if ($HideAccountArea -eq 0) { $HideAccountArea = 1 }
                else { $HideAccountArea = 0 }

                if ($HideDeviceArea -eq 0) { $HideDeviceArea = 1 }
                else { $HideDeviceArea = 0 }

                if ($HideSecureBootArea -eq 0) { $HideSecureBootArea = 1 }
                else { $HideSecureBootArea = 0 }

                if ($NoUserModifySettings -eq 0) { $NoUserModifySettings = 1 }
                else { $NoUserModifySettings = 0 }

                if ($HideSystray -eq 0) { $HideSystray = 1 }
                else { $HideSystray = 0 }

                Set-ItemProperty -Path "$SecurityCenterPath\Virus and threat protection" -Name 'UILockdown' -Value $HideVirusArea
                Set-ItemProperty -Path "$SecurityCenterPath\Virus and threat protection" -Name 'HideRansomwareRecovery' -Value $HideRansomArea
                Set-ItemProperty -Path "$SecurityCenterPath\Firewall and network protection" -Name 'UILockdown' -Value $HideFirewallArea
                Set-ItemProperty -Path "$SecurityCenterPath\App and Browser protection" -Name 'UILockdown' -Value $HideAppBrowserArea
                Set-ItemProperty -Path "$SecurityCenterPath\Device performance and health" -Name 'UILockdown' -Value $HidePerformanceArea
                Set-ItemProperty -Path "$SecurityCenterPath\Account protection" -Name 'UILockdown' -Value $HideAccountArea
                Set-ItemProperty -Path "$SecurityCenterPath\Device security" -Name 'UILockdown' -Value $HideDeviceArea
                Set-ItemProperty -Path "$SecurityCenterPath\Device security" -Name 'HideSecureBoot' -Value $HideSecureBootArea
                Set-ItemProperty -Path "$SecurityCenterPath\App and Browser protection" -Name 'DisallowExploitProtectionOverride' -Value $NoUserModifySettings
                Set-ItemProperty -Path "$SecurityCenterPath\Systray" -Name 'HideSystray' -Value $HideSystray
            }

            Start-Service WinDefend
            Start-Service WdNisSvc

            Write-Output 'Done configuring Windows Defender!'
        }
        else {
            Set-ItemProperty -Path $DefenderPath -Name 'DisableAntiSpyware' -Value 1
        }
    }

    # Filter scheduled tasks
    18 = {
        $TimeInterval = Read-Host 'Time interval (ie. 1H for one hour, 5M for five minutes)'
        $TimeInterval = "PT$TimeInterval"

        $Tasks = Get-ScheduledTask | Where-Object { $_.Triggers }
        foreach ($Task in $Tasks) {
            foreach ($Trigger in $Task.Triggers) {
                if ($Trigger.RandomDelay -eq $TimeInterval -or $Trigger.Repetition.Interval -eq $TimeInterval) {
                    Write-Output $Task
                }
            }
        }

        Write-Output 'Done filtering tasks!'
    }

    # Exit script
    99 = {
        Write-Output 'Good luck and happy hacking!'
        exit
    }
}

function Show-Menu {
    Write-Output '
 1) Run updates                         10) Configure remote desktop
 2) Enable automatic updates            11) Configure security policy
 3) Set UAC to highest                  12) List/remove SMB shares
 4) Find/remove unauthorized users      13) List services
 5) Add missing users                   14) List media files
 6) Fix administrators                  15) Configure firewall
 7) Change all passwords                16) Configure interactive logon policies
 8) Enable/disable user                 17) Configure Windows Defender
 9) Add new group                       18) Filter scheduled tasks

99) Exit script'

    $Option = [int](Read-Host 'Option')

    if ($Menu[$Option]) { . $Menu[$Option] }
    else { Write-Output "Unknown option $Option" }
}

while ($True) { Show-Menu }