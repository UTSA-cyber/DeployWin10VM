# Title:        Windows 10 Deployment Script
# Author:       Jacob Stauffer, CISSP
# Description:  Deployment script for Boxstarter and removing bloatware
# Last Update:  2020-01-20
#
# Usage:        . { Invoke-WebRequest -useb THISRAWSCRIPT } | Invoke-Expression; Deploy-NewWindows10 -installPkg YOURSOFTWARESCRIPT

function Deploy-NewWindows10() {
    Param (
        [string]$installPkg=""
    )
    Start-Transcript

    # Set environment to run this script
    Set-ExecutionPolicy Unrestricted

    # Change power settings
    powercfg /change monitor-timeout-ac 0
    powercfg /change standby-timeout-ac 0

    # Check to make sure script is run as administrator
    Write-Host "[+] Checking if script is running as administrator.." -ForegroundColor Green
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[-] Please run this script as administrator`n" -ForegroundColor Red
        Read-Host  "Press any key to continue"
        exit
    }

    Write-Host "[+] Installing boxstarter" -ForegroundColor Green
    $rc = Install-BoxStarter
    if ( -Not $rc ) {
        Write-Host "[-] Failed to install BoxStarter" -ForegroundColor Red
        Read-Host  "Press any key to continue..."
        exit
    }

    Write-Host "[+] Removing bloatware" -ForegroundColor Green
    $rbw = Remove-Bloatware
    if ( -Not $rbw ) {
        Write-Host "[-] Failed to remove bloatware" -ForegroundColor Red
    }

    Write-Host "[+] Configuring Windows" -ForegroundColor Green
    $rbw = Install-WindowsSettings
    if ( -Not $rbw ) {
        Write-Host "[-] Failed to configure windows 10" -ForegroundColor Red
    }

    Write-Host "[+] Installing required software" -ForegroundColor Green
    if ($installPkg) {
        $rbw = Install-RequiredSoftware
        if ( -Not $rbw ) {
            Write-Host "[-] Failed to install your software" -ForegroundColor Red
        }
    }

    # Setting up user profile
    Remove-Item "$env:PUBLIC\Desktop\Boxstarter Shell.lnk"
    Remove-Item "$env:USERPROFILE\Desktop\Microsoft Edge.lnk"

    # Restore UAC and updater settings
    Enable-UAC
    Enable-MicrosoftUpdate
    Install-WindowsUpdate -acceptEula

    # End
    Clear-Host
    Write-Host "[+] Configuration and installation complete" -ForegroundColor Green
    Stop-Transcript
}


function Install-BoxStarter() {
    # Try to install BoxStarter as is first, then fall back to be over trusing only if this step fails.
    try {
        iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
        return $true
    } catch {
        Write-Host "[!] Could not install boxstarter without trust, escalating privileges" -ForegroundColor Yellow
    }

    # https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
    # Allows current PowerShell session to trust all certificates
    # Also a good find: https://www.briantist.com/errors/could-not-establish-trust-relationship-for-the-ssltls-secure-channel/
    try {
        Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    } catch {
        Write-Host "[!] Failed to add new type" -ForegroundColor Yellow
    }
    try {
        $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    } catch {
        Write-Host "[!] Failed to find SSL type...1" -ForegroundColor Yellow
    }
    try {
        $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls'
    } catch {
        Write-Host "[!] Failed to find SSL type...2" -ForegroundColor Yellow
    }
    $prevSecProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $prevCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy

    # Become overly trusting
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    # download and instal boxstarter
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
    # Restore previous trust settings for this PowerShell session
    # Note: SSL certs trusted from installing BoxStarter above will be trusted for the remaining PS session
    [System.Net.ServicePointManager]::SecurityProtocol = $prevSecProtocol
    [System.Net.ServicePointManager]::CertificatePolicy = $prevCertPolicy
    return $true
}

function Install-RequiredSoftware() {
    try {
        . { Invoke-WebRequest -useb $installPkg } | Invoke-Expression
        return $true
    } catch {
        Write-Host "[-] Could not install your software" -ForegroundColor Red
    }

}

function Install-WindowsSettings() {
    try {
        Disable-BingSearch
        Disable-GameBarTips
        
        Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions
        Set-TaskbarOptions -Size Small -Dock Bottom -Combine Full -Lock
        Set-TaskbarOptions -Size Small -Dock Bottom -Combine Full -AlwaysShowIconsOn
    
        # Some from: @NickCraver's gist https://gist.github.com/NickCraver/7ebf9efbfd0c3eab72e9
        # Privacy: Let apps use my advertising ID: Disable
        If (-Not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
            New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo | Out-Null
        }
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0
    
        # WiFi Sense: HotSpot Sharing: Disable
        If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
            New-Item -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting | Out-Null
        }
        Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0
    
        # WiFi Sense: Shared HotSpot Auto-Connect: Disable
        Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0
    
        # Start Menu: Disable Bing Search Results
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
        # To Restore (Enabled):
        # Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 1
    
        # Disable Telemetry (requires a reboot to take effect)
        # Note this may break Insider builds for your organization
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
        Get-Service DiagTrack,Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled
    
        # Change Explorer home screen back to "This PC"
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
        # Change it back to "Quick Access" (Windows 10 default)
        # Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2
    
        # Better File Explorer
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1		
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1		
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name MMTaskbarMode -Value 2
    
        # These make "Quick Access" behave much closer to the old "Favorites"
        # Disable Quick Access: Recent Files
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0
        # Disable Quick Access: Frequent Folders
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 0
        # To Restore:
        # Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 1
        # Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 1
    
        # Disable the Lock Screen (the one before password prompt - to prevent dropping the first character)
        If (-Not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization)) {
            New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name Personalization | Out-Null
        }
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1
        # To Restore:
        # Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1
    
        # Lock screen (not sleep) on lid close
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name AwayModeEnabled -Type DWord -Value 1
        # To Restore:
        # Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name AwayModeEnabled -Type DWord -Value 0
    
        # These make "Quick Access" behave much closer to the old "Favorites"
        # Disable Quick Access: Recent Files
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0
        # Disable Quick Access: Frequent Folders
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 0
        # To Restore:
        #Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 1
        #Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 1

        # Use the Windows 7-8.1 Style Volume Mixer
        If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name MTCUVC | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name EnableMtcUvc -Type DWord -Value 0
        # To Restore (Windows 10 Style Volume Control):
        # Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name EnableMtcUvc -Type DWord -Value 1
    
        # Disable Xbox Gamebar
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWord -Value 0
    
        # Turn off People in Taskbar
        If (-Not (Test-Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
            New-Item -Path HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People | Out-Null
        }
        Set-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name PeopleBand -Type DWord -Value 0
        return $true
    } catch {
        Write-Host "[-] Could not configure windows 10 properly" -ForegroundColor Red
    }
}

function Remove-Bloatware() {
    try {
        # 3D Builder
        Get-AppxPackage Microsoft.3DBuilder | Remove-AppxPackage
        # 3D Viewer
        Get-AppxPackage Microsoft.Microsoft3DViewer | Remove-AppxPackage
        # Alarms
        Get-AppxPackage Microsoft.WindowsAlarms | Remove-AppxPackage
        # Autodesk
        Get-AppxPackage *Autodesk* | Remove-AppxPackage
        # Bing Weather, News, Sports, and Finance (Money):
        Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage
        Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage
        Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage
        Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage
        # BubbleWitch
        Get-AppxPackage *BubbleWitch* | Remove-AppxPackage
        # Candy Crush
        Get-AppxPackage king.com.CandyCrush* | Remove-AppxPackage
        # Comms Phone
        Get-AppxPackage Microsoft.CommsPhone | Remove-AppxPackage
        # Dell
        Get-AppxPackage *Dell* | Remove-AppxPackage
        # Dropbox
        Get-AppxPackage *Dropbox* | Remove-AppxPackage
        # Facebook
        Get-AppxPackage *Facebook* | Remove-AppxPackage
        # Feedback Hub
        Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage
        # Get Started
        Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage
        # Keeper
        Get-AppxPackage *Keeper* | Remove-AppxPackage
        # Mail & Calendar
        Get-AppxPackage microsoft.windowscommunicationsapps | Remove-AppxPackage
        # Maps
        Get-AppxPackage Microsoft.WindowsMaps | Remove-AppxPackage
        # March of Empires
        Get-AppxPackage *MarchofEmpires* | Remove-AppxPackage
        # McAfee Security
        Get-AppxPackage *McAfee* | Remove-AppxPackage
        # Uninstall McAfee Security App
        $mcafee = gci "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | foreach { gp $_.PSPath } | ? { $_ -match "McAfee Security" } | select UninstallString
        if ($mcafee) {
            $mcafee = $mcafee.UninstallString -Replace "C:\Program Files\McAfee\MSC\mcuihost.exe",""
            Write "Uninstalling McAfee..."
            start-process "C:\Program Files\McAfee\MSC\mcuihost.exe" -arg "$mcafee" -Wait
        }
        # Messaging
        Get-AppxPackage Microsoft.Messaging | Remove-AppxPackage
        # Minecraft
        Get-AppxPackage *Minecraft* | Remove-AppxPackage
        # Netflix
        Get-AppxPackage *Netflix* | Remove-AppxPackage
        # Office Hub
        Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage
        # One Connect
        Get-AppxPackage Microsoft.OneConnect | Remove-AppxPackage
        # OneNote
        Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage
        # People
        Get-AppxPackage Microsoft.People | Remove-AppxPackage
        # Phone
        Get-AppxPackage Microsoft.WindowsPhone | Remove-AppxPackage
        # Photos
        Get-AppxPackage Microsoft.Windows.Photos | Remove-AppxPackage
        # Print3D
        Get-AppxPackage Microsoft.Print3D | Remove-AppxPackage
        # Plex
        Get-AppxPackage *Plex* | Remove-AppxPackage
        # Skype (Metro version)
        Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage
        # Sound Recorder
        Get-AppxPackage Microsoft.WindowsSoundRecorder | Remove-AppxPackage
        # Solitaire
        Get-AppxPackage *Solitaire* | Remove-AppxPackage
        # Sticky Notes
        Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage
        # Sway
        Get-AppxPackage Microsoft.Office.Sway | Remove-AppxPackage
        # Twitter
        Get-AppxPackage *Twitter* | Remove-AppxPackage
        # Xbox
        Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
        Get-AppxPackage Microsoft.XboxGameOverlay | Remove-AppxPackage
        Get-AppxPackage Microsoft.XboxIdentityProvider | Remove-AppxPackage
        Get-AppxPackage Microsoft.XboxSpeechToTextOverlay | Remove-AppxPackage
        # Your Phone
        Get-AppxPackage Microsoft.YourPhone | Remove-AppxPackage
        # Zune Music, Movies & TV
        Get-AppxPackage Microsoft.ZuneMusic | Remove-AppxPackage
        Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage
        return $true
    } catch {
        Write-Host "[-] Could not remove bloatware." -ForegroundColor Red
    }
}



