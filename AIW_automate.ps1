Write-Host ' Checking if winget is installed' -F darkgray -B darkgreen
Start-Sleep -Seconds 2
# Verify if winget is intalled an if is not, open msstore to install it
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Start-Process ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1

    function IsAppInstalled {
    $app = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers
    return [bool]$app
}

do {
    Write-Host "Waiting for Winget to be installed..."
    Start-Sleep -Seconds 10
} until (IsAppInstalled)
    
} else {
    Write-Host "winget is installed on this system."
}
Start-Sleep -Seconds 4

# Windows optimization, stop an disable unnecesary services
Write-Host ' Starting windows optimization' -F darkgray -B darkgreen
Start-Sleep -Seconds 2
<#
Here we stop the services that slow down the pc and makes the hard drive go to 100% continuously
#>
Stop-Service 'SysMain' -Force
Stop-Service 'WSearch' -Force
Stop-Service 'DiagTrack' -Force
Stop-Service 'dmwappushservice' -Force
Stop-Service 'MapsBroker' -Force
Stop-Service 'RemoteRegistry' -Force
Stop-Service 'BDESVC' -Force
<#
Here we check if the services are stopped and display a message to the user
#>
$services = @(
        "SysMain"
        "WSearch"
        "DiagTrack"
        "dmwappushservice"
        "MapsBroker"
        "RemoteRegistry"
        "BDESVC"
)

# Loop through and show the services status
foreach ($service in $services) {

$trap = get-service -Name $service
if ($trap.status -ne "Running")
{

    Write-Host "The service " $trap.name " is not running "
}

if ($trap.status -eq "Running")
{

    Write-Host "The service " $trap.name " is not running "
}
Start-Sleep -Seconds 2


}

<#
Here we disable the services that slow down the pc and makes the hard drive go to 100% continuously
#>
Set-Service -Name "SysMain" -StartupType disabled
Set-Service -Name "WSearch" -StartupType disabled
Set-Service -Name "DiagTrack" -StartupType disabled
Set-Service -Name "dmwappushservice" -StartupType disabled
Set-Service -Name "MapsBroker" -StartupType disabled
Set-Service -Name "RemoteRegistry" -StartupType disabled
Set-Service -Name "BDESVC" -StartupType disabled
Start-Sleep -Seconds 2
<#
Here we check the services StartType and show it to the user
#>
$states = @(
        "SysMain"
        "WSearch"
        "DiagTrack"
        "dmwappushservice"
        "MapsBroker"
        "RemoteRegistry"
        "BDESVC"
)

# Loop through and show the services start type
foreach ($state in $states) {

$trap = get-service -Name $state
if ($trap.StartType -eq "Automatic")
{

    Write-Host "The service " $trap.name " Start Type is automatic "
}

if ($trap.StartType -eq "Manual")
{

    Write-Host "The service " $trap.name " Start Type is Manual "
}
Start-Sleep -Seconds 2

if ($trap.StartType -eq "Disabled")
{

    Write-Host "The service " $trap.name " Start Type is disabled "
}
Start-Sleep -Seconds 1


}
Start-Sleep -Seconds 2

<#
We are creating a firewall rule to allow ICMP
#>
Write-Host ' Creating a firewall rule to allow ICMP traffic (Ping) ' -F darkgray -B darkgreen
Start-Sleep -Seconds 2
netsh advfirewall firewall add rule name="Ping" protocol="icmpv4:8,any" dir=in action=allow
<#
(for notebooks) Here we are creating a registry to inform if webcam is on
#>
Write-Host ' Turn On Webcam On/Off OSD Notifications ' -F darkgray -B darkgreen
Start-Sleep -Seconds 2
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\OEM\Device\Capture' -Name 'NoPhysicalCameraLED' -Value '00000001'
Start-Sleep -Seconds 2
$wshell = New-Object -ComObject Wscript.Shell
$message = "Select the option:" + [Environment]::NewLine + "Adjust for better performance" + [Environment]::NewLine + " and then press [Apply] and [OK]"
$wshell.Popup($message, 0, "Performance Options", 0x1)
start C:\Windows\System32\SystemPropertiesPerformance.exe

# Installing base software (web browswers, pdf readers, etc...)
Write-Host ' Starting windows optimization' -F darkgray -B darkgreen
Start-Sleep -Seconds 2
winget install Mozilla.Firefox -h --accept-package-agreements --accept-source-agreements
winget install Google.Chrome -h --accept-package-agreements --accept-source-agreements
winget install Adobe.Acrobat.Reader.64-bit -h --accept-package-agreements --accept-source-agreements
winget install 7zip.7zip -h --accept-package-agreements --accept-source-agreements
winget install RARLab.WinRAR -h --accept-package-agreements --accept-source-agreements
winget install RustDesk.RustDesk -h --accept-package-agreements --accept-source-agreements
winget install GlavSoft.TightVNC -h --accept-package-agreements --accept-source-agreements
winget install Microsoft.DotNet.Framework.DeveloperPack_4 -h --accept-package-agreements --accept-source-agreements
winget install 9WZDNCRDFWX0 -h --accept-package-agreements --accept-source-agreements
winget install Microsoft.VCRedist.2005.x64 -h --accept-package-agreements --accept-source-agreements
winget install Microsoft.VCRedist.2008.x64 -h --accept-package-agreements --accept-source-agreements
winget install Microsoft.VCRedist.2010.x64 -h --accept-package-agreements --accept-source-agreements
winget install Microsoft.VCRedist.2012.x64 -h --accept-package-agreements --accept-source-agreements
winget install Microsoft.VCRedist.2013.x64 -h --accept-package-agreements --accept-source-agreements
winget install Microsoft.VCRedist.2015+.x64 -h --accept-package-agreements --accept-source-agreements
Dism /online /Enable-Feature /FeatureName:"NetFx3"

# Removing bloatware
Write-Host ' uninstalling bloatware' -F darkgray -B darkgreen
Start-Sleep -Seconds 2
$packages = @(
		"Microsoft.3DBuilder",
		"Microsoft.BingNews"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.OneNote"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.RemoteDesktop"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Office.Todo.List"
		"Microsoft.Wallet",
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.YourPhone",
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*Minecraft*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Spotify*"
        "*LinkedIn*"
)

# Loop through and uninstall each package
foreach ($package in $packages) {
    Write-Host "Attempting to uninstall $package"
    $app = Get-AppxPackage -Name $package -ErrorAction SilentlyContinue
    if ($app -ne $null) {
        # Uninstall the app
        $app | Remove-AppxPackage
        Write-Host "$package uninstalled"
    } else {
        Write-Host "$package is not installed"
    }
}