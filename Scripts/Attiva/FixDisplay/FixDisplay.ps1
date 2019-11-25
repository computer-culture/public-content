"Running Graphics Fix"
""
"Gathering diagnostic information..."

$Now = Get-Date

$OutputLocation = "C:\ProgramData\Attiva\Output\"
$OutputFileName = "FixDisplay-" + 
    $Now.Year + "-" + $Now.Month + "-" + $Now.Day + "-" +
    $Now.Hour + "-" + $Now.Minute + "-" + $Now.Second + ".txt"
    
$OutputFilePath = $OutputLocation + $OutputFileName
    
if (!(Test-Path $OutputLocation))
{
    New-Item -ItemType Directory -Path $OutputLocation
}

# Get user details

$UserDetails = "Computer Name: " + $env:COMPUTERNAME + ", User Name: " + $env:USERNAME
$UserDetails | Out-File $OutputFilePath -Append

# Get OS details

$OSVersion = Get-WmiObject -Class win32_OperatingSystem | Select-Object Version
$OSReleaseId = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId

$OSDetails = "Windows Release: $OSReleaseId, Windows Version: $OSVersion"

$OSDetails | Out-File $OutputFilePath -Append
  
# Get Display Information
    
$GraphicsAdaptors = Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.DeviceClass -eq "DISPLAY"} | Select-Object DeviceName, DriverVersion, DriverDate
$GraphicsAdaptors | Out-File $OutputFilePath -Append
    
# Get Running Processes
    
$RunningProcesses = Get-Process
$RunningApps = $RunningProcesses | Where-Object {$_.MainWindowTitle} | Select-Object Name, MainWindowTitle
$RunningApps | Out-File $OutputFilePath -Append

"Reloading graphics adaptor...screens will go blank momentarily"

Start-Sleep 2

# Press keys to reload graphics driver

$source = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Windows.Forms;
namespace KeyboardSend
{
    public class KeyboardSend
    {
        [DllImport("user32.dll")]
        public static extern void keybd_event(byte bVk, byte bScan, int dwFlags, int dwExtraInfo);
        private const int KEYEVENTF_EXTENDEDKEY = 1;
        private const int KEYEVENTF_KEYUP = 2;
        public static void KeyDown(Keys vKey)
        {
            keybd_event((byte)vKey, 0, KEYEVENTF_EXTENDEDKEY, 0);
        }
        public static void KeyUp(Keys vKey)
        {
            keybd_event((byte)vKey, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
       }
   }
}
"@

if ("KeyboardSend.KeyboardSend" -as [type]) {
	# ClassName is already loaded
}
else {
    Add-Type -TypeDefinition $source -ReferencedAssemblies "System.Windows.Forms"
}

Function Win($Key, $Key2, $Key3)
{
    [KeyboardSend.KeyboardSend]::KeyDown("LWin")
    [KeyboardSend.KeyboardSend]::KeyDown("$Key")
    [KeyboardSend.KeyboardSend]::KeyDown("$Key2")
    [KeyboardSend.KeyboardSend]::KeyDown("$Key3")
    [KeyboardSend.KeyboardSend]::KeyUp("LWin")
    [KeyboardSend.KeyboardSend]::KeyUp("$Key")
    [KeyboardSend.KeyboardSend]::KeyUp("$Key2")
    [KeyboardSend.KeyboardSend]::KeyUp("$Key3")
}
Win 163 161 66

# 163 = ctrl key
# 161 = shift key
# 66 = b key

   