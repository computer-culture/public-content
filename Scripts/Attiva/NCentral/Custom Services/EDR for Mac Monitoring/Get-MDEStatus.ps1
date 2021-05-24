<#

This script checks the status of Microsoft Defender for Endpoint (MDE) on a Mac, and outputs key information to a text file which can be read by other applications such as N-central

It reads status information from the mdatp utility.

#>

""
"Checking MDE Status..."
""

$AttivaDataPath = "/var/Attiva/"
$MDEStatusOutputFile = $AttivaDataPath + "mde-status.txt"

if (!(Test-Path $AttivaDataPath))
{
    "Output directory does not exist, creating it."
    sudo mkdir $AttivaDataPath
    sudo chmod -R 777 /var/Attiva/
}

if (!(Test-Path /usr/local/bin/mdatp))
{
    "MS Defender for Endpoint status utility (/usr/local/bin/mdatp) not found, cannot proceed."
    "ERROR: /usr/local/bin/mdatp does not exist" | Out-File $MDEStatusOutputFile
    exit
}

$MDEHealthy = $true

function Get-StatusValue($StatusObject, $Item)
{
    <#
    
        Extracts the desired value out of the MS Defender for Endpoint health status output text.
    
    #>

    $SearchValue = $Item.ToLower() + " "                              # Name of the value name plus a space
    $ItemLine = $StatusObject | Select-String -Pattern $SearchValue      # Get the line containing the name of the value
    $ItemValue = ($ItemLine -split ": ")[1].Trim()
    return $ItemValue
}

"Running: /usr/local/bin/mdatp health"
$MDEHealthStatus = /usr/local/bin/mdatp health

""
"Data collected from mdatp, processing..."

$MDEHealthy = Get-StatusValue -StatusObject $MDEHealthStatus -Item "healthy"
$MDELicensed = Get-StatusValue -StatusObject $MDEHealthStatus -Item "licensed"
$MDERealTimeProtectionEnabled = Get-StatusValue -StatusObject $MDEHealthStatus -Item "real_time_protection_enabled"

if ($MDEHealthy -ne "true")
{
    $MDEHealthy = $false
}

if ($MDELicensed -ne "true")
{
    $MDEHealthy = $false
}

if ($MDERealTimeProtectionEnabled -ne "true")
{
    $MDEHealthy = $false
}

if ($MDEHealthy -eq $true)
{
    $MDEHealthStatus = $MDEHealthStatus + [Environment]::NewLine + "MDE Healthy: Yes"
}
else
{
    $MDEHealthStatus = $MDEHealthStatus + [Environment]::NewLine + "MDE Healthy: No" 
}

""
"Reported Health Status:"
""

$MDEHealthStatus

$MDEHealthStatus | Out-File $MDEStatusOutputFile

""