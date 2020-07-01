<#

This script checks the status of EDR on a Mac, and outputs key information to a text file which can be read by other applications such as N-central

It reads status information from the /usr/local/bin/sentinelctl utility.

#>

""
"Checking EDR Status..."
""

$AttivaDataPath = "/var/Attiva/"
$EDRStatusOutputFile = $AttivaDataPath + "edr-status.txt"

if (!(Test-Path $AttivaDataPath))
{
    "Output directory does not exist, creating it."
    sudo mkdir $AttivaDataPath
    sudo chmod -R 777 /var/Attiva/
}

if (!(Test-Path /usr/local/bin/sentinelctl))
{
    "Senintel One status utility (/usr/local/bin/sentinelctl) not found, cannot proceed."
    "ERROR: /usr/local/bin/sentinelctl does not exist" | Out-File $EDRStatusOutputFile
    exit
}

$EDRHealthy = $true

$EDRAgentReady = ""
$EDRAgentVersion = ""
$EDRAgentInstallDate = ""
$EDRAgentProtection = ""
$EDREndpointInfected = ""
$EDRDriverStatus = ""
$EDRDriverProtection = ""

function Get-StatusValue($StatusObject, $Item)
{
    <#
    
        Extracts the desired value out of the sentinel one status output text.

        Example output to parse: (from sudo /usr/local/bin/sentinelctl status --filters agent)

            Agent
            Version:               4.0.3.3085
            ID:                    8B54319A-5FA3-54CC-B7D4-FAD3576BABA6
            Codesign:              valid
            Install Date:          23/05/20, 3:00:22 AM
            Ready:                 yes
            Protection:            enabled
            Infected:              no
            Network Quarantine:    no
    
    #>

    $ValueSeparator = $Item.ToLower() + ":"
    $ItemLine = $StatusObject | Select-String -Pattern $ValueSeparator
    $ItemValue = ($ItemLine -split $ValueSeparator).Trim()
    return $ItemValue
}

"Running: sudo /usr/local/bin/sentinelctl status --filters agent"
$EDRAgentStatusRaw = sudo /usr/local/bin/sentinelctl status --filters agent

"Running: sudo /usr/local/bin/sentinelctl status --filters driver"
$EDRDriverStatusRaw = sudo /usr/local/bin/sentinelctl status --filters driver

""
"Data collected from sentinelctl, processing..."
""
"Results:"

$EDRAgentReady = Get-StatusValue -StatusObject $EDRAgentStatusRaw -Item "ready"
$EDRAgentVersion = Get-StatusValue -StatusObject $EDRAgentStatusRaw -Item "version"
$EDRAgentInstallDate = Get-StatusValue -StatusObject $EDRAgentStatusRaw -Item "install date"
$EDRAgentProtection = Get-StatusValue -StatusObject $EDRAgentStatusRaw -Item "protection"
$EDREndpointInfected = Get-StatusValue -StatusObject $EDRAgentStatusRaw -Item "infected"

$EDRDriverStatus = Get-StatusValue -StatusObject $EDRDriverStatusRaw -Item "status"
$EDRDriverProtection = Get-StatusValue -StatusObject $EDRDriverStatusRaw -Item "protection"

if ($EDRAgentReady -ne "yes")
{
    $EDRHealthy = $false
}

if ($EDRAgentProtection -ne "enabled")
{
    $EDRHealthy = $false
}

if ($EDREndpointInfected -ne "no")
{
    $EDRHealthy = $false
}

if ($EDRDriverStatus -ne "loaded")
{
    $EDRHealthy = $false
}

if ($EDRDriverProtection -ne "enabled")
{
    $EDRHealthy = $false
}

$Now = (Get-Date).ToLongDateString() + " " + (Get-Date).ToLongTimeString()

$EDRStatusText = $Now + [Environment]::NewLine + `
"EDR Agent Ready: $EDRAgentReady" + [Environment]::NewLine + `
"EDR Agent Version: $EDRAgentVersion" + [Environment]::NewLine + `
"EDR Agent Install Date: $EDRAgentInstallDate" + [Environment]::NewLine + `
"EDR Agent Protection: $EDRAgentProtection" + [Environment]::NewLine + `
"EDR Endpoint Infected: $EDREndpointInfected" + [Environment]::NewLine + `
"EDR Driver Status: $EDRDriverStatus" + [Environment]::NewLine + `
"EDR Driver Protection: $EDRDriverProtection"

if ($EDRHealthy -eq $true)
{
    $EDRStatusText = $EDRStatusText + [Environment]::NewLine + "EDR Healthy: Yes"
}
else
{
    $EDRStatusText = $EDRStatusText + [Environment]::NewLine + "EDR Healthy: No" 
}

$EDRStatusText

$EDRStatusText | Out-File $EDRStatusOutputFile

""