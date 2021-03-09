tar -zcvf /tmp/agentlogs.tar.gz "/var/log/N-able/N-agent/" "/Applications/Mac_agent.app/Contents/Daemon/etc/" "/var/log/nagent.log" "/var/log/system.log" "/Library/Logs/CrashReporter/" "/Applications/Mac_agent/etc/agent.conf" "/tmp/" "/Library/Logs/MSP Anywhere Agent N-central" "/Users/USER_NAME/Library/Logs/MSP Anywhere Agent N-central" "/Library/Logs/MSP Anywhere Installer"

$LogFileName = $(hostname)

$LocalFile = "/tmp/agentlogs.tar.gz"
$RemoteFile = "ftp://AttivaFTPUpload:ab548kfnbsWF@ftp.computerculture.co.nz/AgentLogs/$LogFileName"

Write-Output "Uploading file to FTP..."

try
{
    $webclient = New-Object System.Net.WebClient
    $uri = New-Object System.Uri($RemoteFile)
    $webclient.UploadFile($Uri, $LocalFile)  
    $webclient.Dispose();
}
catch
{
    Write-Output "Failed to upload file, exiting..."
    Exit
}