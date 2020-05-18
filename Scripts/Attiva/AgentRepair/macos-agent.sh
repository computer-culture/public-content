#!/bin/bash

if [[ -z $1 ]]; then
    echo "Please specify N-central Activation Key as first command line parameter"
    exit 1
fi

separator="---------------------------------------------------------------------------------------------"

ncentral_server="support.attiva.co.nz"
activation_key=$1

daemon_plist_path="/Library/LaunchDaemons/AttivaAgent.local.plist"
ncentral_install_script="/tmp/ncentral-install.sh"
ncentral_install_script_delay=60

powershell_folder="/usr/local/microsoft/powershell/7.0.0"
powershell_symlink="/usr/local/bin/pwsh"

test_powershell()
{
    # Check if PowerShell is installed, and if not, install it

    echo "Checking if PowerShell installed..."
    pwsh -command "Get-Date" # Sample command to run
    return_code=$?
    if [ $return_code -ne 0 ]; then
        echo "PowerShell not working."
        remove_powershell
        install_powershell
        echo "PowerShell Installed"
    else
        echo "PowerShell Functional"
    fi
}

install_powershell()
{
    echo "Installing PowerShell..."

    # Remove previous download if it exists
    sudo rm /tmp/powershell.tar.gz
    
    # Download the powershell '.tar.gz' archive
    curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.0.0/powershell-7.0.0-osx-x64.tar.gz

    # Create the target folder where powershell will be placed
    sudo mkdir -p $powershell_folder

    # Expand powershell to the target folder
    sudo tar zxf /tmp/powershell.tar.gz -C $powershell_folder

    # Set execute permissions
    sudo chmod +x $powershell_folder/pwsh

    # Create the symbolic link that points to pwsh
    sudo ln -s $powershell_folder/pwsh $powershell_symlink
}

remove_powershell()
{
    echo "Removing powershell..."
    sudo rm -rf $powershell_symlink $powershell_folder
}

echo "$separator"

test_powershell

echo "$separator"

# Download MacOS N-central agent and associated install script
echo "Cleaning up any old N-central install files..."
sudo rm /tmp/MacAgentInstallation.dmg
sudo rm /tmp/dmg-install.sh.tar.gz
sudo rm /tmp/dmg-install.sh
echo "Done."
echo ""

echo "$separator"

echo "Downloading N-central install files..."
echo ""
curl -k -o /tmp/MacAgentInstallation.dmg "https://$ncentral_server/download/current/macosx/N-central/MacAgentInstallation.dmg"
curl -k -o /tmp/dmg-install.sh.tar.gz "https://$ncentral_server/download/current/macosx/N-central/dmg-install.sh.tar.gz"
tar -zxvf /tmp/dmg-install.sh.tar.gz
echo ""
echo "N-central install files downloaded."
echo ""

echo "$separator"

# Write script that will be executed after current agent uninstalled
echo "Writing post-uninstall script ($ncentral_install_script)..."
cat > $ncentral_install_script << DAEMONSCRIPT
#!/bin/bash

remove_take_control()
{
        rm "/Applications/MSP Anywhere Agent N-central.app"
        rm -rf "/Library/Logs/MSP Anywhere Agent N-central"
        rm -rf "/Library/Logs/MSP Anywhere Installer"
        rm -rf "/Library/MSP Anywhere Agent N-central"
        rm "/Library/LaunchDaemons/MSPAnywhereDaemonN-central.plist"
        rm "/Library/LaunchDaemons/MSPAnywhereHelperN-central.plist"
        rm "/Library/LaunchAgents/MSPAnywhereAgentN-central.plist"
        rm "/Library/LaunchAgents/MSPAnywhereAgentPLN-central.plist"
        rm "/Library/LaunchAgents/MSPAnywhereServiceConfiguratorN-central.plist"
        rm "/Library/PrivilegedHelperTools/MSP Anywhere Agent N-central.app"
}

echo ""
echo "Removing previous N-central agent if it exists..."
/Applications/Mac_Agent.app/Contents/Daemon/usr/sbin/uninstall-nagent y

echo ""
echo "Removing any remnants of Take Control..."
remove_take_control

echo "Installing N-central agent..."
cd /tmp
/tmp/dmg-install.sh -k $activation_key

# Unload Global Daemon so it doesn't run again
sudo launchctl unload $daemon_plist_path

sleep 10

# Remove Global Daemon file
sudo rm $daemon_plist_path
DAEMONSCRIPT

# Mark above script as executable
echo "Marking post-uninstall script as executable..."
sudo chmod +x $ncentral_install_script

# We will use a launchctl global daemon to schedule the above script to happen later
# This is done as if this script is run from Take Control, execution seems to cancel as Take Control is uninstalled.

# First remove any previous daemon
echo "Removing previous Global Daemon if it exists ($daemon_plist_path)..."
sudo launchctl unload $daemon_plist_path
sudo rm $daemon_plist_path

# Write the daemon plist file
echo "Writing Global Daemon file for post-uninstall script (to re-install N-central agent)..."
cat > $daemon_plist_path << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>Label</key>
        <string>AttivaAgent.local</string>
        <key>StandardOutPath</key>
        <string>/tmp/AttivaAgent.local.out</string>
        <key>StandardErrorPath</key>
        <string>/tmp/AttivaAgent.local.err</string>
        <key>ProgramArguments</key>
        <array>
                <string>/bin/sh</string>
                <string>/tmp/ncentral-install.sh</string>
        </array>
        <key>StartInterval</key>
        <integer>$ncentral_install_script_delay</integer>
</dict>
</plist>
PLIST

# Load the Daemon
echo "Loading the Global Daemon for post-uninstall script..."
sudo launchctl load $daemon_plist_path

echo "$separator"

echo "Please wait for N-central agent to reinstall itself."

echo "$separator"