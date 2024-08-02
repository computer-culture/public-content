#!/bin/bash

<< ////

    This script downloads and installs the latest N-central agent for macOS.
    
    There are two execution options:
        - Using an Activation Key: This is for existing or pre-staged device in N-central (usage script.sh -a "<ACTIVATIONKEY")
        - InTune Lookup: If the device is enrolled in InTune, we can use the Tenant ID and Serial Number of the device to install the agent (no command line parameters)

    If using an activation key, the script will decode the key to get the required values for the silent install.

    If using the InTune method, the script will gather the serial number of the local system along with the Microsoft Tenant ID,
    and send those details to our middleware to get the required values for the silent install.

    To get the Microsoft Tenant ID, we need to find it in the logs of the current logged in user.

    N-central Agent Installation:

    The script downloads the latest Install_N-central_Agent.dmg file, mounts it, extracts the PKG file and installs it silently.
    To pass the agent registration details to the installer, we need to save them in a file called ncentral_silent_install.params

    The following fields are always mandatory:
        NC_IVPRM_PROTOCOL="https"
        NC_IVPRM_SERVER="support.attiva.co.nz"
        NC_IVPRM_PORT="443"

    Then if we are using an Activation Key, we decode it to get:
        NC_IVPRM_TOKEN="${token}"
        NC_IVPRM_APPLIANCE="${param_appliance}"
    
    If not using Activation Key, look up the middleware to get 
        NC_IVPRM_TOKEN="${token}"
        NC_IVPRM_ID="${code}"
        NC_IVPRM_NAME="${customer}"

////

EXIT_ERROR_AGENT_ALREADY_INSTALLED=0
EXIT_ERROR_CANT_FIND_USER=11
EXIT_ERROR_CANT_FIND_USER_DIRECTORY=12
EXIT_ERROR_CANT_MOUNT_DMG=13

AGENT_DIR="/Library/N-central Agent"
LEGACY_AGENT_DIR="/Applications/Mac_Agent.app"

if [ -f "${AGENT_DIR}/nagent" ] || [ -d "${LEGACY_AGENT_DIR}" ]; then
    echo "Agent is already installed on this device."
    exit ${EXIT_ERROR_AGENT_ALREADY_INSTALLED}
fi

# Check if activation key provided
while getopts 'a:' OPTION
do
    case ${OPTION} in
        a)
            activation_key="${OPTARG}" ;;
    esac
done

if [ -z "$activation_key"]; then
    echo "No activation key provided, checking InTune..."
else
    echo "Using activation key: $activation_key"
fi

download_url="https://support.attiva.co.nz/download/latest/macosx/N-central/Install_N-central_Agent.dmg"
agent_download_path="/tmp/Install_N-central_Agent.dmg"
image_base_volume_name="Install N-central Agent"
dmg_mount_point="/Volumes/N-central Agent silent installation"
installer_package_filename="Install.pkg"
installer_package_path="/tmp/${installer_package_filename}"
installer_config_file="/tmp/ncentral_silent_install.params"

unmount_installer_dmg() 
{
    # Mounting a DMG Installer by double clicking on it resolve in a different 
    # place than expected. Trying to mount the same DMG installer under another 
    # path will give an error that the resource is busy (in use). To resolve 
    # this we need to unmount any old installers currently in use in order
    # proceed with the installation.

    # Unmount `hdiutil` mounted, silent installer volume.
    if [ -d "${dmg_mount_point}" ]; then
        echo "Unmounting: ${dmg_mount_point}"

        hdiutil detach "${dmg_mount_point}" -force -quiet
    fi

    # Unmount manually mounted volumes. https://www.shellcheck.net/wiki/SC2044
    for volume in "/Volumes"/*; do
        case ${volume} in
            *"${image_base_volume_name}"*)
                echo "Unmounting: ${volume}"
                hdiutil detach "${volume}" -force -quiet
                ;;
            *)
                ;;
        esac
    done
}

if [ -z "$activation_key" ]; then
    echo "------------------------------------------"
    echo "Using InTune registration method, gathering details from local machine..."

    # Get current console user from root, as we need to search user log files for MS Tenant ID
    current_user=$(stat -f "%Su" /dev/console)

    if [[ -z "$current_user" || "$current_user" == "root" ]]
    then
        echo "Can't find logged in user, exiting"
        exit ${EXIT_ERROR_CANT_FIND_USER}
    else
        echo "Found user $current_user"
    fi

    # Get macOS serial
    serial=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')
    echo "Found Serial Number: $serial"

    # InTune Device ID
    # intune_id=(security find-certificate -a | awk -F= '/issu/ && /MICROSOFT INTUNE MDM DEVICE CA/ { getline; print $2}')

    # Navigate to log directory
    if [ -d /Users/$current_user/Library/Logs/Company\ Portal ]
    then
        cd /Users/$current_user/Library/Logs/Company\ Portal
    else
        echo "Can't finder user directory, exiting"
        exit ${EXIT_ERROR_CANT_FIND_USER_DIRECTORY}
    fi

    #Get Last log file
    last_file=$(find . -type f -iname "com.microsoft.CompanyPortalMac*" | tail -n1)
    tenant_line=$(cat "$last_file" | grep "context: TenantID:" | tail -n1)
    tenant_id=$(echo $tenant_line | cut -d ":" -f 3)

    echo "Found Tenant ID in log file: $tenant_id"

    echo "Sending to middleware and waiting response..."
    curl -d '{"TenantId":"'"$tenant_id"'","DeviceSerialNumber":"'"$serial"'"}'\
        -H 'Content-Type: application/json'\
        -H "Accept: application/json"\
        https://ccl-integrations.azurewebsites.net/api/Get-NcentralRegTokenFromSerial?code=2HmSWJxjh-5WpKCpTlVp0JtwPkfY_hFSgzm8mncwSaGvAzFuaUTpRQ%3D%3D\
        > /tmp/reg.json

    code=$(cat /tmp/reg.json | python3 -c "import json,sys;obj=json.load(sys.stdin);print(obj['ncentralSiteAccessCode']);")
    customer=$(cat /tmp/reg.json | python3 -c "import json,sys;obj=json.load(sys.stdin);print(obj['ncentralCustomerName']);")
    token=$(cat /tmp/reg.json | python3 -c "import json,sys;obj=json.load(sys.stdin);print(obj['ncentralRegistrationToken']);")

    rm -f /tmp/reg.json

    echo "Middleware returned Site ID: $code, Customer Name $customer, and Registration Token: $token"

    echo "Setting up installation configuration file..."
    rm -f $installer_config_file

    cat <<NC_CONFIG >> "${installer_config_file}"
NC_IVPRM_PROTOCOL="https"
NC_IVPRM_SERVER="support.attiva.co.nz"
NC_IVPRM_PORT="443"
NC_IVPRM_TOKEN="${token}"
NC_IVPRM_ID="${code}"
NC_IVPRM_NAME="${customer}"
NC_CONFIG

    echo "File configured as follows: (${installer_config_file})"
    cat ${installer_config_file}
else

    echo "Using activation key registration method..."
    decoded_activation_key=$( echo "$activation_key" | openssl enc -base64 -d -A )    
    echo "Decoded activation key: $decoded_activation_key"
    appliance_id=$( printf "%s" "${decoded_activation_key}" | awk -F "|" '{print $2}' )
    token=$( printf "%s" "${decoded_activation_key}" | awk -F "|" '{print $4}' )

    cat <<NC_CONFIG >> "${installer_config_file}"
NC_IVPRM_PROTOCOL="https"
NC_IVPRM_SERVER="support.attiva.co.nz"
NC_IVPRM_PORT="443"
NC_IVPRM_TOKEN="${token}"
NC_IVPRM_APPLIANCE="${appliance_id}"
NC_CONFIG
fi

echo "Downloading agent installer ${download_url}..."
curl -L -o "${agent_download_path}" "${download_url}"

echo "Removing any previous mount points if they exist..."
unmount_installer_dmg

echo "Mounting ${agent_download_path} at "${dmg_mount_point}"..."
hdiutil attach "${agent_download_path}" -noautoopen -nobrowse -readonly -mountpoint "${dmg_mount_point}" -quiet
if ! [ -d "${dmg_mount_point}" ]; then
    echo "Failed to mount '${agent_download_path}'"
    exit ${EXIT_ERROR_CANT_MOUNT_DMG}
fi

echo "Copying installer package to ${installer_package_path}..."
cp "${dmg_mount_point}/${installer_package_filename}" "${installer_package_path}"

echo "Detaching DMG mount point and removing file..."
hdiutil detach "${dmg_mount_point}" -force -quiet
rm -f "${agent_download_path}"

echo "Installing N-central agent..."
installer -pkg "${installer_package_path}" -target /

echo "Removing ${installer_package_path}..."
echo "Done!"
