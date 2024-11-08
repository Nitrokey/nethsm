#!/bin/sh -e
#
# deploy the software on hw with the installer image over BMC virtual media
#

INSTALLER_URL="$1"

is_inserted ()
{
    local state
    state=$(curl -s -k -u ${BMC_USER}:${BMC_PASS} \
        https://${BMC_IP}/redfish/v1/Managers/1/VirtualMedia/usb0 \
        | jq -r .Inserted)
    [ "$state" = "true" ]
}

eject ()
{
    curl -s -k -u ${BMC_USER}:${BMC_PASS} -X POST \
    https://${BMC_IP}/redfish/v1/Managers/1/VirtualMedia/usb0/Actions/VirtualMedia.EjectMedia
}

insert ()
{
    local url=$1
    curl -s -k -u ${BMC_USER}:${BMC_PASS} -H "Content-Type: application/json" \
      -d "{\"Image\":\"${url}\"}" \
      https://${BMC_IP}/redfish/v1/Managers/1/VirtualMedia/usb0/Actions/VirtualMedia.InsertMedia
}

is_on ()
{
    local state
    state=$(curl -s -k -u ${BMC_USER}:${BMC_PASS} https://${BMC_IP}/redfish/v1/Systems/1 \
      | jq -r .PowerState)
    [ "$state" = "On" ]
}

power_on ()
{
    local state=$1
    curl -s -k -u ${BMC_USER}:${BMC_PASS} -H "Content-Type: application/json" \
      -d '{"ResetType": "On"}' \
      https://${BMC_IP}/redfish/v1/Systems/1/Actions/ComputerSystem.Reset
}

power_off ()
{
    local state=$1
    curl -s -k -u ${BMC_USER}:${BMC_PASS} -H "Content-Type: application/json" \
      -d '{"ResetType": "ForceOff"}' \
      https://${BMC_IP}/redfish/v1/Systems/1/Actions/ComputerSystem.Reset
}

if is_on; then
    echo "switching off"
    power_off
    while is_on; do echo "." ; sleep 1; done
    echo
fi

if is_inserted; then
    echo "ejecting media"
    eject
    while is_inserted; do
        echo "."
        sleep 1
    done
    echo
fi

echo "inserting installer image $INSTALLER_URL"
insert $INSTALLER_URL

while ! is_inserted; do echo "." ; sleep 1; done
echo

echo "starting installer"
power_on

while ! is_on; do echo "." ; sleep 1; done
echo

echo "waiting for installer to finish (power off)"
while is_on; do echo "." ; sleep 2; done
echo

echo "ejecting installer image"
eject

while is_inserted; do echo "." ; sleep 1; done
echo

echo "starting NetHSM"
power_on
