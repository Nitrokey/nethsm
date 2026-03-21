#!/bin/sh -e
#
# deploy the software on hw with the installer image over BMC virtual media
#

INSTALLER_URL="$1"

is_inserted ()
{
    local state
    state=$(curl -s -k -u ${BMC_USER}:${BMC_PASS} https://${BMC_IP}/api/msd \
        | jq -r .result.drive.connected)
    [ "$state" = "true" ]
}

eject ()
{
    curl -s -k -u ${BMC_USER}:${BMC_PASS} -X POST "https://${BMC_IP}/api/msd/set_connected?connected=0"
}

insert ()
{
    local file=$1
    curl -s -X POST -k -u ${BMC_USER}:${BMC_PASS} "https://${BMC_IP}/api/msd/remove?image=ci-installer.iso"
    sleep 2
    curl -s -X POST -k -u ${BMC_USER}:${BMC_PASS} --data-binary @${file} "https://${BMC_IP}/api/msd/write?image=ci-installer.iso"
    curl -s -X POST -k -u ${BMC_USER}:${BMC_PASS} "https://${BMC_IP}/api/msd/set_params?image=ci-installer.iso"
    curl -s -X POST -k -u ${BMC_USER}:${BMC_PASS} "https://${BMC_IP}/api/msd/set_connected?connected=1"
}

is_on ()
{
    local state
    state=$(curl -s -k -u ${BMC_USER}:${BMC_PASS} https://${BMC_IP}/api/atx \
      | jq -r .result.leds.power)
    [ "$state" = "true" ]
}

power_on ()
{
    curl -sS -k -u ${BMC_USER}:${BMC_PASS} \
      -X POST "https://${BMC_IP}/api/atx/power?action=on&wait=true"
    echo
}

power_off ()
{
    curl -sS -k -u ${BMC_USER}:${BMC_PASS} \
      -X POST "https://${BMC_IP}/api/atx/power?action=off_hard&wait=true"
    echo
}

power_long ()
{
    curl -sS -k -u ${BMC_USER}:${BMC_PASS} \
      -X POST "https://${BMC_IP}/api/atx/click?button=power_long&wait=true"
    echo
}

if is_on; then
    echo "switching off"
    power_off
    while is_on; do printf "." ; sleep 1; done
    echo
fi

if is_inserted; then
    echo "ejecting media"
    eject
    while is_inserted; do
        printf "."
        sleep 1
    done
    echo
fi

echo "inserting installer image $INSTALLER_URL"
insert $INSTALLER_URL

while ! is_inserted; do printf "." ; sleep 1; done
echo

echo "starting installer"
power_on

sleep 2

if ! is_on; then
    power_long ()
    sleep 5
    if ! is_on; then
        echo "ERROR: can't power on HIL"
        false
    fi
fi

echo "waiting for installer to finish (power off)"
while is_on; do printf "." ; sleep 2; done
echo

echo "ejecting installer image"
eject

while is_inserted; do printf "." ; sleep 1; done
echo

echo "starting NetHSM"
power_on
