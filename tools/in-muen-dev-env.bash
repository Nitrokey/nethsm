#!/bin/bash

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOP=${SCRIPTDIR}/..
MOUNT=type=bind,source=${TOP}/src/muen,target=/home/user/muen
HOST_UID=$(id -u)
KVM_GID=$(getent group kvm | cut -d: -f3)
NET=host

if [ -z "$1" ]; then
    echo "$0: Please specify image name" 1>&2
    exit 1
fi
if [ -z "${KVM_GID}" ]; then
    echo "$0: Group 'kvm' not resolvable, exiting" 1>&2
    exit 1
fi

IMAGE="$1"
shift
if [ -z "$1" ]; then
    echo "$0: Missing command" 1>&2
    exit 1
fi

# XXX Cannot pass jobserver through here.
# XXX --init -ti is needed for signal handling to work.
exec docker run --rm --init -ti \
    --user="${HOST_UID}" \
    --mount "${MOUNT}" \
    --group-add="${KVM_GID}" \
    --device=/dev/kvm:/dev/kvm \
    --network "${NET}" \
    -e TERM=xterm-color \
    --workdir /home/user/muen \
    "${IMAGE}" "$@"
