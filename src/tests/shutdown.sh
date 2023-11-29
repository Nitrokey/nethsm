#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

case "$1" in
    "-r")
        what=reboot
        ;;
    "-R")
        what=reset
        ;;
    *)
        what=shutdown
        ;;
esac

echo "Shutting down."
POST_admin /v1/system/${what} <<EOM
{}
EOM

