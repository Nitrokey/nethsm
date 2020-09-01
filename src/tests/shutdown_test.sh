#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

# shut down hsm
echo "Shutting down."
POST_admin /v1/system/shutdown <<EOM
EOM
