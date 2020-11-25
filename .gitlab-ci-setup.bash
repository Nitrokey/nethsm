#!/bin/bash

OPAM_REPOSITORY_COMMIT=f86b6d27e1
REQUIRED_DISK_SPACE_KB=1000000

# --- No user-serviceable parts below this point ---

set -xe

# Check that the CI runner has enough disk space, and abort now if not.
(($(df -k --output=avail . | tail -1) > ${REQUIRED_DISK_SPACE_KB}))

# Update local opam-repository to use specified commit
cd ~/opam-repository
git fetch origin master
git reset --hard ${OPAM_REPOSITORY_COMMIT}
opam update
cd -

