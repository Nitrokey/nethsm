# This script should be sourced (not executed!) from .gitlab-ci.yml for correct
# operation.

OPAM_REPOSITORY_COMMIT=$(cat .opam-repository-commit)
REQUIRED_DISK_SPACE_KB=${REQUIRED_DISK_SPACE_KB:-1000000}

# --- No user-serviceable parts below this point ---

# Start an ssh-agent with SSH deploy keys loaded into it.
if [ -n "${SSH_CI_DEPLOY_KEY}" ]; then
    eval $(ssh-agent -s)
    echo "$SSH_CI_DEPLOY_KEY" | tr -d '\r' | ssh-add -
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    echo "$SSH_KNOWN_HOSTS" >> ~/.ssh/known_hosts
    chmod 644 ~/.ssh/known_hosts
else
    echo "$0: warning: \$SSH_CI_DEPLOY_KEY not present." 1>&2
fi

# Auto-fail on error from here onwards.
set -xe

# Check that the CI runner has enough disk space, and abort now if not.
(($(df -k --output=avail . | tail -1) > ${REQUIRED_DISK_SPACE_KB}))

# Update local opam-repository to use specified commit
cd ~/opam-repository
git remote set-url origin https://github.com/ocaml/opam-repository.git
git fetch origin master
git reset --hard ${OPAM_REPOSITORY_COMMIT}
opam update
cd -

# Fetch submodules
make fetch-submodules

# Setup caches
sudo chmod 01777 /downloads
mkdir -p /downloads/opam
rm -rf ~/.opam/download-cache
ln -s /downloads/opam ~/.opam/download-cache

if [ ${MODE} == "muen" ]; then
    mkdir -p /downloads/tarballs
    ln -s /downloads/tarballs src/coreboot/coreboot/util/crossgcc/
fi
