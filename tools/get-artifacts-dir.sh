#!/bin/sh
# This script produces a partial path name identifying the artifacts for this
# build. Used by "make artifacts".

DESCR="$(git -C . describe --dirty --tags --always)"

if [ -z "${CI}" ]; then
    ID="Z$(date -u +%Y%m%d)"
    BRANCH="$(git rev-parse --abbrev-ref HEAD)"
else
    ID="${CI_JOB_ID}"
    BRANCH="${CI_COMMIT_REF_NAME}"
fi

[ -z "${ID}" ] && exit 1
[ -z "${DESCR}" ] && exit 1
[ -z "${BRANCH}" ] && exit 1

echo "${MODE}-${MUEN_HARDWARE}/${ID}-${BRANCH}-${DESCR}"
