#!/bin/sh
#
# Initialize the Git submodules used by NetHSM, and their submodules.
#
# This is complicated for several reasons:
#
# 1. Muen and Coreboot have relative URLs in their .gitmodules, but we are
#    checking these out from a different origin, so we need to use absolute URLs.
#
#    This is persisted in the superproject's .git/config, which in the case of
#    the superproject being a nested submodule is not where you think it is,
#    and can only be done reliably after it exists and "git submodule init" has
#    been performed.
#
#    In case you're asking "Why not just commit the correct URLs to the
#    respective (sub)-superprojects .gitmodules?": While this would remove the
#    need to run the various "git config" commands, it would imply a commit to
#    the superproject which would make updating to a neewer upstream version
#    unnecessarily hard later on.
#
# 2. We want to check out as many submodules as we can as "shallowly" as
#    possible to save time, bandwidth and disk space, especially when building
#    from CI. *Especially* the really large ones, such as src/git and
#    src/muen/muen/components/linux/src. However, some of the remotes fail with
#    "error: Server does not allow request for unadvertised object ...". This
#    script performs a non-shallow clone in those cases.
#
# 3. It'd be nice if we could just retry "git submodule update foo" when "git
#    submodule update foo --depth X" fails. Unfortunately, when the latter fails
#    it leaves the submodule in question in a dirty and unusable state which is
#    not easily recovered from. Arguably this is a bug in Git, and should be
#    reported upstream.
#
#    In case you ever get into this situation, and don't/can't remove and
#    re-clone the superproject, one way to recover is, assuming the submodule
#    registered at "src/foo" and *NAMED* "foo" (see .gitmodules, the two are
#    different things, unfortunately):
#
#      (superproject) $ git submodule deinit --force src/foo
#      (superproject) $ rm -rf .git/modules/foo
#
#    Doing this successfully for a nested submodule is left as an exercise for
#    the reader.
#
# 4. Whoever designed git submodules should be hung out to dry in the cold.
#
# TODO:
#
# - Since we know how to re-write submodule URLs, have an "alongside" mode
#   where the infrequently changing submodules are cloned from
#   "../somewhere/sub/module". This allows for quick builds after cloning a
#   NetHSM tree from scratch.
#
# - Could we introspect the submodules somehow, so that the list doesn't need
#   to be updated here? Unfortunately "git submodule foreach" only works once a
#   successful "git submodule update" has been performed.
#

# MODE=dev
dev_submodules()
{
set -xe

git submodule init src/git
git submodule update ${DEPTH} src/git
}

# MODE=muen
muen_submodules()
{
set -xe

# Top-level submodules
git submodule init
git submodule update ${DEPTH}

# Muen submodules
git -C src/muen/muen submodule init
# XXX Can't do relative here... sigh...
git -C src/muen/muen config --local \
    submodule.components/linux/src.url git@git.dotplex.com:nitrokey/nethsm/linux.git
git -C src/muen/muen config --local \
    submodule.tools/mugenschedcfg.url https://git.codelabs.ch/muen/mugenschedcfg.git
git -C src/muen/muen config --local \
    submodule.components/libxhcidbg.url https://git.codelabs.ch/libxhcidbg.git
git -C src/muen/muen config --local \
    submodule.components/tau0-static.url https://git.codelabs.ch/muen/tau0.git
git -C src/muen/muen config --local \
    submodule.components/linux/modules/muenfs.url https://git.codelabs.ch/muen/linux/muenfs.git
git -C src/muen/muen config --local \
    submodule.components/linux/modules/muennet.url https://git.codelabs.ch/muen/linux/muennet.git
git -C src/muen/muen config --local \
    submodule.components/linux/modules/muenblock.url https://git.codelabs.ch/muen/linux/muenblock.git
git -C src/muen/muen config --local \
    submodule.components/linux/modules/muenevents.url https://git.codelabs.ch/muen/linux/muenevents.git
git -C src/muen/muen config --local \
    submodule.tools/sbs.url https://git.codelabs.ch/sbs-tools.git
# The following don't like shallow clones
git -C src/muen/muen submodule update components/tau0-static
# Rest of Muen's submodules
git -C src/muen/muen submodule update ${DEPTH}

# Coreboot submodules
git submodule update ${DEPTH} src/coreboot/coreboot
git -C src/coreboot/coreboot submodule init
git -C src/coreboot/coreboot config --local \
    submodule.3rdparty/blobs.url https://review.coreboot.org/blobs.git
git -C src/coreboot/coreboot config --local \
    submodule.util/nvidia-cbootimage.url https://review.coreboot.org/nvidia-cbootimage.git
git -C src/coreboot/coreboot config --local \
    submodule.vboot.url https://review.coreboot.org/vboot.git
git -C src/coreboot/coreboot config --local \
    submodule.arm-trusted-firmware.url https://review.coreboot.org/arm-trusted-firmware.git
git -C src/coreboot/coreboot config --local \
    submodule.3rdparty/chromeec.url https://review.coreboot.org/chrome-ec.git
git -C src/coreboot/coreboot config --local \
    submodule.libhwbase.url https://review.coreboot.org/libhwbase.git
git -C src/coreboot/coreboot config --local \
    submodule.libgfxinit.url https://review.coreboot.org/libgfxinit.git
git -C src/coreboot/coreboot config --local \
    submodule.3rdparty/fsp.url https://review.coreboot.org/fsp.git
git -C src/coreboot/coreboot config --local \
    submodule.opensbi.url https://review.coreboot.org/opensbi.git
git -C src/coreboot/coreboot config --local \
    submodule.intel-microcode.url https://review.coreboot.org/intel-microcode.git
git -C src/coreboot/coreboot config --local \
    submodule.3rdparty/ffs.url https://review.coreboot.org/ffs.git
git -C src/coreboot/coreboot config --local \
    submodule.3rdparty/amd_blobs.url https://review.coreboot.org/amd_blobs
# The following don't like shallow clones
git -C src/coreboot/coreboot submodule update 3rdparty/chromeec
git -C src/coreboot/coreboot submodule update 3rdparty/arm-trusted-firmware
git -C src/coreboot/coreboot submodule update 3rdparty/opensbi
git -C src/coreboot/coreboot submodule update 3rdparty/vboot
# Rest of Coreboot's submodules
git -C src/coreboot/coreboot submodule update ${DEPTH}
}

case "${NO_SHALLOW}" in
    1)
        DEPTH=
        ;;
    *)
        DEPTH="--depth 50"
        ;;
esac

case "${MODE}" in
    any)
        # Just use Muen, which is the full set, and ignore NO_GIT.
        muen_submodules
        ;;
    dev)
        # Special case, no submodules required.
        [ -n "${NO_GIT}" ] && exit 0

        dev_submodules
        ;;
    muen*)
        muen_submodules
        ;;
    test)
        # No submodules required here.
        ;;
    *)
        echo "$0: ERROR: \$MODE not set or invalid." 1>&2
        exit 1
        ;;
esac
