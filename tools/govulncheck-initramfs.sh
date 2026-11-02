#!/bin/sh
# Usage: govulncheck-initramfs.sh IMAGE.cpio.gz NAME...
# Run govulncheck on every Go binary inside the gzipped cpio initramfs, i.e.
# exactly what ends up on the device. Fails if any of the named binaries
# (basenames) was not found and scanned.
set -u
img=$1; shift
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
# Skip dev/: cpio cannot mknod the device nodes as an unprivileged user and they are not Go binaries.
gzip -dc "$img" | (cd "$dir" && cpio -id --quiet -f 'dev/*' -f './dev/*') || true
# Known findings in the prebuilt etcd release that upstream has not fixed yet.
# Drop an ID once a newer etcd release ships the fix (check for releases > v3.6.16).
#   GO-2026-6866, GO-2026-6860: golang.org/x/net html, fixed in x/net v0.62.0
#   GO-2026-5932: golang.org/x/crypto/openpgp, fix only in an unreleased x/crypto
etcd_ignore='["GO-2026-6866","GO-2026-6860","GO-2026-5932"]'

# Scan one binary; fail on any reachable (symbol-level) finding not ignored for it.
scan() {
    case $(basename "$1") in
    etcd | etcdutl) ignore=$etcd_ignore ;;
    *) ignore='[]' ;;
    esac
    json=$(govulncheck -mode=binary -format json "$1") || return 1
    ids=$(printf '%s\n' "$json" | jq -rs --argjson ign "$ignore" \
        '[.[] | select(.finding.trace[0].function != null) | .finding.osv] | unique - $ign | .[]') || return 1
    [ -z "$ids" ] && return 0
    echo "ERROR: unignored vulnerabilities in $1: $ids" >&2
    govulncheck -mode=binary "$1"
    return 1
}

rc=0
scanned=
for f in $(find "$dir" -type f -perm -u+x); do
    go version -m "$f" >/dev/null 2>&1 || continue
    echo "== $img: ${f#"$dir"/}"
    scan "$f" || rc=1
    scanned="$scanned $(basename "$f")"
done
for n in "$@"; do
    case " $scanned " in
    *" $n "*) ;;
    *) echo "ERROR: $n not found as Go binary in $img" >&2; rc=1 ;;
    esac
done
exit $rc
