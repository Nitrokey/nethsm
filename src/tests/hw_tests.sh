#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

# PID of the etcd instance we start. Tests may run in parallel on the same
# node, so we must only ever kill the etcd we started ourselves, never other
# etcd processes belonging to concurrent test runs.
ETCD_PID=""

kill_etcd() {
    local sig="${1:-TERM}"
    if [ -n "$ETCD_PID" ]; then
        kill "-$sig" "$ETCD_PID" 2>/dev/null
        wait "$ETCD_PID" 2>/dev/null
        ETCD_PID=""
    fi
}

echo
echo "=== Hardware tests - IPv6 ==="
echo

# clean up any leftover data dir from a previous run of this test
rm -rf witness.etcd

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Operational* ]] ; then
  echo "State $STATE != Operational"
  exit 1
fi

ip a
ip route
ip -6 route

echo "- configure an IPv6 for the HSM"

# in subshell because may fail if the stack is reconfigured before the server
# can answer
(PUT_admin /v1/config/network <<EOM)
{
    "ipAddress": "192.168.1.1",
    "netmask": "255.255.255.0",
    "gateway": "0.0.0.0",
    "ipv6": {
        "cidr": "fc00:22:1::2/48",
        "gateway": null
    }
}
EOM

# wait for HSM stack to restart
sleep 2

GET_admin /v1/config/network

echo "- check the HSM can be pinged via IPv6"
ping -6 -c1 -w10 -q 'fc00:22:1::2' || exit 1

# From now on, talk to the HSM only through IPv6
export NETHSM_URL="https://[fc00:22:1::2]/api"
source "$(dirname $0)/common_functions.sh"

# test that IPv6 is working
echo "- check that keyfender answers over IPv6"
GET /v1/health/state

echo
echo "=== Hardware tests - Adding a witness ==="
echo

# we are going to run a local etcd and make it join our HSM
cat <<EOM > add_req.json
{
    "urls": ["https://192.168.1.100:2380", "https://[fc00:22:1::100]:2380"]
}
EOM

make -f cert.make witness.pem

# ensure no clock drift
SYSTEM_TIME="$(date -u +%FT%TZ)"
PUT_admin /v1/config/time << EOM
{"time": "$SYSTEM_TIME"}
EOM

sleep 2

function generate_witness_conf () {

# a backup passphrase is already configured from a previous restore
echo "- add a new member to the cluster (should succeed)"
ADD_RESP=$(POST_admin /v1/cluster/members < add_req.json) || exit 1
echo $ADD_RESP > response.json

echo "- configure an etcd witness in join mode"
# follow the documentation in docs/clustering.md to create a witness
export ETCD_NAME="witness"
export ETCD_DATA_DIR="witness.etcd"
export ETCD_INITIAL_CLUSTER=$(jq --raw-output '[.members[] | ["\(if .name == "" then "witness" else .name end)=\(.urls[])"]] | flatten | join(",")' < response.json)
export ETCD_INITIAL_ADVERTISE_PEER_URLS=$(jq --raw-output '.members[] | select(.name=="") | .urls | join(",")' < response.json)
echo "ETCD_INITIAL_CLUSTER=$ETCD_INITIAL_CLUSTER"
echo "ETCD_INITIAL_ADVERTISE_PEER_URLS=$ETCD_INITIAL_ADVERTISE_PEER_URLS"
envsubst < ../../docs/etcd_witness.conf.template > witness.conf.yml
echo "- generated witness.conf.yml:"
cat witness.conf.yml
unset ETCD_NAME
unset ETCD_DATA_DIR
unset ETCD_INITIAL_CLUSTER
unset ETCD_INITIAL_ADVERTISE_PEER_URLS

}

generate_witness_conf

etcd_name="etcd-v3.6.13-linux-arm64"
tar xf "$etcd_name.tar.gz"

cleanup_etcd() {
    echo "killing etcd due to TRAP"
    kill_etcd KILL
    rm -rf witness.etcd
}

trap cleanup_etcd EXIT INT TERM # stop etcd no matter what at the end

echo "- start etcd"
"$etcd_name/etcd" --config-file witness.conf.yml &
ETCD_PID=$!

function wait_join() {

echo "- wait for join to complete"
sleep 2 # wait for join to complete

N_id=$(jq -r ".members[] | select(.learner==true) | .id" <response.json)
echo "attempt to promote ${N_id} via ${NETHSM_URL}"
while ! (POST_admin /v1/cluster/members/${N_id}/promote </dev/null); do
    echo "Promotion failed, retry.."; sleep 1;
done;
echo "promoted ${N_id}";

x=0
while ! curl -sf http://127.0.0.1:2379/readyz; do
    ((x++>240)) && echo "etcd is not ready yet while waiting to join!" && exit 1
    sleep 1
done # wait for etcd to start

echo "- waiting for /v1/health/state != Failed"
# Give time for the heartbeat to find that etcd is now alive again
x=0
while test "$(GET /v1/health/state | jq -r .state)" == "Failed"; do
    ((x++>3)) && echo "time out!" && exit 1
    sleep 1
done

}

wait_join

function check_witness_healthy() {
echo "- check witness is healthy"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || exit 1

echo "- check HSM ends up healthy"

x=0
while test "$(GET /v1/health/state | jq -r .state)" != "Operational"; do
    ((x++>32)) && echo "time out!" && exit 1
    sleep 2
done
GET_admin /v1/cluster/members
}

check_witness_healthy

echo "- check we have synced with HSM"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 \
    get "/local/SN3BVNXQFQ/domain-key/attended" || exit 1


MEMBERS=$(GET_admin /v1/cluster/members)
WITNESS_ID=$(echo "$MEMBERS" | jq '.[] | select(.name == "witness") | .id' --raw-output)

echo "- rebooting HSM to check it comes back up healthy"
POST_admin /v1/system/reboot

echo -n "- waiting for NetHSM"
x=0
while ! curl -m 1 -s -k -f ${NETHSM_URL}/v1/health/state ; do
  printf "."
  ((x++>32)) && echo "time out!" && exit 1
  sleep 2
done
echo

echo "- unlock"
POST /v1/unlock <<EOM
{ "passphrase": "UnlockPassphrase" }
EOM

echo "- creating backup"
POST /v1/system/backup --user backup:BackupBackup -o cluster_backup.bin <<EOF
EOF

echo "- generate a key (should get removed by later restore)"
POST_admin /v1/keys/generate <<EOF
{
  "mechanisms": [
    "RSA_Signature_PSS_SHA256"
  ],
  "type": "RSA",
  "length": 2048,
  "id": "extraKey"
}
EOF

sleep 0.5 # give some time for the key to be transferred

echo "- check witness can see the new key"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 \
    get "/key/extraKey" || exit 1

echo "- restoring backup"
${CURL} -X POST --user admin:Administrator -F arguments='{"backupPassphrase": "backupPassphrase"}' -F backup=@cluster_backup.bin \
  ${NETHSM_URL}/v1/system/restore || exit 1

sleep 5

echo "- check witness cannot see the key anymore"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 get "/key/extraKey"

function stop_witness_clean() {
echo "- remove witness cleanly"
DELETE_admin "/v1/cluster/members/$WITNESS_ID"

echo "- killing etcd voluntarily"
kill_etcd
rm -rf witness.etcd
}

stop_witness_clean

sleep 10

echo "- check HSM is still healthy"
GET_admin /v1/cluster/members

echo "- add back witness to the cluster (should succeed)"
generate_witness_conf

echo "- start etcd"
"$etcd_name/etcd" --config-file witness.conf.yml &
ETCD_PID=$!

wait_join

check_witness_healthy

MEMBERS=$(GET_admin /v1/cluster/members)
WITNESS_ID=$(echo "$MEMBERS" | jq '.[] | select(.name == "witness") | .id' --raw-output)

echo "- generate a key (should be retained by recovery)"
POST_admin /v1/keys/generate <<EOF
{
  "mechanisms": [
    "RSA_Signature_PSS_SHA256"
  ],
  "type": "RSA",
  "length": 2048,
  "id": "extraKey2"
}
EOF

echo "- simulating failure"
kill_etcd KILL
rm -rf witness.etcd
x=0
while test $(GET /v1/health/state | jq -r .state) != "Failed"; do
    ((x++>32)) && echo "time out!" && exit 1
    sleep 2
done

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Failed* ]] ; then
  echo "State $STATE != Failed"
  exit 1
fi

echo "- diagnose should show some etcd logs on failure"
GET /v1/health/diagnose >diagnose.out
if test "$(jq -r '.clusterLogs | length' <diagnose.out)" -lt 1; then
	echo "When etcd fails we should have some logs"
	cat diagnose.out
	exit 1
fi

echo "- recover HSM into single node mode"

POST /v1/cluster/force-new <<EOF
EOF

echo "- wait for HSM to complete reboot"
x=0
while ! curl -m 1 -s -k -f "${NETHSM_URL}/v1/health/state"; do
  printf "."
  ((x++>50)) && echo "time out!" && exit 1
  sleep 2
done
echo

echo "- HSM state should be Locked after a succesful recovery and reboot"
STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Locked* ]] ; then
  echo "State $STATE != Locked"
  exit 1
fi

echo "- unlock HSM after recovery"
POST /v1/unlock <<EOM
{ "passphrase": "UnlockPassphrase" }
EOM

echo "- key generated prior to failure should be visible after recovery"
GET_admin /v1/keys/extraKey2 >/dev/null

echo "- after recovery we should have only 1 node: ourselves"
GET_admin /v1/cluster/members >members.out
N=$(jq -r length <members.out)
if test "$N" != "1"; then
	echo "Has unexpected cluster members: $N"
	cat members.out
	exit 1
fi

echo "- add back witness to the recovered node"
generate_witness_conf

echo "- start etcd"
"$etcd_name/etcd" --config-file witness.conf.yml &
ETCD_PID=$!

wait_join

check_witness_healthy

MEMBERS=$(GET_admin /v1/cluster/members)
WITNESS_ID=$(echo "$MEMBERS" | jq '.[] | select(.name == "witness") | .id' --raw-output)

stop_witness_clean

sleep 10

GET_admin /v1/config/network

echo
echo "=== Hardware tests - Cluster join (failure recovery) ==="
echo

GET_admin /v1/cluster/members

cat <<EOM > join_req.json
{
  "members":
    [{"name": "", "urls": ["https://192.168.1.1:2380", "https://[fc00:22:1::2]:2380"]},
     {"name": "witness", "urls": ["https://[fc00:22:1::100]:2380"]}],
  "backupPassphrase": "backupPassphrase",
  "joinerKit": "eyJiYWNrdXBfc2FsdCI6Im9xRHBQTmR1ODdlZVBOb0ZlcmtOaGc9PSIsInVubG9ja19zYWx0IjoiRkJ4RU5ITHg3NGljNHhOd2lCVnhyaUlTYTZ2T0JiV0VGaUFGWkI0d2NQVHQ3bnc0dEd6TVFVN1diYVU9IiwibG9ja2VkX2RvbWFpbl9rZXkiOiI3Vy9qTnRJQkdEQktzSWxPMmwrN1RrOFdMa1pQbWRMc3ppazBMNm9MRXYvU1N1b3UrR2F6Nk1qU0pZM25XMDBOWisyUGxoZzVQV0FBQzhFekRDZ1FxYURzYnNKdFJwR1lKY1dzSlZEV3k3bk1MVklVOXQ0K3R3PT0ifQ=="
}
EOM

# try to join a non-existent cluster, this should restart etcd twice
# (join attempt + recovery)

echo "- join non-existent cluster (should fail)"

! (POST_admin /v1/cluster/join < join_req.json) || exit 1 # in subshell because should fail
echo

# should still be healthy afterward
GET_admin /v1/cluster/members

echo "- launch fresh local etcd"

start_etcd () {
    # purposefully, this etcd instance is only available over IPv6
    "$etcd_name/etcd" \
        --log-format console \
        --log-level error \
        --peer-client-cert-auth=true \
        --peer-trusted-ca-file=CA.pem \
        --peer-cert-file=witness.pem \
        --peer-key-file=witness.key \
        --peer-skip-client-san-verification=true \
        --data-dir=witness.etcd --name witness \
        --initial-advertise-peer-urls "https://[fc00:22:1::100]:2380" \
        --listen-peer-urls "https://0.0.0.0:2380" \
        --advertise-client-urls "" --listen-client-urls http://127.0.0.1:2379 &
    ETCD_PID=$!

    while ! curl -s http://127.0.0.1:2379/readyz; do sleep 1; done # wait for etcd to start
}

start_etcd

# test that we can locally send requests to the witness

echo "- check local etcd is healthy"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || exit 1

# new attempt to join, with the witness listening this time
# the witness is not expecting a new members, so this should still fail (with an
# appropriate error)

echo "- HSM joins local etcd (should fail: etcd not expecting new member)"
! (POST_admin /v1/cluster/join < join_req.json) || exit 1 # in subshell because should fail

# still healthy after failed join

GET_admin /v1/cluster/members

echo
echo "=== Hardware tests - Cluster join (success) ==="
echo

echo "- check local etcd is healthy again"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || exit 1
echo "- set /config/version to 1 to allow join to complete"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 put "/config/version" "1" || exit 1

echo "- adding member to local witness"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member add "joiner" --peer-urls="https://192.168.1.1:2380,https://[fc00:22:1::2]:2380" || exit 1

echo "- attempt to join witness (should succeed)"
POST_admin /v1/cluster/join < join_req.json

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Locked* ]] ; then
  echo "State $STATE != Locked"
  exit 1
fi

GET /v1/health/diagnose >diagnose.out
RUNNING=$(jq -r .clusterState.running <diagnose.out)
if [[ "$RUNNING" != "true" ]]; then
  echo "Diagnose, running is not true: $RUNNING"
  jq < diagnose.out
  exit 1
fi


echo "- local witness should be healthy again after being joined"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || exit 1

echo "- check that NetHSM has written a domain key"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 \
    get "/local/SN3BVNXQFQ/domain-key/attended" || exit 1

echo "- unlock HSM (should fail, store was never provisioned)"
#in subshell because will fail
! (POST /v1/unlock <<EOM) || exit 1
{ "passphrase": "UnlockPassphrase" }
EOM

echo "- kill etcd and wait for HSM to fail"

# kill etcd, this should make the HSM unhealthy
# to avoid race condition with .running below, has to be -9
kill_etcd KILL

GET /v1/health/diagnose >diagnose.out
RUNNING=$(jq -r .clusterState.running <diagnose.out)
if [[ "$RUNNING" != "false" ]]; then
  echo "Diagnose, running is not false: $RUNNING"
  jq < diagnose.out
fi

x=0
while test $(GET /v1/health/state | jq -r .state) != "Failed"; do
    ((x++>32)) && echo "time out!" && exit 1
    sleep 5
done

echo "- reboot HSM to check it comes back up Failed"
POST_admin /v1/system/reboot

x=0
while ! curl -m 1 -s -k -f ${NETHSM_URL}/v1/health/state ; do
  printf "."
  ((x++>32)) && echo "time out!" && exit 1
  sleep 5
done
echo

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Failed* ]] ; then
  echo "State $STATE != Failed"
  exit 1
fi

echo "- restart witness to check HSM recovers automatically"
start_etcd # restart etcd to check we can recover

echo "- check local etcd is healthy"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || exit 1

x=0
while test "$(GET /v1/health/state | jq -r .state)" != "Locked"; do
    ((x++>32)) && echo "time out!" && exit 1
    sleep 5
done

echo "- kill witness again"
# kill etcd one last time
kill_etcd
rm -rf witness.etcd

x=0
while test "$(GET /v1/health/state | jq -r .state)" != "Failed"; do
    ((x++>32)) && echo "time out!" && exit 1
    sleep 5
done

GET /v1/health/diagnose >diagnose.out
cat diagnose.out
RUNNING=$(jq -r .clusterState.running <diagnose.out)
if [[ "$RUNNING" != "false" ]]; then
  echo "Diagnose, running is not false: $RUNNING"
  jq < diagnose.out
fi

echo
echo "Hardware tests OK."

exit 0
