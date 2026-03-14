#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

echo
echo "=== Hardware tests - IPv6 ==="
echo

# make sure there is no remnant etcd polluting the test
pkill -9 etcd
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

echo "- add a new member to the cluster without a backup passphrase (should fail)"
(POST_admin /v1/cluster/members < add_req.json)

echo "- configure backup passphrase"
PUT_admin /v1/config/backup-passphrase <<EOM
{
  "newPassphrase": "backupPassphrase",
  "currentPassphrase": ""
}
EOM


make -f cert.make own.pem

# ensure no clock drift
SYSTEM_TIME="$(date -u +%FT%TZ)"
PUT_admin /v1/config/time << EOM
{"time": "$SYSTEM_TIME"}
EOM

sleep 2

echo "- add a new member to the cluster (should succeed)"
POST_admin /v1/cluster/members < add_req.json

echo "- start an etcd witness in join mode"

etcd_name="etcd-v3.6.5-linux-arm64"
tar xf "$etcd_name.tar.gz"

cleanup_etcd() {
    pkill -9 etcd
    rm -rf witness.etcd
}

trap cleanup_etcd EXIT # stop etcd no matter what at the end

"$etcd_name/etcd" \
    --log-format console \
    --log-level warn \
    --peer-client-cert-auth=true \
    --peer-trusted-ca-file=CA.pem \
    --peer-cert-file=own.pem \
    --peer-key-file=own.key \
    --peer-skip-client-san-verification=true \
    --data-dir=witness.etcd --name witness \
    --initial-cluster-state "existing" \
    --initial-cluster "SN3BVNXQFQ=https://192.168.1.1:2380,SN3BVNXQFQ=https://[fc00:22:1::2]:2380,witness=https://192.168.1.100:2380,witness=https://[fc00:22:1::100]:2380," \
    --initial-advertise-peer-urls "https://192.168.1.1:2380,https://[fc00:22:1::100]:2380" \
    --listen-peer-urls "https://0.0.0.0:2380" \
    --advertise-client-urls "" --listen-client-urls http://127.0.0.1:2379 &

sleep 20 # wait for join to complete

echo "- check witness is healthy"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || exit 1

echo "- check we have synced with HSM"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 \
    get "/local/SN3BVNXQFQ/domain-key/attended" || exit 1

echo "- check HSM is still healthy again"
GET_admin /v1/cluster/members
MEMBERS=$(GET_admin /v1/cluster/members)
WITNESS_ID=$(echo "$MEMBERS" | jq '.[] | select(.name == "witness") | .id' --raw-output)

echo "- remove witness cleanly"
DELETE_admin "/v1/cluster/members/$WITNESS_ID"

pkill etcd
rm -rf witness.etcd

sleep 10

echo "- check HSM is still healthy"
GET_admin /v1/cluster/members

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

(POST_admin /v1/cluster/join < join_req.json) # in subshell because should fail
echo

# should still be healthy afterward
GET_admin /v1/cluster/members

echo "- launch fresh local etcd"


# purposefully, this etcd instance is only available over IPv6
"$etcd_name/etcd" \
    --log-format console \
    --log-level error \
    --peer-client-cert-auth=true \
    --peer-trusted-ca-file=CA.pem \
    --peer-cert-file=own.pem \
    --peer-key-file=own.key \
    --peer-skip-client-san-verification=true \
    --data-dir=witness.etcd --name witness \
    --initial-advertise-peer-urls "https://[fc00:22:1::100]:2380" \
    --listen-peer-urls "https://0.0.0.0:2380" \
    --advertise-client-urls "" --listen-client-urls http://127.0.0.1:2379 &

sleep 3 # wait for etcd to start

# test that we can locally send requests to the witness

echo "- check local etcd is healthy"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || exit 1

# new attempt to join, with the witness listening this time
# the witness is not expecting a new members, so this should still fail (with an
# appropriate error)

echo "- HSM joins local etcd (should fail: etcd not expecting new member)"
(POST_admin /v1/cluster/join < join_req.json) # in subshell because should fail

# still healthy after failed join

GET_admin /v1/cluster/members

echo
echo "=== Hardware tests - Cluster join (success) ==="
echo

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

echo "- local witness should be healthy again after being joined"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || exit 1

echo "- check that NetHSM has written a domain key"
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 \
    get "/local/SN3BVNXQFQ/domain-key/attended" || exit 1

echo "- unlock HSM (should fail, store was never provisioned)"
#in subshell because will fail
(POST /v1/unlock <<EOM)
{ "passphrase": "UnlockPassphrase" }
EOM

echo
echo "Hardware tests OK."

exit 0
