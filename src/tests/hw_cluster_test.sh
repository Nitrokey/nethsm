#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

# make sure there is no remnant etcd polluting the test
pkill -9 etcd
rm -rf witness.etcd

echo "- state: " # should be Operational
GET /v1/health/state

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

# configure an IPv6 for the witness
ip a
ip -6 addr add 'fc00:22:1::100/48' dev eth2

echo "- cluster state: "
GET_admin /v1/cluster/members

cat <<EOM > join_req.json
{
  "members":
    [{"name": "", "urls": ["https://192.168.1.1:2380", "https://[fc00:22:1::2]:2380"]},
     {"name": "witness", "urls": ["https://192.168.1.100:2380"]}],
  "backupPassphrase": "backupPassphrase",
  "joinerKit": "eyJiYWNrdXBfc2FsdCI6Im9xRHBQTmR1ODdlZVBOb0ZlcmtOaGc9PSIsInVubG9ja19zYWx0IjoiRkJ4RU5ITHg3NGljNHhOd2lCVnhyaUlTYTZ2T0JiV0VGaUFGWkI0d2NQVHQ3bnc0dEd6TVFVN1diYVU9IiwibG9ja2VkX2RvbWFpbl9rZXkiOiI3Vy9qTnRJQkdEQktzSWxPMmwrN1RrOFdMa1pQbWRMc3ppazBMNm9MRXYvU1N1b3UrR2F6Nk1qU0pZM25XMDBOWisyUGxoZzVQV0FBQzhFekRDZ1FxYURzYnNKdFJwR1lKY1dzSlZEV3k3bk1MVklVOXQ0K3R3PT0ifQ=="
}
EOM

# try to join a non-existent cluster, this should restart etcd twice
# (join attempt + recovery)

echo "- attempt join to nonexistent cluster, should fail and recover"

(POST_admin /v1/cluster/join < join_req.json) # in subshell because should fail

# should still be healthy afterward

echo "- HSM has recovered: "
GET_admin /v1/cluster/members

echo "- launch fresh etcd witness"

etcd_name="etcd-v3.6.5-linux-arm64"
tar xf "$etcd_name.tar.gz"

make -f cert.make own.pem

cleanup_etcd() {
    pkill -9 etcd
    rm -rf witness.etcd
}

trap cleanup_etcd EXIT # stop etcd no matter what at the end

"$etcd_name/etcd" \
    --log-format console \
    --log-level info \
    --peer-client-cert-auth=true \
    --peer-trusted-ca-file=CA.pem \
    --peer-cert-file=own.pem \
    --peer-key-file=own.key \
    --peer-skip-client-san-verification=true \
    --data-dir=witness.etcd --name witness \
    --initial-advertise-peer-urls "https://192.168.1.100:2380" \
    --listen-peer-urls "https://0.0.0.0:2380" \
    --advertise-client-urls "" --listen-client-urls http://127.0.0.1:2379 &

sleep 3 # wait for etcd to start

# test that we can locally send requests to the witness

echo "- check witness is healthy: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list

# new attempt to join, with the witness listening this time
# the witness is not expecting a new members, so this should still fail (with an
# appropriate error)

echo "- attempt to join witness (should fail/recover: witness not expecting new member)"
(POST_admin /v1/cluster/join < join_req.json) # in subshell because should fail

# still healthy after failed join

echo "- HSM still healthy cluster state: "
GET_admin /v1/cluster/members

echo "- set /config/version to 1 to allow join to complete: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 put "/config/version" "1"

echo "- adding member to local witness: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member add "joiner" --peer-urls="https://192.168.1.1:2380,https://[fc00:22:1::2]:2380"

echo "- attempt to join witness (should succeed)"
POST_admin /v1/cluster/join < join_req.json

echo "- state should be Locked: " # should be Locked
GET /v1/health/state

echo "- local witness should be healthy again after being joined: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list

echo "- check that NetHSM has written stuff: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 get "/" "0"

echo "- HSM cannot be unlocked because stuff is missing: "
#in subshell because will fail
(POST /v1/unlock <<EOM)
{ "passphrase": "UnlockPassphrase" }
EOM

exit 0
