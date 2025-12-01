#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

pkill -9 etcd || true
sleep 2

STATE=$(GET /v1/health/state)
echo "- state: $STATE" # should be Operational

CLUSTER=$(GET_admin /v1/cluster/members)
echo "- cluster state: $CLUSTER"

# try to join a non-existent cluster, this should restart etcd twice 
# (join attempt + recovery)

echo "- attempt join to nonexistent cluster, should fail and recover"

body=$(POST_admin /v1/cluster/join <<EOM
{
  "members":
    [{"name": "", "urls": ["https://192.168.1.1:2380"]},
     {"name": "witness", "urls": ["https://192.168.1.100:2380"]}],
  "backupPassphrase": "backupPassphrase",
  "joinerKit": "eyJiYWNrdXBfc2FsdCI6Im9xRHBQTmR1ODdlZVBOb0ZlcmtOaGc9PSIsInVubG9ja19zYWx0IjoiRkJ4RU5ITHg3NGljNHhOd2lCVnhyaUlTYTZ2T0JiV0VGaUFGWkI0d2NQVHQ3bnc0dEd6TVFVN1diYVU9IiwibG9ja2VkX2RvbWFpbl9rZXkiOiI3Vy9qTnRJQkdEQktzSWxPMmwrN1RrOFdMa1pQbWRMc3ppazBMNm9MRXYvU1N1b3UrR2F6Nk1qU0pZM25XMDBOWisyUGxoZzVQV0FBQzhFekRDZ1FxYURzYnNKdFJwR1lKY1dzSlZEV3k3bk1MVklVOXQ0K3R3PT0ifQ=="
}
EOM
) || true
echo "$body"

# should still be healthy afterward

echo "- HSM has recovered: $CLUSTER"
GET_admin /v1/cluster/members

echo "- launch fresh etcd witness"

rm -rf witness.etcd
etcd_name="etcd-v3.6.5-linux-arm64"
tar xf "$etcd_name.tar.gz"

make -f cert.make own.pem

"$etcd_name/etcd" \
    --log-format console \
    --log-level error \
    --peer-client-cert-auth=true \
    --peer-trusted-ca-file=CA.pem \
    --peer-cert-file=own.pem \
    --peer-key-file=own.key \
    --data-dir=witness.etcd --name witness \
    --initial-advertise-peer-urls https://192.168.1.100:2380 --listen-peer-urls https://0.0.0.0:2380 \
    --advertise-client-urls "" --listen-client-urls http://127.0.0.1:2379 &

sleep 3

# test that we can locally send requests to the witness

echo -n "- check witness is healthy: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list

# new attempt to join, with the witness listening this time
# the witness is not expecting a new members, so this should still fail (with an
# appropriate error)

echo "- attempt to join witness (should fail/recover: witness not expecting new member)"
body=$(POST_admin /v1/cluster/join <<EOM
{
  "members":
    [{"name": "", "urls": ["https://192.168.1.1:2380"]},
     {"name": "witness", "urls": ["https://192.168.1.100:2380"]}],
  "backupPassphrase": "backupPassphrase",
  "joinerKit": "eyJiYWNrdXBfc2FsdCI6Im9xRHBQTmR1ODdlZVBOb0ZlcmtOaGc9PSIsInVubG9ja19zYWx0IjoiRkJ4RU5ITHg3NGljNHhOd2lCVnhyaUlTYTZ2T0JiV0VGaUFGWkI0d2NQVHQ3bnc0dEd6TVFVN1diYVU9IiwibG9ja2VkX2RvbWFpbl9rZXkiOiI3Vy9qTnRJQkdEQktzSWxPMmwrN1RrOFdMa1pQbWRMc3ppazBMNm9MRXYvU1N1b3UrR2F6Nk1qU0pZM25XMDBOWisyUGxoZzVQV0FBQzhFekRDZ1FxYURzYnNKdFJwR1lKY1dzSlZEV3k3bk1MVklVOXQ0K3R3PT0ifQ=="
}
EOM
) || true
echo "$body"

# still healthy after failed join

echo -n "- HSM still healthy cluster state: "
GET_admin /v1/cluster/members

echo "- set /config/version to 1 to allow join to complete: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 put "/config/version" "1"

echo "- adding member to local witness: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member add "joiner" --peer-urls="https://192.168.1.1:2380"

echo "- attempt to join witness (should succeed)"
POST_admin /v1/cluster/join <<EOM || true
{
  "members":
    [{"name": "", "urls": ["https://192.168.1.1:2380"]},
     {"name": "witness", "urls": ["https://192.168.1.100:2380"]}],
  "backupPassphrase": "backupPassphrase",
  "joinerKit": "eyJiYWNrdXBfc2FsdCI6Im9xRHBQTmR1ODdlZVBOb0ZlcmtOaGc9PSIsInVubG9ja19zYWx0IjoiRkJ4RU5ITHg3NGljNHhOd2lCVnhyaUlTYTZ2T0JiV0VGaUFGWkI0d2NQVHQ3bnc0dEd6TVFVN1diYVU9IiwibG9ja2VkX2RvbWFpbl9rZXkiOiI3Vy9qTnRJQkdEQktzSWxPMmwrN1RrOFdMa1pQbWRMc3ppazBMNm9MRXYvU1N1b3UrR2F6Nk1qU0pZM25XMDBOWisyUGxoZzVQV0FBQzhFekRDZ1FxYURzYnNKdFJwR1lKY1dzSlZEV3k3bk1MVklVOXQ0K3R3PT0ifQ=="
}
EOM

echo -n "- state should be Locked: $STATE" # should be Locked
GET /v1/health/state || true

echo "- but local witness should be healthy again after being joined: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 member list || true

echo "- check that NetHSM has written stuff: "
"$etcd_name/etcdctl" --endpoints=http://127.0.0.1:2379 get "/" "0" || true

echo -n "- HSM cannot be unlocked because stuff is missing: "
POST /v1/unlock <<EOM || true
{
    "passphrase": "UnlockPassphrase"
}
EOM

echo -n "- after unlock: "
GET_admin /v1/cluster/members || true

pkill etcd || true

exit 0

# show the return value of adding a member
#
body=$(POST_admin /v1/cluster/members <<EOM
{
    "urls": ["https://192.168.1.100:2380"]
}
EOM
)
echo "$body"

