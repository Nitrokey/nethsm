# Clustering

[[_TOC_]]

Several NetHSM can be synchronized by a simple script on a 3rd host which uses the [backup](https://docs.nitrokey.com/nethsm/administration#backup) and [restore](https://docs.nitrokey.com/nethsm/administration#restore) functions. This works well as long as the frequency of key generations is low. In this case the host would only have access to the encrypted backup and not to the cryptographic keys in clear text. 

Alternatively it is possible to setup a cluster to synchronize data between several NetHSMs directly. This supports high frequency of key generations, realizes high-availability and load balancing. A NetHSM cluster is based on [etcd](etcd.io) which uses the [Raft consensus algorithm](https://raft.github.io/) for strong consistency. This ensures that the data (e.g. keys) is correct in all NetHSMs at all times.

Before setting up a NetHSM cluster make yourself familiar with this technology and constrains to avoid accidential outage and data loss. In addition to this document you may want to refer to [etcd's documentation](https://etcd.io/docs/latest/learning/) too.

## Operational redundancy

We will call "node" a NetHSM that is expected to be part of a cluster.
**A cluster of `N` nodes will continue to operate as long as at least `(N/2)+1`
nodes are healthy and reachable.** That minimal amount of healthy, reachable
nodes is called the **quorum**.

This implies the following scenarios.

### One node goes down and quorum is still reached

In a 3-node cluster, if one node fails (crashes or becomes unreachable due to
network conditions), the two other nodes will continue to work and serve
requests.

If the failed node is still healthy (e.g. it was just a network
problem), it will be inoperable while isolated (not even read-only).

However if the node recovers, it will cleanly resynchronize with the rest of the
cluster and becomes operable again, without losing data.

If it never recovers, it has to be removed from the cluster (see next section),
factory reset, and go through the join process again from scratch.

### A network partition happens and quorum is still reached

This is just a generalization of the previous scenario. In a 5-nodes cluster
where e.g. 3 nodes are in one physical location A and 2 nodes are in another
location B, a network problem isolating A and B would mean the following:

- The 3 nodes in location A are meeting the quorum (3 in this case), so they
  continue to operate.
- The 2 nodes in location B are **not** meeting the quorum (still 3), so they
  will stop operating (even read-only).
- If the network issue is resolved, the 2 nodes will cleanly join back the 3
  others.

### The quorum is durably lost

A failure causing all subsets of the cluster to lose quorum will render the
cluster and its data completely lost, unless the failure is resolved. In this
case, nodes must be factory-reset and a backup must be restored.

This can happen for example if a single node fails in a 2-node cluster (where
the quorum is 2). In this situation, the failed node can not be
cleanly removed from the cluster after the fact, because the remaining healthy
node is already inoperable since it has lost quorum.

Hence it is advised to always have an odd amount of nodes in a
cluster, and to back up often. 

For more information, see [etcd's FAQ](https://etcd.io/docs/v3.6/faq/#why-an-odd-number-of-cluster-members)

## 2-Node Cluster

A two-node active/passive cluster is not supported yet and will be added in a
future version. We recommend introducing a 3rd node, either a 3rd NetHSM or an
etcd "witness" which could be operated on any host. See next section "Witness".

## Witness

The nature of clustering with `etcd` makes it more reliable the more nodes there
are in the cluster. As explained in the "Operational Redundancy" section,
clusters should ideally have at least 3 nodes to have room to fail, since a
2-node cluster will entirely fail if only one fails.

However the design of the feature is such that you don't need to add a full,
real NetHSM device to your cluster to reach a stable number of nodes. Instead,
you can deploy and add a "witness" node yourself. Such a node is just an
instance of `etcd` running on the machine of your choice (or in a container),
and connected to the cluster. It will be recognized as a normal node from the
real devices in the cluster, and receive all data and updates from devices (but
of course you won't be able to perform any HSM operations with it, it's only
storing data).

### Security considerations

The witness node (or anyone with access to it) has direct access to the storage
backend of all nodes in the cluster (e.g. you can dump all entries and
corresponding values with `etcdctl get "/" "0"`).

However, with the exception of the config version
(`/config/version`, which should always be "1"), strictly all of the values are
encrypted (with either a device key for node-specific values or the domain keys
for others), ensuring the confidentiality of sensitive data.

Note however that a malicious node can:
- write garbage as the value for any entry in the store, which will cause nodes
  to fail decrypting it (which may lead to crashes for some system entries).
- list entry names such as users, namespaces and keys, which you may consider sensitive.

## What is shared between nodes

Having a cluster of NetHSMs means that most of the data is shared between them.
Any addition, modification or deletion of keys, users, or namespaces on one node
are eventually reflected on all the others. In general, any operation that
modifies state, will modify state for every node. This include the backup **restore**
operation which works as normal.

The following sections detail what data is fully local, what data is stored in
the shared `etcd` store but remains node-specific, and what data is fully shared
across nodes.

### Not stored in etcd

The **device key** of each node remains only stored locally, and it never shared
across nodes.

### Stored in etcd but node-specific

The following data is stored in `etcd` in different scopes for each node. It
is hence *accessible* to every node but not *uniform* across nodes (each node
can have a different value for this data).

Configuration:
- TLS certificates
- clock configuration
- network configuration
- logging configuration
- unattended boot configuration
- unlock salt (so each node has its own unlock passphrase)
- locked domain key

Note than while each node has its own version of the locked domain key (because
each node locks it with its own device key or unlock passphrase), the underlying
domain key is **shared** across nodes (to access their shared HSM data, such as
keys).


### Stored in etcd and shared

Finally, all the following data is stored in `etcd` in the global scope, so it
is uniform across all nodes of a cluster:

HSM data:
- keys
- users
- namespaces

Configuration:
- config/domain store version
- cluster CA (used to authentify nodes across cluster)
- backup passphrase and backup salt

Note that for now the config/domain store version can only be version 1 (if your
software version supports clustering, then that is what you have). Refer to the
"Upgrading software in a cluster" section for more details on the safety of
installing software updates within a cluster.

## Creating a cluster

Any cluster will initially start from a single node. New nodes will join the
cluster one by one.

### Preparing nodes

Network traffic between nodes is encrypted and authenticated, using their TLS
certificate.

All nodes that are expected to be part of the same cluster must first install a
common Certificate Authority (CA) that will allow them to check that other nodes are
legitimate.

In the following, we assume all nodes are freshly provisioned and operational.

#### Networking

Nodes must first be reconfigured with their expected final network configuration
with the `/config/network` endpoint (refer to its documentation).

#### Creating and installing a CA

Users should create a CA by their own means and according to their own
operational constraints, making sure it allows at least the `keyCertSign` key
usage.

For example, a minimal CA can be created with `openssl`:

```bash
$ openssl genrsa -out CA.key 2048 # create a key
$ openssl req -x509 -new -nodes -key CA.key -sha256 -days 1825 -out CA.pem -addext keyUsage=critical,keyCertSign
```

This CA now has to be installed to every node.

To do this, first generate a Certificate Signing Request (CSR) from
the node with the `/config/tls/csr.pem` endpoint (refer to its documentation).

**NOTE**: To properly authentify nodes, the clustering backend (etcd) expects
that each node has a certificate with a properly filled Subject Alt Names (SAN) field.
In particular, nodes expecting to be reached ony via their IP need to have a
proper IP SAN in their certificate. IP SANs can be requested for the CSR by
prefixing "IP:" to the names, as in `openssl`:

```json
"subjectAltNames": [ "normalname.org", "IP:192.168.1.1" ]
```

Given the obtained CSR (let's call it `nethsm.csr`), we can then generate a
certificate for it, ready to be installed. For example with `openssl`:

```bash
$ openssl x509 -req -days 1825 -in nethsm.csr -CA CA.pem -copy_extensions copy \
    -CAkey CA.key -out new_cert.pem -set_serial 01 -sha256
```

Then install the obtained `new_cert.pem` with the `/config/tls/cert.pem`
endpoint (refer to its documentation).

Finally, the CA (`CA.pem`) can now be installed with the new
`/config/tls/cluster-ca.pem` endpoint (refer to its documentation).
This is only possible now that the installed TLS certificate is signed by it.
Otherwise, the operation would be rejected.

**Note that this process has to be repeated for every node**

#### Clock sync

Make sure every node has been provisioned with an accurate system time. If not,
adjust their clocks with the `/config/time` endpoint.

### Adding a new node

Adding a node to a cluster is done in two steps:
- register the addition to the cluster (through any one of its members)
- tell the new node to join

#### Configure a backup passphrase

First make sure a backup passphrase is configured on the node that will be used
to register a new joiner (see the API documentation of the
`/config/backup-passphrase` endpoint).

#### Registering a new node

**WARNING**: registering a node immediately introduces a new node in the
cluster, modifying the quorum threshold, even if the node has not actually joined
yet. This can render the existing nodes inoperable until the new node has
actually joined. Refer to the [API documentation](https://nethsmdemo.nitrokey.com/api_docs/index.html)
and the "Operational Redundancy" section of this document.

Have at hand the IP of the node that will join. The full *URL* (also called
*peer URL* in `etcd` terminology) of that node
will be `https://<IP_of_node>:2380` (e.g. `https://192.168.1.1:2380`). The port
**MUST** be 2380, so ensure any firewall between the nodes will allow TCP
traffic on that port.

You can double-check the URL is right by calling `GET /cluster/members` on the
node that is expected to join. This should list just one member: itself.

Then register that expected URL on any existing node of the cluster (if you
don't have a cluster yet, do this on the NetHSM that will serve as the initial
node of the cluster). This is done using the `POST /cluster/members` endpoint
(refer to its documentation), passing it a JSON body containing the URL.

If successful, this returns a JSON body of the form
```json
{
  "members": [
    {
      "name": "",
      "urls": [
        "https://172.22.1.3:2380"
      ]
    },
    {
      "name": "9ZVNM2MNWP",
      "urls": [
        "https://172.22.1.2:2380"
      ]
    }
  ],
  "joinerKit": "eyJiYWNrdXBfc2FsdCI6IkVlUzNPOEhHSEc5NnlNRktrdG1NZmc9PSIsInVubG9ja19zYWx0IjoiU3phMkEvYW13NlhxVWsrdHZMMmFubm5SZFlWd2ZQUjdpZ3IxK1RSdTdVaU14dmh3d0x2NWIvYVNkY2c9IiwibG9ja2VkX2RvbWFpbl9rZXkiOiIyMnNGVlkyelhQUVZ6S1pQenI3MmkwTk1WM3lmQ2k5dGwzeDhUbGtuOXM0WjFOd3JoZkRQTFZIVHp1WVl0YkQxaVZCMlovV3JHUHJlMXlwN0t4U0w4WkxjY2ZUTmUzcFg0WXE4YXNlY0wwREhXNGlIaXlPMlZnPT0ifQ=="
}
```

which contains information necessary for the new node the join the cluster. In
particular, it lists all members of the cluster (where the member with an empty
name is the new joiner). It also contains the domain key encrypted
by both the unlock and backup passphrases -- so a backup passphrase must have
been configured before.

Keep that response for the next step.

#### Actually join the cluster

Take the response from last step and append to it a `backupPassphrase` field
containing the backup passphrase of the node on which the new joiner was
registered, and pass that data to a call to `POST /cluster/join` (refer to its
documentation) on the node that is expected to join.

Assuming both the cluster and the node can reach each other, this will enact the
actual join, wiping the data on the new joiner to instead sync its state with
that of the cluster.

Depending on the networking and cluster conditions, this operation may take a
few dozens of seconds. If this operation fails immediately (e.g. the cluster was
not reachable or authentication failed), this node's state will not be wiped and
the join will be reverted. However as soon as a first join is successful, this
operation is final and can only be reverted by a factory reset.

If this join is successful, the node will end up in a `Locked` state, and has to
be unlocked with the unlock passphrase of the node that was used for
registration. Afterwards the unlock passphrase can be changed (unlock passphrases
remain node-specific, not shared across nodes).

**NOTE**: Even after the join has succeeded, if the cluster's database is large
or if the cluster is busy, it may take some time for the new joiner to
synchronize its state fully. During that time, all nodes (including in
particular the new joiner) may be less responsive or unresponsive. The new
joiner in particular may initially return errors when trying to unlock it for
example. In that case, give it some time and try again.

## Adding a witness node

### Prepare a witness

You will need an environment with `etcd` v3.6 available, with an IPv4 (at least)
reachable by the other members of your cluster. TCP traffic to and from port 2380
needs to be allowed.

Create an empty directory where `etcd` will store its data, and write down its
path (we will use `/var/etcd/data`). Ensure the user that will launch the
process has permission to read and write to the directory.

Transfer to the machine the CA certificate that is being used to authenticate
nodes in the cluster. You should have created one in the "Creating and
Installing a CA" section. We'll store it in `/var/etc/CA.pem`.

You will then need to create a certificate for the witness, and sign it with the
CA so it can talk to its peers. This can be done for example through `openssl`:

```bash
# Create a key
$ openssl genrsa -out witness.key 2048
# Create a CSR with a SAN that corresponds to the witness's IP or hostname
$ openssl req -new -sha256 -key own.key -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=witness" \
    -addext "subjectAltName=IP:172.22.1.3" --out witness.csr
# Sign it
$ openssl x509 -req -days 1825 -in witness.csr -CA CA.pem -copy_extensions copy \
    -CAkey CA.key -out witness.pem -set_serial 01 -sha256
```

Store the resulting `witness.key` and `witness.pem` in `/var/etcd` as well.

### Register witness to cluster

Follow the normal instructions from the "Registering a node" section to signal
the existing cluster the addition of a new member with the given URL(s).

Write down the response from the cluster: it should contain the list of cluster
members and a joiner kit (you won't need this part).

### Configure etcd

Unlike NetHSMs which automatically choose a node name for themselves (using the
device ID), you must choose a name for each witness you add, *making sure the
names are unique*. We will use "witness1" in the following examples.

With the NetHSM's response to registering the witness, prepare variables of the form:

```bash
export ETCD_NAME="witness1"
export ETCD_DATA_DIR="/var/etcd/data"
export ETCD_INITIAL_CLUSTER="peer1=url1,peer1=url2,peer2=url1,peer2=url2,..."
export ETCD_INITIAL_ADVERTISE_PEER_URLS="my_url1,my_url2,..."

```
Assuming the NetHSM response is stored in a `response.json` file, you can
generate these last two variables automatically with the following `jq` expressions:

```bash
export ETCD_INITIAL_CLUSTER=$(jq --raw-output '[.members[] | ["\(if .name == "" then "witness1" else .name end)=\(.urls[])"]] | flatten | join(",")' < response.json)
export ETCD_INITIAL_ADVERTISE_PEER_URLS=$(jq --raw-output '.members[] | select(.name=="") | .urls | join(",")' < response.json)
```

For example with the example response provided in the "Registering a new node"
section, you will have:

```bash
ETCD_NAME="witness1"
ETCD_DATA_DIR="/var/etcd/data"
ETCD_INITIAL_CLUSTER="witness1=https://172.22.1.3:2380,9ZVNM2MNWP=https://172.22.1.2:2380"
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://172.22.1.3:2380"
```

Finally, create a `etcd.conf.yml` file by using the template file provided in
`docs/etc_witness.conf.template`:

```bash
$ envsubst < NETHSM_ROOT/docs/etcd_witness.conf.template > /var/etcd/witness.conf.yml
$ cat witness.conf.yml
```

This should give you a field of the form

```yaml
name: witness1
data-dir: /var/etcd/data
log-level: warn
log-format: console

listen-peer-urls: https://0.0.0.0:2380
listen-client-urls: http://localhost:2379

initial-advertise-peer-urls: https://172.22.1.3:2380
advertise-client-urls: http://localhost:2379
initial-cluster: witness1=https://172.22.1.3:2380,9ZVNM2MNWP=https://172.22.1.2:2380
initial-cluster-state: 'existing'

peer-transport-security:
  cert-file: witness.pem
  key-file: witness.key
  client-cert-auth: true
  trusted-ca-file: CA.pem
  skip-client-san-verification: true
```

### Start etcd

Start `etcd` in your preferred way (manually, `systemd` service, container,
etc.), pointing it to the configuration file created in the previous step:

```bash
$ cd /var/etcd
$ etcd --config-file witness.conf.yml
```

You should see it start, join the cluster and catch up with the data. After some
time, you should see in its logs that "etcd is now serving clients".
You can check that it is working with the `etcdctl` client:
```
etcdctl get /config/version
```
This key should exist and contain "1".

Make sure this process keeps running, as it is now a proper member of your
cluster. If you need to decommission it, first properly remove it from the
cluster (see the dedicated section). If its reachable IP change, update its URL
from the cluster.

## Operating a cluster

### Backup and restore

The backup operation works the same as without a cluster and can be requested from
any node of the cluster. It will back up data for the whole cluster, including
node-specific fields (though these will be ignored unless restoring the backup
on an unprovisioned node).

A backup done on a cluster can be restored on the same cluster, even if some
nodes have been added or removed since. Such restores done on operational
clusters will not affect configuration values (only keys, users, namespaces),
like any other partial restore.

Restoring a backup on an unprovisioned node will restore the node-specific fields
(like network configuration, certificates, etc.) of the node that was used to
create the backup.

Restoring a large backup may overwhelm the cluster for some time, while the node
applying the restore forwards changes to the others.

This operation remains compatible with backups made on previous
versions of the NetHSM.

**NOTE**: restoring on a node A a backup made another node Z with a different
domain key will correctly rewrite A's domain key, as before. However if A was in
a cluster with node B, B will become inoperable as Z's domain key will not be
restored on B.

In other words, only perform a restore in a cluster with backups done in the
same cluster (though again nodes may have been removed or added since). If you
want to restore a foreign backup on a node, first safely remove it from its
cluster, then factory reset it and restore the backup.

### Removing a node cleanly

As long as some part of the cluster is still meeting quorum, any of its members
can be used to remove another node from the cluster, whether this node is
already unreachable or is expected to be.

You first have to know the ID of the node you want to remove, by listing all
nodes through `GET /cluster/members` and looking for the right one.

Then it can be removed by calling `DELETE /cluster/members/<id>`. If the node in
question was still healthy, this will isolate it from the rest of the cluster
and render it inoperable.

### Software updates in clusters

Future updates will be marked as "cluster-safe" (this should be the majority) or
"cluster-unsafe".

Cluster-safe updates can be applied to nodes that are part of
a cluster without removing them from the cluster first. However as with all
operations, you should ensure to do this on one node at a time, and in a cluster
where removing a node does not go below the quorum (e.g. if the update fails).

Cluster-unsafe updates must be applied to isolated nodes. You should dismantle
the cluster (removing nodes one by one), factory reset all nodes but one, apply
the update to every node, then make all reset nodes join the remaining node.

Make sure to backup before such operations.

### Reconfiguring an existing cluster

#### Changing the cluster CA

An existing cluster (with two or more nodes) **cannot** change its cluster CA
while in operation. If you need to change this certificate: choose a node,
remove all other nodes, update the CA, then have the other members re-join.

#### Changing the network configuration of nodes

Modifying the network configuration of a node (e.g. changing its IP) will
automatically tell the other nodes about the update. You should however ensure
that do only perform such updates on a single node at a time, and in a cluster
where losing that node would not lost quorum.

## Limitations

Be aware of the following, temporary limitations:

- If a cluster is lost (quorum is lost), the only means of recovery is
    factory-reset + restore. Make sure to back up often. Future releases will
    include means to recover from on-disk data.
- Active/passive setup to support two-nodes cluster, either by utilizing etcd
    Learner or Mirror.
- system time between nodes must be manually synchronized for now. Future
    release may include automatic clock sync.
