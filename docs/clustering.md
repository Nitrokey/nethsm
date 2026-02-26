# Operating a NetHSM cluster

We will call "node" a NetHSM that is expected to be part of a cluster. A "peer"
of a node is another node within the same cluster.

[[_TOC_]]

## Creating a cluster

Any cluster will initially start from a single node. New nodes will join the
cluster one by one.

### Preparing nodes

Network traffic between nodes is encrypted and authenticated, using their TLS
certificate.

All nodes that are expected to be part of the same cluster must first install a
common Certificate Authority (CA) that will allow them to check their peers are
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

#### Registering a new node

Have at hand the IP of the node that will join. The full *peer URL* of that node
will be `https://<IP_of_node>:2380` (e.g. `https://192.168.1.1:2380`). The port
**MUST** be 2380, so ensure any firewall between the nodes will allow TCP
traffic on that port.

You can double-check the URL is right by calling `GET /cluster/members` on the
node that is expected to join. This should list just one member: itself.

Then register that expected peer URL on any existing node of the cluster (if you
don't have a cluster yet, do this on the NetHSM that will serve as the initial
node of the cluster). This is done using the `POST /cluster/members` endpoint
(refer to its documentation), passing it a JSON body containing the peer URL.

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

**WARNING**: registering a node immediately introduces a new node in the
cluster, modifying the quorum threshold, even if the node has not actually joined
yet. This can render the existing nodes inoperable until the new node has
actually joined. Refer to the endpoints' documentation and the "Operational
Redundancy" section of this document.

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
registration. Afterwards the passphrase can be changed (unlock passphrases
remain device-specific, not shared across nodes).

**NOTE**: Even after the join has succeeded, if the cluster's database is large
or if the cluster is busy, it may take some time for the new joiner to
synchronize its state fully. During that time, all nodes (including in
particular the new joiner) may be less responsive or unresponsive. The new
joiner in particular may initially return errors when trying to unlock it for
example. In that case, give it some time and try again.

## Operating a cluster

### What is shared between nodes

Having a cluster of NetHSMs means that most of the data is shared between them.
Any addition, modification or deletion of keys, users, or namespaces on one node
are eventually reflected on all the others. In general, any operation that
modifies state, will modify state for every node.

This include the backup **restore** operation, which works as before. Note that
restoring a large backup may overwhelm the cluster for a while, while the node
applying the restore forwards changes to the others.

The only exceptions to this (i.e. data which are not shared but instead
node-specific) are config data and the domain store:
- TLS certificates
- clock configuration
- network configuration
- logging configuration
- unattended boot configuration
- device key
- unlock passphrase and backup passphrase

Configuration data that **are** shared are:
- the software version (nodes must have a uniform version)
- the cluster CA
- unlock salt and backup salt

In terms of encryption, each node retains its own device key but they all share
the same **domain key** to access their shared data (keys, users, namespaces).

### Backup and restore

The backup operation, which works as before and can be requested from any node
of the cluster, will back up data for the whole cluster, including
device-specific fields.

A backup done on a cluster can be restored on the same cluster, even if some
nodes have been added or removed since. Such restores will, as before, not
affect configuration values (only keys, users, namespaces).

Contrary to before, a backup done on a node (or cluster) and restored on
another unprovisioned one will only restore configuration values if this is the
same node. If not, the machine will be minimally provisioned (and the rest
will get restored normally).

This operation remains compatible with backups made on previous
versions of the NetHSM.

**NOTE**: restoring on a node A a backup made another node Z with a different
domain key will correctly rewrite A's domain key, as before. However if A was in
a cluster with node B, B will become inoperable as Z's domain key will not be
restored on B.

In other words, only perform a restore in a cluster with backups done in the
same cluster. If you want to restore a foreign backup on a node, first safely
remove it from its cluster.

### Operational redundancy

**A cluster of `N` nodes will continue to operate as long as at least `(N/2)+1`
nodes are healthy and reachable.** That minimal amount of healthy, reachable
nodes is called the **quorum**.

This implies the following scenarios.

#### One node goes down and quorum is still reached

In a 3-node cluster, if one node fails (crashes or becomes unreachable due to
network conditions), the two other nodes will continue to work and serve
requests.

If the failed node is still healthy (e.g. it was just a network
problem), it will be inoperable while isolated (not even read-only).

However if the node recovers, it will cleanly resynchronize with the rest of the
cluster and become operable again, without losing data.

If it never recovers, it has to be removed from the cluster (see next section),
factory reset, and go through the join process again from scratch.

#### A network partition happens and quorum is still reached

This is just a generalization of the previous scenario. In a 7-nodes cluster
where e.g. 3 nodes are in one physical location A and 4 nodes are in another
location B, a network problem isolating A and B would mean the following:

- The 4 nodes in location A are meeting the quorum (4 in this case), so they
  continue to operate.
- The 3 nodes in location B are **not** meeting the quorum (still 4), so they
  will stop operating (even read-only).
- If the network issue is resolved, the 3 nodes will cleanly join back the 4
  others.

#### The quorum is durably lost

A failure causing all subsets of the cluster to lose quorum will render the
cluster and its data completely lost, unless the failure is resolved. In this
case, nodes must be factory-reset and a backup must be restored.

This can happen for example if a single node fails in a 2-node cluster (where
the quorum is 2). In this situation, the failed node can not be
cleanly removed from the cluster after the fact, because the remaining healthy
node is already inoperable since it has lost quorum.

Hence it is advised to always have an odd amount of nodes in a
cluster, and to back up often. 

For more information, see [etcd FAQ](https://etcd.io/docs/v3.6/faq/#why-an-odd-number-of-cluster-members)

### Removing a node cleanly

As long as some part of the cluster is still meeting quorum, any of its members
can be used to remove another node from the cluster, whether this node is
already unreachable or is expected to be.

You first have to know the ID of the node you want to remove, by listing all
nodes through `GET /cluster/members` and looking for the right one.

Then it can be removed by calling `DELETE /cluster/members/<id>`. If the node in
question was still healthy, this will isolate it from the rest of the cluster
and render it inoperable.

### Reconfiguring an existing cluster

#### Changing the cluster CA

An existing cluster (with two or more nodes) **cannot** change its cluster CA
while in operation. If you need to change this certificate: choose a node,
remove all other nodes, update the CA, then have the other members re-join.

### Changing the network configuration of nodes

Modifying the network configuration of a node (e.g. changing its IP) will
automatically tell the other nodes about the update. You should however ensure
that do only perform such updates on a single node at a time, and in a cluster
where losing that node would not lost quorum.

## Limitations

Be aware of the following, temporary limitations:

- if a cluster is lost (quorum is lost), the only means of recovery is
    factory-reset + restore. Make sure to back up often. Future releases will
    include means to recover from on-disk data ;
- system time between nodes must be manually synchronized for now. Future
    release may include automatic clock sync.
