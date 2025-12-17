# Operating a NetHSM cluster

* [Creating a cluster](#creating-a-cluster)
  + [Preparing nodes](#preparing-nodes)
      - [Networking](#networking)
      - [Creating and installing a CA](#creating-and-installing-a-ca)
      - [Clock sync](#clock-sync)
  + [Adding a new node](#adding-a-new-node)
      - [Registering a new node](#registering-a-new-node)
      - [Actually join the cluster](#actually-join-the-cluster)
* [Operating a cluster](#operating-a-cluster)
  + [What it means to have a cluster](#what-it-means-to-have-a-cluster)
  + [Updating the CA](#updating-the-ca)
  + [Changing the peer URLs](#changing-the-peer-urls)
  + [Removing a node cleanly](#removing-a-node-cleanly)
* [Limitations](#limitations)
* [Failure modes](#failure-modes)


We will call "node" a NetHSM that is expected to be part of a cluster.

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

For example, a minimal CA can be created by `openssl`:

```bash
$ openssl genrsa -out CA.key 2048 # create a key
$ openssl req -x509 -new -nodes -key CA.key -sha256 -days 1825 -out CA.pem -addext keyUsage=critical,keyCertSign
```

This CA now has to be installed to every node.

Installing this CA to a node is done though the new endpoint
`/config/tls/cluster-ca.pem`. However right now it wouldn't be accepted, because
the node would detect its TLS cert is not signed by our CA yet.

To do this, first generate a Certificate Signing Request (CSR) from
the node with the `/config/tls/csr.pem` endpoint (refer to its documentation).

**NOTE**: The properly authentify peers, the clustering backend (etcd) expects
that each node has a certificate with a properly filled Subject Alt Names (SAN) field.
In particular, nodes expecting to be reached via their IP only need to have a
proper IP SAN in their certificate. IP SANs can be requested for the CSR by
prefixing "IP:" to the names, as in `openssl`:

```
  ...
  "subjectAltNames": [ "normalname.org", "IP:192.168.1.1" ]
  ...
```

Given the obtained CSR (let's call it `nethsm.csr`), we can then generate a
certificate for it, ready to be installed. For example with `openssl`:

```bash
$ openssl x509 -req -days 1825 -in nethsm.csr -CA CA.pem -copy_extensions copy \
    -CAkey CA.key -out new_cert.pem -set_serial 01 -sha256
```

Then install the obtained `new_cert.pem` with the `/config/tls/cert.pem`
endpoint (refer to its documentation).

Finally, the CA (`CA.pem`) can now be installed with the
`/config/tls/cluster-ca.pem` (refer to its documentation).

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
```
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
name is the new joiner). It also contains it contains the domain key encrypted
by both the unlock and backup passphrases -- so a backup passphrase must have
been configured before.

Keep that response for the next step.

**WARNING**: registering a node immediately introduces a new node in the
cluster, modifying the quorum theshold, even if the node has not actually joined
yet. This can render the existing nodes inoperable until the new node has
actually joined. Refer to the endpoints' documentation and the last section of
the document.

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

### What it means to have a cluster

- keys/users/namespaces are shared
- backup/restore
- some configs are shared, some are not

### Updating the CA

### Changing the peer URLs

### Removing a node cleanly

## Limitations

## Failure modes
