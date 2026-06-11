## ICMP P2P
A lightweight trust based P2P network built on top of ICMP Echo Request and Echo Reply packets.

## Features

1. Discovers peers through a bootstrap node.
2. Expands the peer list using information received from other peers.
3. Automatically verifies newly discovered peers.
4. Periodically refreshes peer information.
5. Removes inactive peers after a timeout period.
6. Exchanges peer information through ICMP payloads.
7. Broadcasts signed messages across the network.
8. Maintains trust scores for peer selection and propagation.

## Protocol

### Lookup Request (type: 0)
`[type (1 byte)][want (1 byte)][free_slots (1 byte)][public_key (32 bytes)][signature (64 bytes)]`

* type: Protocol identifier.
* want: Number of peers requested by the node. This value is dynamically adjusted based on the trust score of the destination peer.
* free_slots: Number of available peer slots.
* public_key: Node public key.
* signature: Ed25519 signature over `[type][want][free_slots][public_key]`.

### Lookup Response (type: 0)
`[type (1 byte)][free_slots (1 byte)][peers (n bytes)][public_key (32 bytes)][signature (64 bytes)]`

* type: Protocol identifier.
* free_slots: Number of available peer slots on the responding node.
* peer_count: Number of peers included in the response.
* peers: List of peer addresses.
* public_key: Node public key.
* signature: Ed25519 signature over `[type][free_slots][peers][public_key]`.

### Message (type: 1)
`[type (1 byte)][id (2 bytes)][message (n bytes)][expiry (8 bytes)][signature (64 bytes)]`

* type: Protocol identifier.
* id: Message identifier used for deduplication.
* message: Message payload.
* expiry: Expiration time as an 8-byte big-endian Unix timestamp.
* signature: Ed25519 signature over `[type][id][message][expiry]`.

## Message Propagation

1. A node receives a Message packet through an ICMP Echo Request.
2. The packet signature is verified using the configured admin public key.
3. Expired messages are discarded.
4. Duplicate message IDs are ignored.
5. Valid messages are printed to stdout.
6. The message is rebroadcast to all checked peers.

## Peer States

| State | Description |
|---------|-------------|
| unchecked | Newly discovered peer |
| checking | Peer verification in progress |
| checked | Verified peer |

## Trust

- Peers are assigned a trust score.
- Verified peers gain trust.
- Peers that provide valid peer information gain trust.
- Peers that provide invalid or inactive peers lose trust.
- Low-trust peers are not shared with other peers.
- Banned peers are removed from the peer list.

## Peer Management

- Peer information is updated whenever a Lookup Response is received.
- Newly discovered peers are added as unchecked.
- Lookup Requests are retransmitted after 60 seconds of inactivity.
- Peers are removed after 10 minutes without a response.

## Bootstrap

Peer discovery begins by sending a Lookup Request to a bootstrap node.
