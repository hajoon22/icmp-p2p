## ICMP P2P
A simple P2P network built on top of ICMP Echo Request and Echo Reply packets.

## Features
1. Discovers peers through a bootstrap node.
2. Expands the peer list using information received from other peers.
3. Automatically verifies newly discovered peers.
4. Periodically refreshes peer information.
5. Removes inactive peers after a timeout period.
6. Exchanges peer information through ICMP payloads.
7. Broadcasts signed messages across the network.

## Protocol

### Lookup Request (type: 0)

`[type (1 byte)][free_slots (1 byte)][public_key (32 bytes)][signature (64 bytes)]`

* type: Protocol identifier.
* free_slots: Number of available peer slots.
* public_key: Node public key.
* signature: Ed25519 signature over `[type][free_slots][public_key]`.

### Lookup Response (type: 0)

`[type (1 byte)][free_slots (1 byte)][peer_count (1 byte)][peers (n bytes)][public_key (32 bytes)][signature (64 bytes)]`

* type: Protocol identifier.
* free_slots: Number of available peer slots on the responding node.
* peer_count: Number of peers included in the response.
* peers: List of peer addresses.
* public_key: Node public key.
* signature: Ed25519 signature over `[type][free_slots][peer_count][peers][public_key]`.

### Message (type: 1)

`[type (1 byte)][id (1 byte)][message (n bytes)][expiry (8 bytes)][signature (64 bytes)]`

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

## Peer Management

- Peer information is updated whenever a Lookup Response is received.
- Newly discovered peers are added as unchecked.
- Lookup Requests are retransmitted after 60 seconds of inactivity.
- Peers are removed after 10 minutes without a response.

## Bootstrap

Peer discovery begins by sending a Lookup Request to a bootstrap node.
