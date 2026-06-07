## ICMP P2P
A simple p2p built on top of ICMP Echo Request and Echo Reply packets.

## Features
1. Discovers peers through a bootstrap node.
2. Expands the peer list using information received from other peers.
3. Automatically verifies newly discovered peers.
4. Periodically refreshes peer information.
5. Removes inactive peers after a timeout period.
6. Exchanges peer information through ICMP payloads.

## Protocol
**Lookup Request (type: 0)**   
   
`[type (1 byte)][free_slots (1 byte)][public key (32 bytes)][signature (64 bytes)`
* type: Protocol identifier
* free_slots: Number of available peer slots

**Lookup Response (type: 0)**   
   
`[type (1 byte)][free_slots (1 byte)][peer_count (1 byte)][peers (n bytes)][public key (32 bytes)][signature (64 bytes)]`
* type: Protocol identifier
* free_slots: Number of available peer slots on the responding node
* peer_count: Number of peers included in the response
* peers: List of peer addresses

## Peer States
| State | Description |
|--------|-------------|
| unchecked | Newly discovered peer |
| checking | Peer verification in progress |
| checked | Verified peer |

## Peer Management
- Peer information is updated whenever a Lookup Response is received.
- Newly discovered peers are added as `unchecked`.
- Lookup Requests are retransmitted after 60 seconds of inactivity.
- Peers are removed after 10 minutes without a response.

## Bootstrap
Peer discovery begins by sending a Lookup Request to a bootstrap node.
