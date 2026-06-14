## ICMP P2P
An ICMP based network protocol for peer discovery, peer exchange, and signed message propagation.

## Features
1. Discovers peers through bootstrap nodes.
2. Exchanges peer information between peers.
3. Verifies discovered peers using Ed25519 signatures.
4. Maintains a peer table with periodic refresh and timeout handling.
5. Broadcasts signed messages through the network.
6. Maintains trust scores for peer selection.

## Protocol
**Lookup Request (ICMP Echo Request)**   
`[type (1 byte)][want (1 byte)][free_slots (1 byte)][public_key (32 bytes)][signature (64 bytes)]`
* type: Protocol identifier.
* want: Number of peer addresses requested.
* free_slots: Number of available peer slots on the sender.
* public_key: Sender public key.
* signature: Ed25519 signature over `[type][want][free_slots][public_key]`.

**Lookup Response (ICMP Echo Reply)**   
`[type (1 byte)][free_slots (1 byte)][peers (4*n bytes)][public_key (32 bytes)][signature (64 bytes)]`
* type: Protocol identifier.
* free_slots: Number of available peer slots on the sender.
* peers: List of IPv4 peer addresses.
* public_key: Sender public key.
* signature: Ed25519 signature over `[type][free_slots][peers][public_key]`.

**Message (ICMP Echo Request)**    
`[type (1 byte)][message (n bytes)][fanout (1 byte)][expiry (8 bytes)][signature (64 bytes)]`
* type: Protocol identifier.
* message: Message payload.
* fanout: Maximum rebroadcast targets. A value of 0 broadcasts to all checked peers.
* expiry: Big endian Unix timestamp.
* signature: Ed25519 signature over `[type][message][fanout][expiry]`.
The first 8 bytes of the verified signature are used internally as a message identifier for duplicate suppression.

## Message Processing
1. Receive a Message packet.
2. Verify the message signature using the configured administrator public key.
3. Discard expired messages.
4. Derive a message identifier from the first 8 bytes of the verified signature.
5. Discard messages that have already been processed.
6. Print the message payload.
7. Rebroadcast the message according to the fanout value.

## Peer States
| State | Description |
|---------|-------------|
| unchecked | Discovered but not verified |
| checking | Lookup Request sent and waiting for a response |
| checked | Verified peer |

## Trust
- New peers start with a default trust score.
- Verified peers gain trust.
- Peers that provide valid peer information gain trust.
- Peers that provide inactive peers lose trust.
- Peers below the minimum trust threshold are not shared.
- Peers reaching the ban threshold are removed.

## Peer Selection
Lookup Responses include peers that:
- are in the `checked` state,
- are not bootstrap peers,
- have trust above the minimum trust threshold,
- are not the requesting peer.
  
Peers with available slots are preferred before peers with no free slots.

## Peer Management
- Newly discovered peers are added as `unchecked`.
- Unchecked peers are verified using Lookup Requests.
- Peer information is updated when a valid Lookup Request or Lookup Response is received.
- Lookup Requests are sent periodically to known peers.
- Unresponsive peers are removed after the configured timeout.
- Banned peers are removed from the peer table.

## Bootstrap
Peer discovery begins by sending Lookup Requests to one or more bootstrap nodes.
