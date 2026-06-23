## ICMP P2P

A peer discovery, peer exchange, and signed message propagation protocol over ICMP.

## Features

* Discovers public UDP mappings using STUN.
* Discovers peers through bootstrap nodes.
* Exchanges peer information between peers.
* Verifies discovered peers using Ed25519 signatures.
* Maintains a peer table with periodic refresh and timeout handling.
* Broadcasts signed messages through the network.
* Maintains trust scores for peer selection.
* Keeps the UDP NAT mapping alive periodically.

## NAT Traversal

This project uses ICMP NAT traversal from:
https://github.com/hajoon22/icmp-nat-traversal

1. Create and maintain a UDP mapping using STUN.
2. Send ICMP Destination Unreachable packets referencing the mapped UDP flow.
3. Carry protocol payloads after the quoted IPv4 header and UDP header.
4. Receive protocol payloads through the NAT mapping.

**Verified Environments**   
- Linux netfilter NAT (Ubuntu, Kernel 7.0.0-15-generic)
- TELUS Mobility LTE/5G
- TELUS Wi-Fi Hub (Firmware v3.26.01 build11)


## Protocol

Protocol payloads are carried inside ICMP packets.

`[ICMP Header][IPv4 header][UDP header][protocol payload]`

### Lookup Request

`[type (1 byte)][nonce (2 bytes)][mapped_port (2 bytes)][want (1 byte)][free_slots (1 byte)][public_key (32 bytes)][signature (64 bytes)]`

* `type` (1 byte): Protocol identifier.
* `nonce` (2 bytes): Request nonce used to match a Lookup Response.
* `mapped_port` (2 bytes): Sender public UDP mapped port.
* `want` (1 byte): Number of peer entries requested.
* `free_slots` (1 byte): Number of available peer slots on the sender.
* `public_key` (32 bytes): Sender public key.
* `signature` (64 bytes): Ed25519 signature over `[type][nonce][mapped_port][want][free_slots][public_key]`.

### Lookup Response

`[type (1 byte)][nonce (2 bytes)][free_slots (1 byte)][peers (6*n bytes)][public_key (32 bytes)][signature (64 bytes)]`

* `type` (1 byte): Protocol identifier.
* `nonce` (2 bytes): Nonce copied from the corresponding Lookup Request.
* `free_slots` (1 byte): Number of available peer slots on the sender.
* `peers` (6*n bytes): List of IPv4 peer entries.
* `peer entry`: `[ipv4_address (4 bytes)][mapped_port (2 bytes)]`.
* `public_key` (32 bytes): Sender public key.
* `signature` (64 bytes): Ed25519 signature over `[type][nonce][free_slots][peers][public_key]`.

### Message

`[type (1 byte)][message (n bytes)][fanout (1 byte)][expiry (8 bytes)][signature (64 bytes)]`

* `type` (1 byte): Protocol identifier.
* `message` (n bytes): Message payload.
* `fanout` (1 byte): Maximum rebroadcast targets.
* `expiry` (8 bytes): Big endian Unix timestamp.
* `signature` (64 bytes): Ed25519 signature over `[type][message][fanout][expiry]`.

The first 8 bytes of the verified signature are used internally as a message identifier for duplicate suppression.

## Message Processing

1. Receive a Message packet.
2. Verify the message signature using the configured administrator public key.
3. Discard expired messages.
4. Derive a message identifier from the first 8 bytes of the verified signature.
5. Discard messages that have already been processed.
6. Print the message payload.
7. Rebroadcast the message according to the fanout value.

## Peer Management

Peer discovery begins by sending Lookup Requests to one or more bootstrap nodes.

Peers can be in one of three states:

* `unchecked`: Discovered but not verified.
* `checking`: Lookup Request sent and waiting for a response.
* `checked`: Verified peer.

Newly discovered peers are added as unchecked.
Unchecked peers are verified using Lookup Requests.
Lookup Responses are accepted only when the response nonce matches the saved request nonce.
Peer information is updated when a valid Lookup Request or Lookup Response is received.

New peers start with a default trust score.
Verified peers gain trust.
Peers that provide valid peer information gain trust.
Peers that provide inactive peers lose trust.

Shared peers:

* are in the checked state,
* are not bootstrap peers,
* have trust above the minimum trust threshold,
* are not the requesting peer.

Peers with available slots are preferred before peers with no free slots.

Lookup Requests are sent periodically to known peers.
Unresponsive peers are removed after the configured timeout.
Peers reaching the ban threshold are removed from the peer table.

The UDP NAT mapping is kept alive periodically through the STUN connected UDP socket.
