# `chirik` — encrypted voice group chat

> [!WARNING]
> Experimental and unaudited software. Use at your own risk.

`chirik` is a single-binary, IPv4/UDP voice chat application. An exchange introduces channel members. Clients prefer direct public/LAN UDP links and automatically fall back to an exchange-routed relay link when direct KEX does not complete promptly.

Direct and relayed paths use the same inner peer X25519/AES-256-GCM session. In fallback mode the exchange forwards opaque peer KEX, request, acknowledgement, and audio packets through each client's encrypted exchange session.

## Design choices

- PipeWire via `pipewire-pulse`, since implementing the native PipeWire protocol is a giant pain in the ass: SPA POD serialization, object/proxy state, ancillary FD passing, and shared-memory buffer management.
- Connectionless IPv4/UDP transport with a 1200-byte maximum datagram. The application protocol itself is stateful: it maintains encrypted sessions, sequence numbers, replay state, discovery entries, and TTLs.
- Direct public/LAN UDP is preferred. A delayed handle-routed UDP relay starts after a two-second direct window; the first authenticated path wins and removes competing candidates.
- Application payloads are encrypted after an unauthenticated X25519 exchange. Public keys are not pinned, so the protocol does not prevent an active man-in-the-middle attack.
- Audio packets are not retransmitted. KEX and registration requests are retried; audio uses small bounded buffers and real-time delivery.
- `exchange` and `chirp` modes use the same encrypted discovery engine and wire records. 
- Encryption: X25519 key agreement, HKDF-SHA-256 key derivation, and AES-256-GCM encrypted packets.
- Audio: 48 kHz mono ADPCM, 480 samples per packet, 100 packets per second. One encrypted stream is approximately 26.8 kB/s before IP/UDP headers and 29.6 kB/s including IPv4/UDP headers.
- Audio processing is limited to simple fades and packet-loss/underflow transition smoothing. Use an external processing pipeline when additional noise suppression is required.
- The application does not mix peers itself. Every peer gets a separate playback stream; PipeWire/Pulse performs final sink mixing.
- Muting clears captured frames but continues transmitting encoded silence, which maintains the selected direct or relay link.

## Requirements

- Go 1.24 or newer.
- A PipeWire Pulse-compatible audio server.
- Bidirectional UDP reachability between the exchange and every client.
- Client-to-client UDP reachability for preferred direct audio; otherwise sufficient exchange bandwidth for relayed fallback streams.

## Build

```sh
make
```

This produces one binary:

```text
./chirik
```

The Makefile builds with `CGO_ENABLED=0`.

## Run an exchange

```sh
./chirik exchange 0:7777
```

`0:7777` is normalized to `0.0.0.0:7777` for the IPv4 listener.

The exchange generates an ephemeral X25519 keypair at startup, prints the public key to stderr, and keeps the private key only in memory. Restarting the exchange changes the key. No persistent key material is created or loaded.

## Join a channel

```sh
./chirik chirp alice@exchange.example:7777/team-room
```

Optional audio-device selection:

```sh
./chirik chirp alice@exchange.example:7777/team-room \
  --source=<pulse-source-name> \
  --sink=<pulse-sink-name>
```

Target format:

```text
<handle>@<exchange-host>:<exchange-port>/<channel>
```

Rules:

- Handles contain only ASCII letters and digits and are 1–255 bytes long.
- Channels are nonempty strings. `/` and spaces are allowed; quote the target when required by the shell.
- The encoded handle, local IPv4 endpoint, and channel request must fit the 894-byte relay-safe request limit.
- Networking is IPv4-only.
- An unguessable channel suffix can reduce unwanted discovery, but the channel is visible to the exchange and is not a substitute for authenticated identities or key verification.

Interactive controls:

```text
m  toggle microphone mute
q  quit
```

`Ctrl-C` and `SIGTERM` also stop the process.

## Discovery behavior

Both modes use the same discovery engine:

- A valid request contains the sender handle, route-selected local IPv4 address, listening UDP port, and channel.
- The exchange registers or refreshes the sender and replies to the joining client with an empty peer list.
- The exchange announces only the joining/changed handle's public and LAN endpoint records to existing clients.
- Each authoritative endpoint record starts immediate direct KEX. One delayed relay candidate is also created for the handle.
- If no direct path authenticates within two seconds, KEX begins through encrypted type `0x08` relay messages addressed by target handle.
- The exchange validates that source and target are registered in the same channel, replaces the target handle with the source handle, and forwards the opaque inner packet.
- Direct and relay candidates race after the fallback delay. The first path to complete encrypted peer traffic is retained; all other candidates for that handle are removed.
- Peer requests, empty acknowledgements, and audio remain encrypted by the inner peer session on both paths.
- Exchange entries use a 24-hour TTL. Selected direct or relay peer links use a one-minute liveness TTL maintained by audio traffic.

## Security boundaries

Clients use one AES-256-GCM session with the exchange and separate X25519-derived AES-256-GCM sessions with peers. The exchange can see handles, channels, public/local endpoints, relay source and target handles, packet sizes, timing, and peer KEX public keys. It forwards peer request/audio ciphertext without decrypting the inner peer session. KEX packets remain unauthenticated and public keys are not pinned, so the exchange or an active attacker can perform a man-in-the-middle attack. Handles are labels, not cryptographic identities.

## Validation

```sh
make test
make lint
go test -race ./...
```

Live audio integration tests are opt-in:

```sh
CHIRIK_AUDIO_INTEGRATION=1 go test ./internal/audio
```

Remove generated binaries with:

```sh
make clean
```
