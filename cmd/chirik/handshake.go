package main

import (
	"encoding/base64"
	"errors"
	"net"
	"time"

	"github.com/reconquest/karma-go"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

func (client *client) initialLink() (*link, error) {
	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return nil, karma.Format(err, "generate key pair")
	}

	client.output.lineWrite(karma.
		Describe("exchange", client.cfg.peerex).
		Describe("local_udp", client.t.conn.LocalAddr()).
		Format(nil, "connecting to exchange"),
	)

	err = client.output.writeError()
	if err != nil {
		return nil, karma.Format(err, "write exchange endpoint")
	}

	return &link{
		addr:        addrCopy(client.cfg.peerex),
		pair:        pair,
		state:       linkState_KEX,
		initiated:   true,
		peerex:      true,
		bootstrap:   true,
		kexDeadline: time.Now().Add(proto.KEXTimeout),
	}, nil
}

func (client *client) packetHandle(packet datagram) {
	if public, ok := proto.KEXParse(packet.data); ok {
		client.kexHandle(packet.addr, public, time.Now())

		return
	}

	links := append([]*link(nil), client.links[packet.addr.String()]...)
	authFailed := false

	for _, item := range links {
		if item.voice == nil {
			continue
		}

		kind, seq, payload, err := item.voice.Open(packet.data)
		if err != nil {
			if !errors.Is(err, sessioncrypto.ErrReplay) {
				authFailed = true
			}

			continue
		}

		client.encryptedHandle(item, kind, seq, payload, packet.data)

		return
	}

	if authFailed {
		client.counters.badAuth.Add(1)
	}
}

func (client *client) kexHandle(
	addr *net.UDPAddr,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
) {
	if client.kexEstablishedReply(addr, peerPublic, now) {
		return
	}

	item := client.kexPending(addr)
	kexReply := item != nil

	if item == nil {
		item = client.kexPassiveAdd(addr, now)
		if item == nil {
			return
		}
	}

	client.linkKEXComplete(item, peerPublic, now, kexReply)
}

func (client *client) kexEstablishedReply(
	addr *net.UDPAddr,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
) bool {
	for _, item := range client.links[addr.String()] {
		if item.voice == nil || item.peerPublic != peerPublic {
			continue
		}

		if now.Sub(item.lastKEXSent) >= proto.KEXInterval {
			err := client.linkKEXSend(item, now)
			if err != nil {
				client.linkRemove(item, err.Error())
			}
		}

		return true
	}

	return false
}

func (client *client) kexPending(addr *net.UDPAddr) *link {
	for _, item := range client.links[addr.String()] {
		if item.state == linkState_KEX &&
			item.peerPublic == ([sessioncrypto.PublicKeyBytes]byte{}) {
			return item
		}
	}

	return nil
}

func (client *client) kexPassiveAdd(addr *net.UDPAddr, now time.Time) *link {
	if udpAddrEqual(addr, client.cfg.peerex) {
		return nil
	}

	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return nil
	}

	item := &link{
		addr:        addrCopy(addr),
		pair:        pair,
		state:       linkState_Request,
		kexDeadline: now.Add(proto.KEXTimeout),
	}
	client.linkAdd(item)

	err = client.linkKEXSend(item, now)
	if err != nil {
		client.linkRemove(item, err.Error())

		return nil
	}

	return item
}

func (client *client) linkKEXComplete(
	item *link,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
	kexReply bool,
) {
	salt := client.cfg.channelKey[:]

	if item.peerex {
		zero := [32]byte{}

		salt = zero[:]
	}

	voice, err := discoverySessionNew(item.pair, peerPublic, salt)
	if err != nil {
		client.linkFail(item, karma.Format(err, "derive session keys"))

		return
	}

	item.peerPublic = peerPublic
	item.voice = voice
	item.lastSeen = now
	item.state = linkState_Request
	item.responseDeadline = now.Add(proto.ResponseTimeout)

	publicKey := base64.StdEncoding.EncodeToString(peerPublic[:])

	client.output.lineWrite(karma.
		Describe("peer", linkEndpoint(item)).
		Describe("public_key", publicKey).
		Format(nil, "peer key received"),
	)

	if kexReply {
		sendErr := client.linkKEXSend(item, now)
		if sendErr != nil {
			client.linkFail(item, sendErr)

			return
		}
	}

	if !item.peerex || item.initiated {
		requestErr := client.linkRequestSend(item, now)
		if requestErr != nil {
			client.linkFail(item, requestErr)
		}
	}
}

func (client *client) encryptedHandle(
	item *link,
	kind byte,
	seq uint64,
	payload []byte,
	packet []byte,
) bool {
	now := time.Now()
	if !client.encryptedPayloadHandle(item, kind, seq, payload, now) {
		return false
	}

	item.lastSeen = now
	item.counters.received.Add(1)
	item.counters.receivedBytes.Add(uint64(len(packet)))
	client.counters.received.Add(1)
	client.counters.receivedBytes.Add(uint64(len(packet)))

	return true
}

func (client *client) encryptedPayloadHandle(
	item *link,
	kind byte,
	seq uint64,
	payload []byte,
	now time.Time,
) bool {
	switch kind {
	case proto.Type_Request:
		return !item.peerex && client.requestHandle(item, payload, now)

	case proto.Type_PeerList:
		return item.peerex && client.peerListHandle(item, payload, false, now)

	case proto.Type_PeerListAudio:
		return !item.peerex && client.peerListHandle(item, payload, true, now)

	case proto.Type_Audio:
		return client.audioReceive(item, seq, payload, now)

	case proto.Type_Relay:
		return client.relayEncryptedHandle(item, payload)

	default:
		return false
	}
}

func (client *client) relayEncryptedHandle(item *link, payload []byte) bool {
	if !item.peerex {
		return false
	}

	source, inner, ok := proto.RelayParse(payload)

	return ok && client.relayPacketHandle(source, inner)
}

func (client *client) requestHandle(
	item *link,
	payload []byte,
	now time.Time,
) bool {
	handle, channel, _, ok := proto.RequestParse(payload)
	if !ok || channel != client.cfg.channel {
		return false
	}

	if item.expectedKnown && handle != item.expectedHandle {
		return false
	}

	membershipChanged := !item.stateActive() || !item.audioEligible

	item.handle = handle
	item.handleKnown = true

	err := client.linkPromote(item, now)
	if err != nil {
		client.linkFail(item, err)

		return false
	}

	item.audioEligible = true

	err = client.peerListAnnounce(item, membershipChanged)
	if err != nil {
		client.linkFail(item, err)

		return false
	}

	client.markReady(item)

	return true
}

func (client *client) peerListHandle(
	item *link,
	payload []byte,
	audioPeer bool,
	now time.Time,
) bool {
	records, ok := proto.PeerListParse(payload)
	if !ok || (item.relay && len(records) != 0) {
		return false
	}

	peerListIdentity(item)

	membershipChanged, err := client.peerListPromote(item, audioPeer, now)
	if err != nil {
		client.linkFail(item, err)

		return false
	}

	client.peerListExchangeActivate(item)

	item.responseReceived = true

	listChanged := client.peerListMerge(item, records, now, membershipChanged)
	client.markReady(item)

	if listChanged && !item.peerex {
		client.peerListBroadcast()
	}

	return true
}

func peerListIdentity(item *link) {
	if !item.expectedKnown {
		return
	}

	item.handle = item.expectedHandle
	item.handleKnown = true
}

func (client *client) peerListPromote(
	item *link,
	audioPeer bool,
	now time.Time,
) (bool, error) {
	membershipChanged := audioPeer &&
		(!item.stateActive() || !item.audioEligible)
	if !audioPeer {
		return membershipChanged, nil
	}

	err := client.linkPromote(item, now)
	if err != nil {
		return false, err
	}

	item.audioEligible = true

	return membershipChanged, nil
}

func (client *client) peerListExchangeActivate(item *link) {
	if !item.peerex {
		return
	}

	recovered := client.peerexRecoveryRequired

	item.state = linkState_Active
	item.requestAttempts = 0
	item.requestNext = time.Time{}
	item.responseDeadline = time.Time{}
	client.peerexRecoveryRequired = false
	client.peerexRecoveryStarted = false

	if recovered && client.logger != nil {
		client.logger.Print("INFO exchange connection recovered")
	}
}

func (client *client) peerListMerge(
	item *link,
	records []proto.PeerRecord,
	now time.Time,
	membershipChanged bool,
) bool {
	if item.relay {
		return false
	}

	changed := discoveryMerge(
		records,
		func(record proto.PeerRecord) bool {
			return client.candidateAdd(record, item.peerex, now)
		},
	)

	return changed || membershipChanged
}
