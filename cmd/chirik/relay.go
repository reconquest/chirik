package main

import (
	"errors"
	"time"

	"github.com/reconquest/karma-go"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

const relayLinkPrefix = "\x00relay\x00"

func relayLinkKey(
	handle proto.Handle,
) string {
	return relayLinkPrefix + string(handle)
}

func linkKey(item *link) string {
	if item.relay {
		if item.handleKnown {
			return relayLinkKey(item.handle)
		}

		return relayLinkKey(item.expectedHandle)
	}

	return item.addr.String()
}

func linkEndpoint(item *link) string {
	if item.relay {
		return "relay"
	}

	return item.addr.String()
}

func (client *client) relayLink(handle proto.Handle) *link {
	for _, item := range client.links[relayLinkKey(handle)] {
		if item.relay {
			return item
		}
	}

	return nil
}

func (client *client) relayCandidateAdd(
	handle proto.Handle,
	now time.Time,
	delay time.Duration,
) bool {
	if handle == client.cfg.handle || !proto.HandleValid(handle) {
		return false
	}

	existing := client.relayLink(handle)
	if existing != nil && !existing.stateActive() {
		return false
	}

	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return false
	}

	start := now.Add(delay)
	if existing != nil {
		relayCandidateReset(existing, pair, start)

		return client.relayCandidateSend(existing, now, delay)
	}

	item := &link{
		addr:           addrCopy(client.cfg.peerex),
		pair:           pair,
		expectedHandle: handle,
		expectedKnown:  true,
		state:          linkState_KEX,
		initiated:      true,
		relay:          true,
		kexNext:        start,
		kexDeadline:    start.Add(proto.KEXTimeout),
	}

	client.seen[handle] = struct{}{}
	client.linkAdd(item)

	return client.relayCandidateSend(item, now, delay)
}

func relayCandidateReset(
	item *link,
	pair *sessioncrypto.KeyPair,
	start time.Time,
) {
	item.pair = pair
	item.peerPublic = [sessioncrypto.PublicKeyBytes]byte{}
	item.voice = nil
	item.state = linkState_KEX
	item.initiated = true
	item.audioEligible = false
	item.responseReceived = false
	item.kexNext = start
	item.kexDeadline = start.Add(proto.KEXTimeout)
	item.requestNext = time.Time{}
	item.responseDeadline = time.Time{}
	item.requestAttempts = 0
	item.lastKEXSent = time.Time{}
}

func (client *client) relayCandidateSend(
	item *link,
	now time.Time,
	delay time.Duration,
) bool {
	if delay != 0 {
		return true
	}

	err := client.linkKEXSend(item, now)
	if err != nil {
		client.linkRemove(item, err.Error())

		return false
	}

	return true
}

func (client *client) relaySend(target proto.Handle, inner []byte) error {
	payload, ok := proto.Relay(target, inner)
	if !ok {
		return errors.New("relay packet exceeds protocol limit")
	}

	peerex := client.activePeerex()
	if peerex == nil || peerex.voice == nil {
		return errors.New("peer exchange unavailable")
	}

	packet, err := peerex.voice.Seal(proto.Type_Relay, payload)
	if err != nil {
		return karma.Format(err, "encrypt relay packet")
	}

	return datagramSend(client.t.conn, peerex.addr, packet)
}

func (client *client) activePeerex() *link {
	for _, item := range client.links[client.cfg.peerex.String()] {
		if item.peerex && item.stateActive() && item.voice != nil {
			return item
		}
	}

	return nil
}

func (client *client) relayPacketHandle(
	source proto.Handle,
	inner []byte,
) bool {
	if source == client.cfg.handle || !relayInnerValid(inner) {
		return false
	}

	if public, ok := proto.KEXParse(inner); ok {
		client.relayKEXHandle(source, public, time.Now())

		return true
	}

	item := client.relayLink(source)
	if item == nil || item.voice == nil {
		return false
	}

	kind, seq, payload, err := item.voice.Open(inner)
	if err != nil {
		if !errors.Is(err, sessioncrypto.ErrReplay) {
			client.counters.badAuth.Add(1)
		}

		return false
	}

	return client.encryptedHandle(item, kind, seq, payload, inner)
}

func (client *client) relayKEXHandle(
	handle proto.Handle,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
) {
	item := client.relayLink(handle)
	if item != nil && item.voice != nil && item.peerPublic == peerPublic {
		if now.Sub(item.lastKEXSent) >= proto.KEXInterval {
			err := client.linkKEXSend(item, now)
			if err != nil {
				client.linkRemove(item, err.Error())
			}
		}

		return
	}

	kexReply := item != nil
	if item == nil {
		pair, err := sessioncrypto.KeyPairGenerate()
		if err != nil {
			return
		}

		item = &link{
			addr:           addrCopy(client.cfg.peerex),
			pair:           pair,
			expectedHandle: handle,
			expectedKnown:  true,
			state:          linkState_Request,
			relay:          true,
			kexDeadline:    now.Add(proto.KEXTimeout),
		}
		client.linkAdd(item)

		err = client.linkKEXSend(item, now)
		if err != nil {
			client.linkRemove(item, err.Error())

			return
		}
	}

	client.linkKEXComplete(item, peerPublic, now, kexReply)
}

func (client *client) relayPeerListSend(item *link) error {
	payload, ok := proto.PeerList(nil)
	if !ok {
		return karma.Format(nil, "encode relayed peer list")
	}

	packet, err := item.voice.Seal(proto.Type_PeerListAudio, payload)
	if err != nil {
		return karma.Format(err, "encrypt relayed peer list")
	}

	target := item.expectedHandle
	if item.handleKnown {
		target = item.handle
	}

	err = client.relaySend(target, packet)
	if err != nil {
		return karma.Format(err, "send relayed peer list")
	}

	return nil
}
