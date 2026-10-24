package main

import (
	"errors"
	"time"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

const relayLinkPrefix = "\x00relay\x00"

func relayLinkKey(handle proto.Handle) string { return relayLinkPrefix + string(handle) }

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

func (m *manager) relayLink(handle proto.Handle) *link {
	for _, item := range m.links[relayLinkKey(handle)] {
		if item.relay {
			return item
		}
	}
	return nil
}

func (m *manager) relayCandidateAdd(
	handle proto.Handle,
	now time.Time,
	delay time.Duration,
) bool {
	if handle == m.cfg.handle || !proto.HandleValid(handle) {
		return false
	}
	existing := m.relayLink(handle)
	if existing != nil && !existing.stateActive() {
		return false
	}

	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return false
	}
	start := now.Add(delay)
	if existing != nil {
		existing.pair = pair
		existing.peerPublic = [sessioncrypto.PublicKeyBytes]byte{}
		existing.voice = nil
		existing.state = linkState_KEX
		existing.initiated = true
		existing.audioEligible = false
		existing.responseReceived = false
		existing.kexNext = start
		existing.kexDeadline = start.Add(proto.KEXTimeout)
		existing.requestNext = time.Time{}
		existing.responseDeadline = time.Time{}
		existing.requestAttempts = 0
		existing.lastKEXSent = time.Time{}
		if delay == 0 {
			m.linkKEXSend(existing, now)
		}
		return true
	}

	item := &link{
		addr:           addrCopy(m.cfg.peerex),
		pair:           pair,
		expectedHandle: handle,
		expectedKnown:  true,
		state:          linkState_KEX,
		initiated:      true,
		relay:          true,
		kexNext:        start,
		kexDeadline:    start.Add(proto.KEXTimeout),
	}
	m.seen[handle] = struct{}{}
	m.linkAdd(item)
	if delay == 0 {
		m.linkKEXSend(item, now)
	}

	return true
}

func (m *manager) relaySend(target proto.Handle, inner []byte) error {
	payload, ok := proto.Relay(target, inner)
	if !ok {
		return errors.New("relay packet exceeds protocol limit")
	}

	peerex := m.activePeerex()
	if peerex == nil || peerex.voice == nil {
		return errors.New("peer exchange unavailable")
	}
	packet, err := peerex.voice.Seal(proto.Type_Relay, payload)
	if err != nil {
		return err
	}
	return datagramSend(m.t.conn, peerex.addr, packet)
}

func (m *manager) activePeerex() *link {
	for _, item := range m.links[m.cfg.peerex.String()] {
		if item.peerex && item.stateActive() && item.voice != nil {
			return item
		}
	}
	return nil
}

func (m *manager) relayPacketHandle(source proto.Handle, inner []byte) bool {
	if source == m.cfg.handle || !relayInnerValid(inner) {
		return false
	}
	if public, ok := proto.KEXParse(inner); ok {
		m.relayKEXHandle(source, public, time.Now())
		return true
	}

	item := m.relayLink(source)
	if item == nil || item.voice == nil {
		return false
	}
	kind, seq, payload, err := item.voice.Open(inner)
	if err != nil {
		if !errors.Is(err, sessioncrypto.ErrReplay) {
			m.counters.badAuth.Add(1)
		}
		return false
	}
	return m.encryptedHandle(item, kind, seq, payload, inner)
}

func (m *manager) relayKEXHandle(
	handle proto.Handle,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
) {
	item := m.relayLink(handle)
	if item != nil && item.voice != nil && item.peerPublic == peerPublic {
		if now.Sub(item.lastKEXSent) >= proto.KEXInterval {
			m.linkKEXSend(item, now)
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
			addr:           addrCopy(m.cfg.peerex),
			pair:           pair,
			expectedHandle: handle,
			expectedKnown:  true,
			state:          linkState_Request,
			relay:          true,
			kexDeadline:    now.Add(proto.KEXTimeout),
		}
		m.linkAdd(item)
		m.linkKEXSend(item, now)
	}

	m.linkKEXComplete(item, peerPublic, now, kexReply)
}

func (m *manager) relayPeerListSend(item *link) bool {
	payload, ok := proto.PeerList(nil)
	if !ok {
		return false
	}
	packet, err := item.voice.Seal(proto.Type_PeerListAudio, payload)
	if err != nil {
		return false
	}
	target := item.expectedHandle
	if item.handleKnown {
		target = item.handle
	}
	return m.relaySend(target, packet) == nil
}
