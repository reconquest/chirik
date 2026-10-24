package main

import (
	"net"
	"time"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

type discoveryPolicy struct {
	audio bool
	ttl   time.Duration
}

func (p discoveryPolicy) peerListType() byte {
	if p.audio {
		return proto.Type_PeerListAudio
	}

	return proto.Type_PeerList
}

type discoveryRecipient struct {
	addr    *net.UDPAddr
	handle  proto.Handle
	session *sessioncrypto.Session
}

type discoveryPacketSent func(
	channel string,
	recipient discoveryRecipient,
	packet int,
	packets int,
	records []proto.PeerRecord,
)

type discoveryEngine struct {
	conn       *net.UDPConn
	policy     discoveryPolicy
	records    func(channel string, exclude proto.Handle) []proto.PeerRecord
	recipients func(channel string) []discoveryRecipient
	packetSent discoveryPacketSent
}

func (e *discoveryEngine) reply(channel string, recipient discoveryRecipient) bool {
	return e.send(channel, recipient)
}

func (e *discoveryEngine) request(
	payload []byte,
) (proto.Handle, string, *net.UDPAddr, bool) {
	return proto.RequestParse(payload)
}

func (e *discoveryEngine) announce(
	channel string,
	recipient discoveryRecipient,
	changed bool,
) bool {
	replied := e.reply(channel, recipient)
	if changed {
		e.broadcastExcept(channel, recipient)
	}

	return replied
}

func (e *discoveryEngine) broadcast(channel string) {
	e.broadcastExcept(channel, discoveryRecipient{})
}

func (e *discoveryEngine) broadcastExcept(
	channel string,
	exclude discoveryRecipient,
) {
	for _, recipient := range e.recipients(channel) {
		if exclude.session != nil && recipient.session == exclude.session {
			continue
		}
		e.send(channel, recipient)
	}
}

func (e *discoveryEngine) broadcastRecordsExcept(
	channel string,
	exclude discoveryRecipient,
	records []proto.PeerRecord,
) {
	for _, recipient := range e.recipients(channel) {
		if exclude.session != nil && recipient.session == exclude.session {
			continue
		}
		e.sendRecords(channel, recipient, records)
	}
}

func (e *discoveryEngine) decode(payload []byte) ([]proto.PeerRecord, bool) {
	return proto.PeerListParse(payload)
}

func (e *discoveryEngine) merge(
	records []proto.PeerRecord,
	apply func(proto.PeerRecord) bool,
) (changed bool) {
	for _, record := range records {
		if apply(record) {
			changed = true
		}
	}

	return changed
}

func (e *discoveryEngine) send(channel string, recipient discoveryRecipient) bool {
	return e.sendRecords(channel, recipient, e.records(channel, recipient.handle))
}

func (e *discoveryEngine) sendRecords(
	channel string,
	recipient discoveryRecipient,
	records []proto.PeerRecord,
) bool {
	if recipient.addr == nil || recipient.session == nil {
		return false
	}

	payloads, ok := proto.PeerListSplit(records)
	if !ok {
		return false
	}

	for i, payload := range payloads {
		packet, err := recipient.session.Seal(e.policy.peerListType(), payload)
		if err != nil || datagramSend(e.conn, recipient.addr, packet) != nil {
			return false
		}

		if e.packetSent != nil {
			records, valid := proto.PeerListParse(payload)
			if !valid {
				return false
			}
			e.packetSent(channel, recipient, i+1, len(payloads), records)
		}
	}

	return true
}

func discoverySessionNew(
	pair *sessioncrypto.KeyPair,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	salt []byte,
) (*sessioncrypto.Session, error) {
	keys, err := pair.Derive(peerPublic[:], salt)
	if err != nil {
		return nil, err
	}

	return sessioncrypto.SessionNew(keys)
}

func discoveryKEXSend(
	conn *net.UDPConn,
	addr *net.UDPAddr,
	pair *sessioncrypto.KeyPair,
) bool {
	return datagramSend(conn, addr, proto.KEX(pair.Public())) == nil
}
