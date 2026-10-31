package main

import (
	"errors"
	"net"
	"time"

	"github.com/reconquest/karma-go"

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
	string,
	discoveryRecipient,
	int,
	int,
	[]proto.PeerRecord,
)

type discoveryEngine struct {
	conn       *net.UDPConn
	policy     discoveryPolicy
	records    func(string, proto.Handle) []proto.PeerRecord
	recipients func(string) []discoveryRecipient
	packetSent discoveryPacketSent
}

func (engine *discoveryEngine) reply(
	channel string,
	recipient discoveryRecipient,
) error {
	return engine.send(channel, recipient)
}

func (engine *discoveryEngine) broadcast(channel string) error {
	return engine.broadcastExcept(channel, discoveryRecipient{})
}

func (engine *discoveryEngine) broadcastExcept(
	channel string,
	exclude discoveryRecipient,
) error {
	var failures []error

	for _, recipient := range engine.recipients(channel) {
		if exclude.session != nil && recipient.session == exclude.session {
			continue
		}

		err := engine.send(channel, recipient)
		if err != nil {
			failures = append(failures, err)
		}
	}

	return errors.Join(failures...)
}

func (engine *discoveryEngine) broadcastRecordsExcept(
	channel string,
	exclude discoveryRecipient,
	records []proto.PeerRecord,
) error {
	var failures []error

	for _, recipient := range engine.recipients(channel) {
		if exclude.session != nil && recipient.session == exclude.session {
			continue
		}

		err := engine.sendRecords(channel, recipient, records)
		if err != nil {
			failures = append(failures, err)
		}
	}

	return errors.Join(failures...)
}

func discoveryMerge(
	records []proto.PeerRecord,
	apply func(proto.PeerRecord) bool,
) bool {
	changed := false

	for _, record := range records {
		if apply(record) {
			changed = true
		}
	}

	return changed
}

func (engine *discoveryEngine) send(
	channel string,
	recipient discoveryRecipient,
) error {
	return engine.sendRecords(
		channel,
		recipient,
		engine.records(channel, recipient.handle),
	)
}

func (engine *discoveryEngine) sendRecords(
	channel string,
	recipient discoveryRecipient,
	records []proto.PeerRecord,
) error {
	context := karma.
		Describe("channel", channel).
		Describe("to_addr", recipient.addr).
		Describe("to_handle", recipient.handle)
	if recipient.addr == nil || recipient.session == nil {
		return context.Format(nil, "peer-list recipient unavailable")
	}

	payloads, ok := proto.PeerListSplit(records)
	if !ok {
		return context.Format(nil, "encode peer list")
	}

	for index, payload := range payloads {
		packet, err := recipient.session.Seal(
			engine.policy.peerListType(),
			payload,
		)
		if err != nil {
			return context.Format(err, "encrypt peer list")
		}

		err = datagramSend(engine.conn, recipient.addr, packet)
		if err != nil {
			return context.Format(err, "send peer list")
		}

		if engine.packetSent != nil {
			sentRecords, valid := proto.PeerListParse(payload)
			if !valid {
				return context.Format(nil, "parse sent peer list")
			}

			engine.packetSent(
				channel,
				recipient,
				index+1,
				len(payloads),
				sentRecords,
			)
		}
	}

	return nil
}

func discoverySessionNew(
	pair *sessioncrypto.KeyPair,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	salt []byte,
) (*sessioncrypto.Session, error) {
	keys, err := pair.Derive(peerPublic[:], salt)
	if err != nil {
		return nil, karma.Format(err, "derive discovery session keys")
	}

	session, err := sessioncrypto.SessionNew(keys)
	if err != nil {
		return nil, karma.Format(err, "create discovery session")
	}

	return session, nil
}
