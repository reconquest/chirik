package main

import (
	"net"
	"time"

	"github.com/reconquest/karma-go"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

type relayRoute struct {
	source  proto.Handle
	target  proto.Handle
	channel string
	addr    *net.UDPAddr
	voice   *sessioncrypto.Session
}

func (server *exchangeServer) relayHandle(
	session *exchangeSession,
	payload []byte,
	now time.Time,
) {
	targetHandle, inner, valid := proto.RelayParse(payload)
	if !valid || !relayInnerValid(inner) {
		return
	}

	route, valid := server.relayRouteFor(session, targetHandle, now)
	if !valid {
		return
	}

	delivery, valid := proto.Relay(route.source, inner)
	if !valid {
		return
	}

	packet, err := route.voice.Seal(proto.Type_Relay, delivery)
	if err != nil {
		server.logger.Print("ERROR ", karma.
			Describe("type", "RELAY").
			Describe("to_addr", route.addr).
			Format(err, "encrypt relay packet"),
		)

		return
	}

	err = datagramSend(server.conn, route.addr, packet)
	if err != nil {
		server.logger.Print("ERROR ", karma.
			Describe("type", "RELAY").
			Describe("to_addr", route.addr).
			Format(err, "send relay packet"),
		)

		return
	}

	if relayInnerLoggable(inner) {
		server.logger.Print("INFO ", karma.
			Describe("type", "RELAY").
			Describe("channel", route.channel).
			Describe("from_handle", route.source).
			Describe("to_handle", route.target).
			Describe("to_addr", route.addr).
			Describe("inner_bytes", len(inner)).
			Format(nil, "packet sent"),
		)
	}
}

func (server *exchangeServer) relayRouteFor(
	session *exchangeSession,
	targetHandle proto.Handle,
	now time.Time,
) (relayRoute, bool) {
	server.mu.Lock()
	defer server.mu.Unlock()

	if !server.sessionContains(session) || !session.registered ||
		targetHandle == session.handle {
		return relayRoute{}, false
	}

	target := server.entries[session.channel][targetHandle]
	if target == nil || target.session == nil || target.session.voice == nil {
		return relayRoute{}, false
	}

	session.seen = now

	return relayRoute{
		source:  session.handle,
		target:  targetHandle,
		channel: session.channel,
		addr:    addrCopy(target.addr),
		voice:   target.session.voice,
	}, true
}

func relayInnerValid(packet []byte) bool {
	if _, valid := proto.KEXParse(packet); valid {
		return true
	}

	kind, _, _, _, valid := proto.EnvelopeParse(packet)
	if !valid {
		return false
	}

	switch kind {
	case proto.Type_Request, proto.Type_PeerListAudio, proto.Type_Audio:
		return true

	default:
		return false
	}
}

func relayInnerLoggable(packet []byte) bool {
	if _, valid := proto.KEXParse(packet); valid {
		return true
	}

	kind, _, _, _, valid := proto.EnvelopeParse(packet)

	return valid && kind != proto.Type_Audio
}
