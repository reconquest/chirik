package main

import (
	"time"

	"chirik/internal/proto"
)

func (s *exchangeServer) relayHandle(
	session *exchangeSession,
	payload []byte,
	now time.Time,
) {
	targetHandle, inner, ok := proto.RelayParse(payload)
	if !ok || !relayInnerValid(inner) {
		return
	}

	s.mu.Lock()
	if !s.sessionContains(session) || !session.registered || targetHandle == session.handle {
		s.mu.Unlock()
		return
	}
	target := s.entries[session.channel][targetHandle]
	if target == nil || target.session == nil || target.session.voice == nil {
		s.mu.Unlock()
		return
	}
	var (
		sourceHandle = session.handle
		channel      = session.channel
		targetAddr   = addrCopy(target.addr)
		targetVoice  = target.session.voice
	)
	session.seen = now
	s.mu.Unlock()

	delivery, ok := proto.Relay(sourceHandle, inner)
	if !ok {
		return
	}
	packet, err := targetVoice.Seal(proto.Type_Relay, delivery)
	if err != nil || datagramSend(s.conn, targetAddr, packet) != nil {
		return
	}

	if relayInnerLoggable(inner) {
		s.logger.Printf(
			"SEND type=RELAY channel=%q from_handle=%q to_handle=%q to_addr=%s inner_bytes=%d",
			channel, sourceHandle, targetHandle, targetAddr, len(inner),
		)
	}
}

func relayInnerValid(packet []byte) bool {
	if _, ok := proto.KEXParse(packet); ok {
		return true
	}

	kind, _, _, _, ok := proto.EnvelopeParse(packet)
	if !ok {
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
	if _, ok := proto.KEXParse(packet); ok {
		return true
	}
	kind, _, _, _, ok := proto.EnvelopeParse(packet)
	return ok && kind != proto.Type_Audio
}
