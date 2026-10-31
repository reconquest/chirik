package main

import (
	"net"
	"slices"
	"time"

	"github.com/reconquest/karma-go"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

type exchangeEntry struct {
	addr    *net.UDPAddr
	local   *net.UDPAddr
	handle  proto.Handle
	session *exchangeSession
	seen    time.Time
}

type exchangeSession struct {
	addr       *net.UDPAddr
	peerPublic [sessioncrypto.PublicKeyBytes]byte
	voice      *sessioncrypto.Session
	seen       time.Time
	registered bool
	handle     proto.Handle
	channel    string
}

func (server *exchangeServer) kexHandle(
	addr *net.UDPAddr,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
) {
	key := addr.String()

	server.mu.Lock()

	for _, stored := range server.sessions[key] {
		if stored.peerPublic == peerPublic {
			server.mu.Unlock()
			server.kexSend(addr)

			return
		}
	}

	server.mu.Unlock()

	zero := [32]byte{}

	voice, err := discoverySessionNew(server.pair, peerPublic, zero[:])
	if err != nil {
		return
	}

	session := &exchangeSession{
		addr:       addrCopy(addr),
		peerPublic: peerPublic,
		voice:      voice,
		seen:       now,
	}

	server.mu.Lock()

	server.sessions[key] = append(server.sessions[key], session)
	server.mu.Unlock()

	server.kexSend(addr)
}

func (server *exchangeServer) kexSend(addr *net.UDPAddr) {
	err := datagramSend(server.conn, addr, proto.KEX(server.pair.Public()))
	if err != nil {
		server.logger.Print("ERROR ", karma.
			Describe("type", "KEX").
			Describe("to_addr", addr).
			Format(err, "send packet"),
		)

		return
	}

	server.logger.Print("INFO ", karma.
		Describe("type", "KEX").
		Describe("to_addr", addr).
		Format(nil, "packet sent"),
	)
}

func (server *exchangeServer) encryptedHandle(
	addr *net.UDPAddr,
	packet []byte,
	now time.Time,
) {
	server.mu.Lock()

	sessions := append(
		[]*exchangeSession(nil),
		server.sessions[addr.String()]...)
	server.mu.Unlock()

	for _, session := range sessions {
		kind, _, payload, err := session.voice.Open(packet)
		if err != nil {
			continue
		}

		switch kind {
		case proto.Type_Request:
			handle, channel, local, ok := proto.RequestParse(payload)
			if !ok {
				return
			}

			if _, valid := proto.PeerRecordFrom(addr, handle); !valid {
				return
			}

			server.registrationHandle(
				session,
				addr,
				local,
				handle,
				channel,
				now,
			)

		case proto.Type_PeerListAudio:
			server.peerListHandle(session, payload, now)

		case proto.Type_Relay:
			server.relayHandle(session, payload, now)

		default:
			return
		}

		return
	}
}

func (server *exchangeServer) registrationHandle(
	session *exchangeSession,
	addr *net.UDPAddr,
	local *net.UDPAddr,
	handle proto.Handle,
	channel string,
	now time.Time,
) {
	changed, registered := server.registrationUpdate(
		session,
		addr,
		local,
		handle,
		channel,
		now,
	)
	if !registered {
		return
	}

	peers := exchangeRecordsLog(server.discoveryRecords(channel, ""))

	server.logger.Print("INFO ", karma.
		Describe("channel", channel).
		Describe("handle", handle).
		Describe("address", addr).
		Describe("peers", peers).
		Format(nil, "peer registered"),
	)

	discovery := server.discoveryEnsure()
	recipient := discoveryRecipient{
		addr:    addrCopy(addr),
		handle:  handle,
		session: session.voice,
	}

	err := discovery.sendRecords(channel, recipient, nil)
	if err != nil {
		server.logger.Print("ERROR ", err)
	}

	if changed {
		broadcastErr := discovery.broadcastRecordsExcept(
			channel,
			recipient,
			server.endpointRecordsFor(addr, local, handle),
		)
		if broadcastErr != nil {
			server.logger.Print(
				"ERROR ",
				karma.Format(broadcastErr, "broadcast peer list"),
			)
		}
	}
}

func (server *exchangeServer) registrationUpdate(
	session *exchangeSession,
	addr *net.UDPAddr,
	local *net.UDPAddr,
	handle proto.Handle,
	channel string,
	now time.Time,
) (bool, bool) {
	server.mu.Lock()
	defer server.mu.Unlock()

	if !server.sessionContains(session) {
		return false, false
	}

	server.registrationMove(session, handle, channel)

	entries := server.registrationEntries(channel)
	previous := entries[handle]
	changed := registrationChanged(previous, session, addr, local)
	server.registrationReplacePrevious(channel, handle, previous, session)

	server.entries[channel] = entries

	entries[handle] = &exchangeEntry{
		addr:    addrCopy(addr),
		local:   addrCopy(local),
		handle:  handle,
		session: session,
		seen:    now,
	}
	session.registered = true
	session.handle = handle
	session.channel = channel
	session.seen = now

	return changed, true
}

func (server *exchangeServer) registrationMove(
	session *exchangeSession,
	handle proto.Handle,
	channel string,
) {
	if !session.registered ||
		(session.handle == handle && session.channel == channel) {
		return
	}

	oldEntries := server.entries[session.channel]
	if item := oldEntries[session.handle]; item != nil &&
		item.session == session {
		delete(oldEntries, session.handle)
	}

	if len(oldEntries) == 0 {
		delete(server.entries, session.channel)
	}
}

func (server *exchangeServer) registrationEntries(
	channel string,
) map[proto.Handle]*exchangeEntry {
	entries := server.entries[channel]
	if entries == nil {
		entries = make(map[proto.Handle]*exchangeEntry)
		server.entries[channel] = entries
	}

	return entries
}

func registrationChanged(
	previous *exchangeEntry,
	session *exchangeSession,
	addr *net.UDPAddr,
	local *net.UDPAddr,
) bool {
	return previous == nil || previous.session != session ||
		!udpAddrEqual(previous.addr, addr) ||
		!udpAddrEqual(previous.local, local)
}

func (server *exchangeServer) registrationReplacePrevious(
	channel string,
	handle proto.Handle,
	previous *exchangeEntry,
	session *exchangeSession,
) {
	if previous == nil || previous.session == session {
		return
	}

	if previous.session != nil {
		server.sessionRemove(previous.session)
	} else {
		delete(server.entries[channel], handle)
	}
}

func (server *exchangeServer) sessionContains(session *exchangeSession) bool {
	return slices.Contains(server.sessions[session.addr.String()], session)
}

func (server *exchangeServer) sessionRemove(session *exchangeSession) {
	key := session.addr.String()
	stored := server.sessions[key]

	for index, candidate := range stored {
		if candidate != session {
			continue
		}

		stored = append(stored[:index], stored[index+1:]...)

		break
	}

	if len(stored) == 0 {
		delete(server.sessions, key)
	} else {
		server.sessions[key] = stored
	}

	if !session.registered {
		return
	}

	entries := server.entries[session.channel]
	if item := entries[session.handle]; item != nil && item.session == session {
		delete(entries, session.handle)
	}

	if len(entries) == 0 {
		delete(server.entries, session.channel)
	}
}

func (server *exchangeServer) sweepLoop(stopped <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case now := <-ticker.C:
			server.mu.Lock()
			server.entriesSweep(now)
			server.sessionsSweep(now)
			server.mu.Unlock()

		case <-stopped:
			return
		}
	}
}

func (server *exchangeServer) entriesSweep(now time.Time) {
	var expired []*exchangeSession

	for channel, entries := range server.entries {
		for handle, item := range entries {
			if now.Sub(item.seen) <= server.discoveryEnsure().policy.ttl {
				continue
			}

			if item.session == nil {
				delete(entries, handle)

				continue
			}

			expired = append(expired, item.session)
		}

		if len(entries) == 0 {
			delete(server.entries, channel)
		}
	}

	for _, session := range expired {
		server.sessionRemove(session)
	}
}

func (server *exchangeServer) sessionsSweep(now time.Time) {
	var expired []*exchangeSession

	for _, sessions := range server.sessions {
		for _, session := range sessions {
			ttl := proto.KEXTimeout
			if session.registered {
				ttl = server.discoveryEnsure().policy.ttl
			}

			if now.Sub(session.seen) > ttl {
				expired = append(expired, session)
			}
		}
	}

	for _, session := range expired {
		server.sessionRemove(session)
	}
}
