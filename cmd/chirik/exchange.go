package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

type exchangeEntry struct {
	addr    *net.UDPAddr
	local   *net.UDPAddr
	handle  proto.Handle
	channel string
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

type exchangeServer struct {
	conn            *net.UDPConn
	logger          *log.Logger
	pair            *sessioncrypto.KeyPair
	entries         map[string]map[proto.Handle]*exchangeEntry
	sessions        map[string][]*exchangeSession
	discovery       *discoveryEngine
	endpointRecords func(*net.UDPAddr, *net.UDPAddr, proto.Handle) []proto.PeerRecord
	mu              sync.Mutex
}

func exchangeRun(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: chirik exchange <host>:<port>")
		return 2
	}

	addr, err := exchangeAddrResolve(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "exchange address: %v\n", err)
		return 1
	}
	if addr.Port == 0 {
		fmt.Fprintln(stderr, "exchange address: port must be non-zero")
		return 1
	}

	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		fmt.Fprintf(stderr, "exchange key: %v\n", err)
		return 1
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		fmt.Fprintf(stderr, "exchange listen: %v\n", err)
		return 1
	}
	defer conn.Close()

	s := &exchangeServer{
		conn:     conn,
		logger:   log.New(stderr, "", log.LstdFlags),
		pair:     pair,
		entries:  make(map[string]map[proto.Handle]*exchangeEntry),
		sessions: make(map[string][]*exchangeSession),
	}
	s.discoveryEnsure()
	public := pair.Public()
	fmt.Fprintf(stderr, "exchange public key: %s\n", base64.StdEncoding.EncodeToString(public[:]))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stopped:
		}
	}()
	go s.sweepLoop(stopped)

	err = s.serve()
	close(stopped)
	if err != nil {
		fmt.Fprintf(stderr, "exchange: %v\n", err)
		return 1
	}

	return 0
}

func exchangeAddrResolve(raw string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, err
	}
	if host == "0" {
		raw = net.JoinHostPort("0.0.0.0", port)
	}

	return net.ResolveUDPAddr("udp4", raw)
}

func (s *exchangeServer) serve() error {
	buffer := make([]byte, proto.MaxDatagram+1)
	for {
		n, addr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			return err
		}

		if n > proto.MaxDatagram {
			continue
		}

		s.handle(buffer[:n], addr, time.Now())
	}
}

func (s *exchangeServer) handle(packet []byte, addr *net.UDPAddr, now time.Time) {
	if public, ok := proto.KEXParse(packet); ok {
		s.kexHandle(addr, public, now)
		return
	}

	s.encryptedHandle(addr, packet, now)
}

func (s *exchangeServer) kexHandle(
	addr *net.UDPAddr,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
) {
	key := addr.String()
	s.mu.Lock()
	for _, stored := range s.sessions[key] {
		if stored.peerPublic == peerPublic {
			s.mu.Unlock()
			if discoveryKEXSend(s.conn, addr, s.pair) {
				s.logger.Printf("SEND type=KEX to_addr=%s", addr)
			}
			return
		}
	}
	s.mu.Unlock()

	zero := [32]byte{}
	voice, err := discoverySessionNew(s.pair, peerPublic, zero[:])
	if err != nil {
		return
	}

	session := &exchangeSession{
		addr:       addrCopy(addr),
		peerPublic: peerPublic,
		voice:      voice,
		seen:       now,
	}
	s.mu.Lock()
	s.sessions[key] = append(s.sessions[key], session)
	s.mu.Unlock()

	if discoveryKEXSend(s.conn, addr, s.pair) {
		s.logger.Printf("SEND type=KEX to_addr=%s", addr)
	}
}

func (s *exchangeServer) encryptedHandle(addr *net.UDPAddr, packet []byte, now time.Time) {
	s.mu.Lock()
	sessions := append([]*exchangeSession(nil), s.sessions[addr.String()]...)
	s.mu.Unlock()

	for _, session := range sessions {
		kind, _, payload, err := session.voice.Open(packet)
		if err != nil {
			continue
		}

		switch kind {
		case proto.Type_Request:
			handle, channel, local, ok := s.discoveryEnsure().request(payload)
			if !ok {
				return
			}
			if _, ok := proto.PeerRecordFrom(addr, handle); !ok {
				return
			}
			s.registrationHandle(session, addr, local, handle, channel, now)

		case proto.Type_PeerListAudio:
			s.peerListHandle(session, payload, now)

		case proto.Type_Relay:
			s.relayHandle(session, payload, now)
		}
		return
	}
}

func (s *exchangeServer) registrationHandle(
	session *exchangeSession,
	addr *net.UDPAddr,
	local *net.UDPAddr,
	handle proto.Handle,
	channel string,
	now time.Time,
) {
	s.mu.Lock()
	if !s.sessionContains(session) {
		s.mu.Unlock()
		return
	}

	if session.registered && (session.handle != handle || session.channel != channel) {
		oldEntries := s.entries[session.channel]
		if item := oldEntries[session.handle]; item != nil && item.session == session {
			delete(oldEntries, session.handle)
		}
		if len(oldEntries) == 0 {
			delete(s.entries, session.channel)
		}
	}

	channelEntries := s.entries[channel]
	if channelEntries == nil {
		channelEntries = make(map[proto.Handle]*exchangeEntry)
		s.entries[channel] = channelEntries
	}

	var (
		previous = channelEntries[handle]
		changed  = previous == nil || previous.session != session ||
			!udpAddrEqual(previous.addr, addr) || !udpAddrEqual(previous.local, local)
	)
	if previous != nil && previous.session != session {
		if previous.session != nil {
			s.sessionRemove(previous.session)
		} else {
			delete(channelEntries, handle)
		}
		s.entries[channel] = channelEntries
	}

	channelEntries[handle] = &exchangeEntry{
		addr:    addrCopy(addr),
		local:   addrCopy(local),
		handle:  handle,
		channel: channel,
		session: session,
		seen:    now,
	}
	session.registered = true
	session.handle = handle
	session.channel = channel
	session.seen = now

	s.mu.Unlock()

	s.logger.Printf(
		"CONNECT channel=%q handle=%q addr=%s peers=[%s]",
		channel, handle, addr,
		exchangeRecordsLog(s.discoveryRecords(channel, "")),
	)

	discovery := s.discoveryEnsure()
	recipient := discoveryRecipient{
		addr:    addrCopy(addr),
		handle:  handle,
		session: session.voice,
	}
	discovery.sendRecords(channel, recipient, nil)
	if changed {
		discovery.broadcastRecordsExcept(
			channel,
			recipient,
			s.endpointRecordsFor(addr, local, handle),
		)
	}
}

func (s *exchangeServer) sessionContains(session *exchangeSession) bool {
	for _, stored := range s.sessions[session.addr.String()] {
		if stored == session {
			return true
		}
	}

	return false
}

func (s *exchangeServer) sessionRemove(session *exchangeSession) {
	key := session.addr.String()
	stored := s.sessions[key]
	for i, candidate := range stored {
		if candidate != session {
			continue
		}

		stored = append(stored[:i], stored[i+1:]...)
		break
	}

	if len(stored) == 0 {
		delete(s.sessions, key)
	} else {
		s.sessions[key] = stored
	}

	if !session.registered {
		return
	}

	entries := s.entries[session.channel]
	if item := entries[session.handle]; item != nil && item.session == session {
		delete(entries, session.handle)
	}
	if len(entries) == 0 {
		delete(s.entries, session.channel)
	}
}

func (s *exchangeServer) sweepLoop(stopped <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case now := <-ticker.C:
			s.mu.Lock()
			s.entriesSweep(now)
			s.sessionsSweep(now)
			s.mu.Unlock()

		case <-stopped:
			return
		}
	}
}

func (s *exchangeServer) entriesSweep(now time.Time) {
	var expired []*exchangeSession
	for channel, entries := range s.entries {
		for handle, item := range entries {
			if now.Sub(item.seen) <= s.discoveryEnsure().policy.ttl {
				continue
			}

			if item.session == nil {
				delete(entries, handle)
				continue
			}

			expired = append(expired, item.session)
		}

		if len(entries) == 0 {
			delete(s.entries, channel)
		}
	}

	for _, session := range expired {
		s.sessionRemove(session)
	}
}

func (s *exchangeServer) sessionsSweep(now time.Time) {
	var expired []*exchangeSession
	for _, sessions := range s.sessions {
		for _, session := range sessions {
			ttl := proto.KEXTimeout
			if session.registered {
				ttl = s.discoveryEnsure().policy.ttl
			}
			if now.Sub(session.seen) > ttl {
				expired = append(expired, session)
			}
		}
	}

	for _, session := range expired {
		s.sessionRemove(session)
	}
}
