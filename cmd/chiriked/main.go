package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

type entry struct {
	addr     *net.UDPAddr
	callsign proto.Callsign
	channel  proto.Channel
	session  *controlSession
	seen     time.Time
}

type controlSession struct {
	addr       *net.UDPAddr
	peerPublic [sessioncrypto.PublicKeyBytes]byte
	voice      *sessioncrypto.Session
	seen       time.Time
	registered bool
	callsign   proto.Callsign
	channel    proto.Channel
}

type peerListRecipient struct {
	addr     *net.UDPAddr
	callsign proto.Callsign
	session  *controlSession
}

type server struct {
	conn     *net.UDPConn
	logger   *log.Logger
	pair     *sessioncrypto.KeyPair
	entries  map[proto.Channel]map[proto.Callsign]*entry
	sessions map[string][]*controlSession
	mu       sync.Mutex
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "keygen":
		return keygenRun(args[1:], stdout, stderr)

	case "listen":
		return listenRun(args[1:], stderr)

	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func keygenRun(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("chiriked keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keyPath := flags.String("key", "chiriked.key", "X25519 private-key file")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: chiriked keygen [--key=<file>]")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		flags.Usage()
		return 2
	}

	if flags.NArg() != 0 {
		flags.Usage()
		return 2
	}

	pair, err := keyPairCreate(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "server key: %v\n", err)
		return 1
	}

	public := pair.Public()
	fmt.Fprintf(stdout, "public key: %s\n", base64.StdEncoding.EncodeToString(public[:]))
	return 0
}

func listenRun(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("chiriked listen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keyPath := flags.String("key", "chiriked.key", "X25519 private-key file")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: chiriked listen <addr>:<port> [--key=<file>]")
		flags.PrintDefaults()
	}

	if len(args) == 0 {
		flags.Usage()
		return 2
	}

	listen := ""
	if strings.HasPrefix(args[0], "-") {
		if err := flags.Parse(args); err != nil {
			flags.Usage()
			return 2
		}

		if flags.NArg() != 1 {
			flags.Usage()
			return 2
		}
		listen = flags.Arg(0)
	} else {
		listen = args[0]
		if err := flags.Parse(args[1:]); err != nil {
			flags.Usage()
			return 2
		}

		if flags.NArg() != 0 {
			flags.Usage()
			return 2
		}
	}

	pair, err := keyPairLoad(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "server key: %v\n", err)
		return 1
	}
	public := pair.Public()
	fmt.Fprintf(stderr, "public key: %s\n", base64.StdEncoding.EncodeToString(public[:]))

	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		fmt.Fprintf(stderr, "listen address: %v\n", err)
		return 1
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		fmt.Fprintf(stderr, "listen: %v\n", err)
		return 1
	}

	s := &server{
		conn:     conn,
		logger:   log.New(stderr, "", log.LstdFlags),
		pair:     pair,
		entries:  make(map[proto.Channel]map[proto.Callsign]*entry),
		sessions: make(map[string][]*controlSession),
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	stopped := make(chan struct{})
	go func() {
		select {
		case <-signals:
			conn.Close()
		case <-stopped:
		}
	}()

	go s.sweepLoop(stopped)
	err = s.serve()
	close(stopped)
	conn.Close()
	if err != nil {
		fmt.Fprintf(stderr, "server: %v\n", err)
		return 1
	}

	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  chiriked keygen [--key=<file>]")
	fmt.Fprintln(w, "  chiriked listen <addr>:<port> [--key=<file>]")
}

func (s *server) serve() error {
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

func (s *server) handle(packet []byte, addr *net.UDPAddr, now time.Time) {
	if public, ok := proto.KEXParse(packet); ok {
		s.handleKEX(addr, public, now)
		return
	}

	s.handleEncrypted(addr, packet, now)
}

func (s *server) handleKEX(
	addr *net.UDPAddr,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
) {
	key := addr.String()
	s.mu.Lock()
	for _, stored := range s.sessions[key] {
		if stored.peerPublic == peerPublic {
			s.mu.Unlock()
			if s.send(addr, proto.KEX(s.pair.Public())) {
				s.logger.Printf("SEND type=KEX to_addr=%s", addr)
			}
			return
		}
	}
	s.mu.Unlock()

	zeroSalt := [proto.ChannelBytes]byte{}
	keys, err := s.pair.Derive(peerPublic[:], zeroSalt[:])
	if err != nil {
		return
	}

	voice, err := sessioncrypto.SessionNew(keys)
	if err != nil {
		return
	}

	session := &controlSession{
		addr:       addrCopy(addr),
		peerPublic: peerPublic,
		voice:      voice,
		seen:       now,
	}
	s.mu.Lock()
	s.sessions[key] = append(s.sessions[key], session)
	s.mu.Unlock()

	if s.send(addr, proto.KEX(s.pair.Public())) {
		s.logger.Printf("SEND type=KEX to_addr=%s", addr)
	}
}

func (s *server) handleEncrypted(addr *net.UDPAddr, packet []byte, now time.Time) {
	s.mu.Lock()
	sessions := append([]*controlSession(nil), s.sessions[addr.String()]...)
	s.mu.Unlock()

	for _, session := range sessions {
		kind, _, payload, err := session.voice.Open(packet)
		if err != nil {
			continue
		}

		if kind != proto.Type_Request {
			return
		}

		callsign, channel, ok := proto.RequestParse(payload)
		if !ok {
			return
		}

		if _, ok := proto.PeerRecordFrom(addr, callsign); !ok {
			return
		}

		s.registrationHandle(session, addr, callsign, channel, now)
		return
	}
}

func (s *server) registrationHandle(
	session *controlSession,
	addr *net.UDPAddr,
	callsign proto.Callsign,
	channel proto.Channel,
	now time.Time,
) {
	s.mu.Lock()
	if !s.sessionContains(session) {
		s.mu.Unlock()
		return
	}

	channelEntries := s.entries[channel]
	if channelEntries == nil {
		channelEntries = make(map[proto.Callsign]*entry)
		s.entries[channel] = channelEntries
	}

	var (
		previous = channelEntries[callsign]
		changed  = previous == nil || previous.session != session || previous.addr.String() != addr.String()
	)
	if previous != nil && previous.session != session {
		s.sessionRemove(previous.session)
		s.entries[channel] = channelEntries
	}

	channelEntries[callsign] = &entry{
		addr:     addrCopy(addr),
		callsign: callsign,
		channel:  channel,
		session:  session,
		seen:     now,
	}
	session.registered = true
	session.callsign = callsign
	session.channel = channel
	session.seen = now

	var (
		records    = make([]proto.PeerRecord, 0, len(channelEntries))
		recipients = make([]peerListRecipient, 0, len(channelEntries))
	)
	for _, item := range channelEntries {
		itemRecord, valid := proto.PeerRecordFrom(item.addr, item.callsign)
		if valid {
			records = append(records, itemRecord)
		}

		if item.session != nil {
			recipients = append(recipients, peerListRecipient{
				addr:     addrCopy(item.addr),
				callsign: item.callsign,
				session:  item.session,
			})
		}
	}
	s.mu.Unlock()

	var (
		channelText  = base64.StdEncoding.EncodeToString(channel[:])
		callsignText = base64.StdEncoding.EncodeToString(callsign[:])
	)
	s.logger.Printf(
		"CONNECT channel=%s callsign=%s addr=%s peers=[%s]",
		channelText, callsignText, addr,
		peerRecordsLog(records),
	)

	if changed {
		s.peerListBroadcast(channel, recipients, records)
		return
	}

	s.peerListSend(
		channel,
		peerListRecipient{addr: addrCopy(addr), callsign: callsign, session: session},
		records,
	)
}

func (s *server) peerListBroadcast(
	channel proto.Channel,
	recipients []peerListRecipient,
	records []proto.PeerRecord,
) {
	for _, recipient := range recipients {
		s.peerListSend(channel, recipient, records)
	}
}

func (s *server) peerListSend(
	channel proto.Channel,
	recipient peerListRecipient,
	records []proto.PeerRecord,
) bool {
	var (
		channelText  = base64.StdEncoding.EncodeToString(channel[:])
		callsignText = base64.StdEncoding.EncodeToString(recipient.callsign[:])
		packets      = (len(records) + proto.PeersPerPacket - 1) / proto.PeersPerPacket
	)
	for start := 0; start < len(records); start += proto.PeersPerPacket {
		var (
			end            = min(start+proto.PeersPerPacket, len(records))
			packetRecords  = records[start:end]
			payload, valid = proto.PeerList(packetRecords)
		)
		if !valid {
			return false
		}

		response, err := recipient.session.voice.Seal(proto.Type_PeerList, payload)
		if err != nil || !s.send(recipient.addr, response) {
			return false
		}

		s.logger.Printf(
			"SEND type=PEER_LIST channel=%s to_callsign=%s to_addr=%s packet=%d/%d peers=[%s]",
			channelText, callsignText, recipient.addr,
			start/proto.PeersPerPacket+1, packets,
			peerRecordsLog(packetRecords),
		)
	}

	return true
}

func (s *server) send(addr *net.UDPAddr, packet []byte) bool {
	n, err := s.conn.WriteToUDP(packet, addr)
	return err == nil && n == len(packet)
}

func peerRecordsLog(records []proto.PeerRecord) string {
	peers := make([]string, len(records))
	for i, record := range records {
		peers[i] = fmt.Sprintf(
			"%s@%s",
			base64.StdEncoding.EncodeToString(record.Callsign[:]),
			record.Addr(),
		)
	}
	sort.Strings(peers)

	return strings.Join(peers, ",")
}

func (s *server) sessionContains(session *controlSession) bool {
	for _, stored := range s.sessions[session.addr.String()] {
		if stored == session {
			return true
		}
	}

	return false
}

func (s *server) sessionRemove(session *controlSession) {
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
	if item := entries[session.callsign]; item != nil && item.session == session {
		delete(entries, session.callsign)
	}

	if len(entries) == 0 {
		delete(s.entries, session.channel)
	}
}

func (s *server) sweepLoop(stopped <-chan struct{}) {
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

func (s *server) entriesSweep(now time.Time) {
	var expired []*controlSession
	for channel, entries := range s.entries {
		for callsign, item := range entries {
			if now.Sub(item.seen) <= proto.EntryTTL {
				continue
			}

			if item.session == nil {
				delete(entries, callsign)
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

func (s *server) sessionsSweep(now time.Time) {
	var expired []*controlSession
	for _, sessions := range s.sessions {
		for _, session := range sessions {
			ttl := proto.KEXTimeout
			if session.registered {
				ttl = proto.EntryTTL
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

func keyPairLoad(path string) (*sessioncrypto.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s permissions must not allow group or other access", path)
	}

	private, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}

	return sessioncrypto.KeyPairFromPrivate(private)
}

func keyPairCreate(path string) (*sessioncrypto.KeyPair, error) {
	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return nil, err
	}

	var (
		encoded = []byte(base64.StdEncoding.EncodeToString(pair.PrivateBytes()) + "\n")
		file    *os.File
	)
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}

	_, err = file.Write(encoded)
	err = errors.Join(err, file.Close())
	if err != nil {
		os.Remove(path)
		return nil, err
	}

	return pair, nil
}

func addrCopy(addr *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}
