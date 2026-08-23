package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

type logBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *logBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.data.Write(data)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.data.String()
}

func TestServerRegistersAndReturnsChannelPeers(t *testing.T) {
	serverConn := udpListen(t)
	defer serverConn.Close()
	var (
		pair = keyPair(t)
		logs = &logBuffer{}
		s    = &server{
			conn:     serverConn,
			logger:   log.New(logs, "", 0),
			pair:     pair,
			entries:  make(map[proto.Channel]map[proto.Callsign]*entry),
			sessions: make(map[string][]*controlSession),
		}
	)

	served := make(chan error, 1)
	go func() { served <- s.serve() }()
	defer func() {
		serverConn.Close()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	var (
		channel   proto.Channel
		callsignA proto.Callsign
		callsignB proto.Callsign
	)
	channel[0] = 1
	callsignA[0] = 0xa1
	callsignB[0] = 0xb2

	a := udpListen(t)
	defer a.Close()
	sessionA := serverSession(t, a, serverConn.LocalAddr().(*net.UDPAddr), pair.Public())
	peersA := registerRead(t, a, serverConn.LocalAddr().(*net.UDPAddr), sessionA, callsignA, channel)
	if len(peersA) != 1 || peersA[0].Callsign != callsignA {
		t.Fatalf("first peer list = %+v", peersA)
	}

	b := udpListen(t)
	defer b.Close()
	sessionB := serverSession(t, b, serverConn.LocalAddr().(*net.UDPAddr), pair.Public())
	peersB := registerRead(t, b, serverConn.LocalAddr().(*net.UDPAddr), sessionB, callsignB, channel)
	if len(peersB) != 2 {
		t.Fatalf("second peer list length = %d", len(peersB))
	}

	addresses := make(map[proto.Callsign]string, len(peersB))
	for _, record := range peersB {
		addresses[record.Callsign] = record.Addr().String()
	}
	if addresses[callsignA] != a.LocalAddr().String() || addresses[callsignB] != b.LocalAddr().String() {
		t.Fatalf("second peer addresses = %+v", addresses)
	}

	update := udpRead(t, a)
	kind, _, payload, err := sessionA.Open(update)
	if err != nil {
		t.Fatal(err)
	}
	if kind != proto.Type_PeerList {
		t.Fatalf("update type = %#x", kind)
	}
	updatedPeers, ok := proto.PeerListParse(payload)
	if !ok || len(updatedPeers) != 2 {
		t.Fatalf("updated peer list = %+v, %t", updatedPeers, ok)
	}

	registerRead(t, b, serverConn.LocalAddr().(*net.UDPAddr), sessionB, callsignB, channel)
	if err := a.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, proto.MaxDatagram)
	if _, _, err := a.ReadFromUDP(buffer); err == nil {
		t.Fatal("duplicate registration triggered channel update")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("unexpected read error: %v", err)
	}

	var (
		channelText   = base64.StdEncoding.EncodeToString(channel[:])
		callsignAText = base64.StdEncoding.EncodeToString(callsignA[:])
		callsignBText = base64.StdEncoding.EncodeToString(callsignB[:])
		addrA         = a.LocalAddr().String()
		addrB         = b.LocalAddr().String()
		logText       = logs.String()
	)
	for _, expected := range []string{
		"SEND type=KEX to_addr=" + addrA,
		"SEND type=KEX to_addr=" + addrB,
		"CONNECT channel=" + channelText + " callsign=" + callsignAText + " addr=" + addrA,
		"CONNECT channel=" + channelText + " callsign=" + callsignBText + " addr=" + addrB,
		"SEND type=PEER_LIST channel=" + channelText + " to_callsign=" + callsignAText + " to_addr=" + addrA,
		"SEND type=PEER_LIST channel=" + channelText + " to_callsign=" + callsignBText + " to_addr=" + addrB,
		callsignAText + "@" + addrA,
		callsignBText + "@" + addrB,
	} {
		if !strings.Contains(logText, expected) {
			t.Errorf("missing log entry %q in:\n%s", expected, logText)
		}
	}
}

func TestServerReplacesSameCallsignEndpoint(t *testing.T) {
	serverConn := udpListen(t)
	defer serverConn.Close()
	pair := keyPair(t)
	s := &server{
		conn:     serverConn,
		logger:   log.New(io.Discard, "", 0),
		pair:     pair,
		entries:  make(map[proto.Channel]map[proto.Callsign]*entry),
		sessions: make(map[string][]*controlSession),
	}

	served := make(chan error, 1)
	go func() { served <- s.serve() }()
	defer func() {
		serverConn.Close()
		<-served
	}()

	var (
		channel  proto.Channel
		callsign proto.Callsign
	)
	channel[0] = 3
	callsign[0] = 4

	first := udpListen(t)
	firstSession := serverSession(t, first, serverConn.LocalAddr().(*net.UDPAddr), pair.Public())
	registerRead(t, first, serverConn.LocalAddr().(*net.UDPAddr), firstSession, callsign, channel)
	first.Close()

	second := udpListen(t)
	defer second.Close()
	secondSession := serverSession(t, second, serverConn.LocalAddr().(*net.UDPAddr), pair.Public())
	registerRead(t, second, serverConn.LocalAddr().(*net.UDPAddr), secondSession, callsign, channel)

	s.mu.Lock()
	stored := s.entries[channel][callsign]
	s.mu.Unlock()
	if stored == nil || !udpAddrEqual(stored.addr, second.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("stored endpoint = %v, want %v", stored.addr, second.LocalAddr())
	}
}

func TestServerBroadcastsReconnectedClientEndpoint(t *testing.T) {
	var (
		serverConn = udpListen(t)
		pair       = keyPair(t)
		s          = &server{
			conn:     serverConn,
			logger:   log.New(io.Discard, "", 0),
			pair:     pair,
			entries:  make(map[proto.Channel]map[proto.Callsign]*entry),
			sessions: make(map[string][]*controlSession),
		}
	)

	served := make(chan error, 1)
	go func() { served <- s.serve() }()
	defer func() {
		serverConn.Close()
		<-served
	}()

	var (
		serverAddr = serverConn.LocalAddr().(*net.UDPAddr)
		channel    = proto.Channel{3}
		callsignA  = proto.Callsign{0xa1}
		callsignB  = proto.Callsign{0xb2}
		clientA    = udpListen(t)
		clientB1   = udpListen(t)
		clientB2   = udpListen(t)
	)
	defer clientA.Close()
	defer clientB1.Close()
	defer clientB2.Close()

	sessionA := serverSession(t, clientA, serverAddr, pair.Public())
	registerRead(t, clientA, serverAddr, sessionA, callsignA, channel)
	sessionB1 := serverSession(t, clientB1, serverAddr, pair.Public())
	registerRead(t, clientB1, serverAddr, sessionB1, callsignB, channel)

	kind, _, payload, err := sessionA.Open(udpRead(t, clientA))
	if err != nil || kind != proto.Type_PeerList {
		t.Fatalf("initial client A update = %#x, %v", kind, err)
	}
	peers, ok := proto.PeerListParse(payload)
	if !ok {
		t.Fatal("initial client A update rejected")
	}
	addresses := make(map[proto.Callsign]string, len(peers))
	for _, record := range peers {
		addresses[record.Callsign] = record.Addr().String()
	}
	if addresses[callsignB] != clientB1.LocalAddr().String() {
		t.Fatalf("initial client B endpoint = %q", addresses[callsignB])
	}

	sessionB2 := serverSession(t, clientB2, serverAddr, pair.Public())
	registerRead(t, clientB2, serverAddr, sessionB2, callsignB, channel)

	kind, _, payload, err = sessionA.Open(udpRead(t, clientA))
	if err != nil || kind != proto.Type_PeerList {
		t.Fatalf("reconnected client A update = %#x, %v", kind, err)
	}
	peers, ok = proto.PeerListParse(payload)
	if !ok {
		t.Fatal("reconnected client A update rejected")
	}
	addresses = make(map[proto.Callsign]string, len(peers))
	for _, record := range peers {
		addresses[record.Callsign] = record.Addr().String()
	}
	if len(peers) != 2 || addresses[callsignB] != clientB2.LocalAddr().String() ||
		addresses[callsignB] == clientB1.LocalAddr().String() {
		t.Fatalf("reconnected client B endpoint = %q; peers=%+v", addresses[callsignB], addresses)
	}
}

func TestServerReregistersSameClientFromSameEndpoint(t *testing.T) {
	var (
		serverConn = udpListen(t)
		pair       = keyPair(t)
		s          = &server{
			conn:     serverConn,
			logger:   log.New(io.Discard, "", 0),
			pair:     pair,
			entries:  make(map[proto.Channel]map[proto.Callsign]*entry),
			sessions: make(map[string][]*controlSession),
		}
	)

	served := make(chan error, 1)
	go func() { served <- s.serve() }()
	defer func() {
		serverConn.Close()
		<-served
	}()

	var (
		serverAddr = serverConn.LocalAddr().(*net.UDPAddr)
		channel    = proto.Channel{3}
		callsignA  = proto.Callsign{0xa1}
		callsignB  = proto.Callsign{0xb2}
		clientA    = udpListen(t)
		clientB    = udpListen(t)
	)
	defer clientA.Close()
	defer clientB.Close()

	sessionB := serverSession(t, clientB, serverAddr, pair.Public())
	registerRead(t, clientB, serverAddr, sessionB, callsignB, channel)
	sessionA := serverSession(t, clientA, serverAddr, pair.Public())
	registerRead(t, clientA, serverAddr, sessionA, callsignA, channel)

	kind, _, _, err := sessionB.Open(udpRead(t, clientB))
	if err != nil || kind != proto.Type_PeerList {
		t.Fatalf("initial client B update = %#x, %v", kind, err)
	}

	sessionA = serverSession(t, clientA, serverAddr, pair.Public())
	peers := registerRead(t, clientA, serverAddr, sessionA, callsignA, channel)
	addresses := make(map[proto.Callsign]string, len(peers))
	for _, record := range peers {
		addresses[record.Callsign] = record.Addr().String()
	}
	if len(peers) != 2 || addresses[callsignA] != clientA.LocalAddr().String() ||
		addresses[callsignB] != clientB.LocalAddr().String() {
		t.Fatalf("re-registration peers = %+v", addresses)
	}

	s.mu.Lock()
	sessionCount := len(s.sessions[clientA.LocalAddr().String()])
	stored := s.entries[channel][callsignA]
	s.mu.Unlock()
	if sessionCount != 1 || stored == nil || !udpAddrEqual(stored.addr, clientA.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("re-registration state = sessions:%d entry:%+v", sessionCount, stored)
	}
}

func TestServerSupportsMultipleSessionsFromSameEndpoint(t *testing.T) {
	serverConn := udpListen(t)
	defer serverConn.Close()
	pair := keyPair(t)
	s := &server{
		conn:     serverConn,
		logger:   log.New(io.Discard, "", 0),
		pair:     pair,
		entries:  make(map[proto.Channel]map[proto.Callsign]*entry),
		sessions: make(map[string][]*controlSession),
	}

	served := make(chan error, 1)
	go func() { served <- s.serve() }()
	defer func() {
		serverConn.Close()
		<-served
	}()

	client := udpListen(t)
	defer client.Close()
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	firstSession := serverSession(t, client, serverAddr, pair.Public())
	firstCallsign := proto.Callsign{1}
	registerRead(t, client, serverAddr, firstSession, firstCallsign, proto.Channel{1})

	secondSession := serverSession(t, client, serverAddr, pair.Public())
	secondCallsign := proto.Callsign{2}
	registerRead(t, client, serverAddr, secondSession, secondCallsign, proto.Channel{2})

	s.mu.Lock()
	sessionCount := len(s.sessions[client.LocalAddr().String()])
	first := s.entries[proto.Channel{1}][firstCallsign]
	second := s.entries[proto.Channel{2}][secondCallsign]
	s.mu.Unlock()
	if sessionCount != 2 || first == nil || second == nil {
		t.Fatalf("sessions/entries = %d/%v/%v", sessionCount, first, second)
	}
}

func TestServerEntriesSweep(t *testing.T) {
	now := time.Unix(100, 0)
	var (
		channel   proto.Channel
		callsignA proto.Callsign
		callsignB proto.Callsign
	)
	callsignA[0] = 1
	callsignB[0] = 2

	s := &server{
		entries: map[proto.Channel]map[proto.Callsign]*entry{
			channel: {
				callsignA: {seen: now.Add(-proto.EntryTTL - time.Second)},
				callsignB: {seen: now.Add(-proto.EntryTTL + time.Second)},
			},
		},
		sessions: make(map[string][]*controlSession),
	}

	s.entriesSweep(now)
	if _, ok := s.entries[channel][callsignA]; ok {
		t.Fatal("expired entry retained")
	}

	if _, ok := s.entries[channel][callsignB]; !ok {
		t.Fatal("fresh entry deleted")
	}
}

func TestKeyPairCreateAndLoad(t *testing.T) {
	var (
		path       = filepath.Join(t.TempDir(), "server.key")
		first, err = keyPairCreate(path)
	)
	if err != nil {
		t.Fatal(err)
	}

	second, err := keyPairLoad(path)
	if err != nil {
		t.Fatal(err)
	}

	if first.Public() != second.Public() {
		t.Fatal("persisted server public key differs")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(private) != sessioncrypto.PublicKeyBytes {
		t.Fatalf("private key = %d bytes, %v", len(private), err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %#o", info.Mode().Perm())
	}

	if _, err := keyPairCreate(path); err == nil {
		t.Fatal("existing key overwritten")
	}
}

func TestRunKeygenCustomPath(t *testing.T) {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
		path   = filepath.Join(t.TempDir(), "custom.key")
	)

	if code := run([]string{"keygen", "--key=" + path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d: %s", code, stderr.String())
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	var (
		text        = strings.TrimSpace(strings.TrimPrefix(stdout.String(), "public key:"))
		public, err = base64.StdEncoding.DecodeString(text)
	)
	if err != nil || len(public) != sessioncrypto.PublicKeyBytes {
		t.Fatalf("public key = %q, %v", stdout.String(), err)
	}
}

func TestRunListenDoesNotCreateKey(t *testing.T) {
	for name, args := range map[string][]string{
		"flag after address":  {"listen", "127.0.0.1:7777"},
		"flag before address": {"listen"},
	} {
		t.Run(name, func(t *testing.T) {
			var (
				stdout bytes.Buffer
				stderr bytes.Buffer
				path   = filepath.Join(t.TempDir(), "missing.key")
			)

			if name == "flag after address" {
				args = append(args, "--key="+path)
			} else {
				args = append(args, "--key="+path, "127.0.0.1:7777")
			}

			if code := run(args, &stdout, &stderr); code != 1 {
				t.Fatalf("run = %d: %s", code, stderr.String())
			}

			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("missing key was created: %v", err)
			}
		})
	}
}

func serverSession(
	t *testing.T,
	conn *net.UDPConn,
	serverAddr *net.UDPAddr,
	serverPublic [sessioncrypto.PublicKeyBytes]byte,
) *sessioncrypto.Session {
	t.Helper()

	pair := keyPair(t)
	if _, err := conn.WriteToUDP(proto.KEX(pair.Public()), serverAddr); err != nil {
		t.Fatal(err)
	}

	packet := udpRead(t, conn)
	public, ok := proto.KEXParse(packet)
	if !ok || public != serverPublic {
		t.Fatalf("server KEX = %x, %t", public, ok)
	}

	var zero [proto.ChannelBytes]byte
	keys, err := pair.Derive(serverPublic[:], zero[:])
	if err != nil {
		t.Fatal(err)
	}

	session, err := sessioncrypto.SessionNew(keys)
	if err != nil {
		t.Fatal(err)
	}

	return session
}

func registerRead(
	t *testing.T,
	conn *net.UDPConn,
	serverAddr *net.UDPAddr,
	session *sessioncrypto.Session,
	callsign proto.Callsign,
	channel proto.Channel,
) []proto.PeerRecord {
	t.Helper()

	payload := proto.Request(callsign, channel)
	packet, err := session.Seal(proto.Type_Request, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDP(packet, serverAddr); err != nil {
		t.Fatal(err)
	}

	response := udpRead(t, conn)
	kind, _, payload, err := session.Open(response)
	if err != nil {
		t.Fatal(err)
	}
	if kind != proto.Type_PeerList {
		t.Fatalf("response type = %#x", kind)
	}

	records, ok := proto.PeerListParse(payload)
	if !ok {
		t.Fatalf("invalid peer list: %x", payload)
	}

	return records
}

func udpRead(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, proto.MaxDatagram)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}

	return bytes.Clone(buffer[:n])
}

func udpListen(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}

	return conn
}

func keyPair(t *testing.T) *sessioncrypto.KeyPair {
	t.Helper()

	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		t.Fatal(err)
	}

	return pair
}

func udpAddrEqual(a *net.UDPAddr, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}
