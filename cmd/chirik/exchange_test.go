package main

import (
	"bytes"
	"io"
	"log"
	"net"
	"testing"
	"time"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

func TestExchangeRegistersAndBroadcasts(t *testing.T) {
	var (
		serverConn = udpListen(t)
		pair       = testKeyPair(t)
		s          = &exchangeServer{
			conn:     serverConn,
			logger:   log.New(io.Discard, "", 0),
			pair:     pair,
			entries:  make(map[string]map[proto.Handle]*exchangeEntry),
			sessions: make(map[string][]*exchangeSession),
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
		serverAddr = serverConn.LocalAddr().(*net.UDPAddr)
		clientA    = udpListen(t)
		clientB    = udpListen(t)
		channel    = "free form/channel"
	)
	defer clientA.Close()
	defer clientB.Close()

	sessionA := exchangeClientSession(t, clientA, serverAddr, pair.Public())
	peersA := exchangeRegister(t, clientA, serverAddr, sessionA, "Alice", channel)
	if len(peersA) != 0 {
		t.Fatalf("first peer list = %+v", peersA)
	}

	sessionB := exchangeClientSession(t, clientB, serverAddr, pair.Public())
	peersB := exchangeRegister(t, clientB, serverAddr, sessionB, "Bob", channel)
	if len(peersB) != 0 {
		t.Fatalf("passive joiner peer list = %+v", peersB)
	}

	kind, _, payload, err := sessionA.Open(udpRead(t, clientA))
	if err != nil || kind != proto.Type_PeerList {
		t.Fatalf("client A update = %#x, %v", kind, err)
	}
	updated, ok := proto.PeerListParse(payload)
	if !ok || len(updated) != 1 || updated[0].Handle != "Bob" ||
		updated[0].Addr().String() != clientB.LocalAddr().String() {
		t.Fatalf("client A peers = %+v/%t", updated, ok)
	}

	peersB = exchangeRegister(t, clientB, serverAddr, sessionB, "Bob", channel)
	if len(peersB) != 0 {
		t.Fatalf("duplicate passive registration peers = %+v", peersB)
	}
	expectUDPTimeout(t, clientA, "duplicate registration broadcast")
}

func TestExchangeRelaysOpaquePeerPackets(t *testing.T) {
	serverConn := udpListen(t)
	pair := testKeyPair(t)
	s := &exchangeServer{
		conn:     serverConn,
		logger:   log.New(io.Discard, "", 0),
		pair:     pair,
		entries:  make(map[string]map[proto.Handle]*exchangeEntry),
		sessions: make(map[string][]*exchangeSession),
	}
	served := make(chan error, 1)
	go func() { served <- s.serve() }()
	defer func() {
		serverConn.Close()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	clientA := udpListen(t)
	defer clientA.Close()
	clientB := udpListen(t)
	defer clientB.Close()
	sessionA := exchangeClientSession(t, clientA, serverAddr, pair.Public())
	exchangeRegister(t, clientA, serverAddr, sessionA, "Alice", "room")
	sessionB := exchangeClientSession(t, clientB, serverAddr, pair.Public())
	exchangeRegister(t, clientB, serverAddr, sessionB, "Bob", "room")
	udpRead(t, clientA)

	inner := proto.KEX(testKeyPair(t).Public())
	relay, ok := proto.Relay("Bob", inner)
	if !ok {
		t.Fatal("relay payload rejected")
	}
	packet, err := sessionA.Seal(proto.Type_Relay, relay)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientA.WriteToUDP(packet, serverAddr); err != nil {
		t.Fatal(err)
	}

	kind, _, payload, err := sessionB.Open(udpRead(t, clientB))
	if err != nil || kind != proto.Type_Relay {
		t.Fatalf("relay delivery = %#x/%v", kind, err)
	}
	source, delivered, ok := proto.RelayParse(payload)
	if !ok || source != "Alice" || !bytes.Equal(delivered, inner) {
		t.Fatalf("relay source/payload = %q/%x/%t", source, delivered, ok)
	}
}

func TestExchangeMergesAudioPeerLists(t *testing.T) {
	var (
		serverConn = udpListen(t)
		pair       = testKeyPair(t)
		s          = &exchangeServer{
			conn:     serverConn,
			logger:   log.New(io.Discard, "", 0),
			pair:     pair,
			entries:  make(map[string]map[proto.Handle]*exchangeEntry),
			sessions: make(map[string][]*exchangeSession),
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
		serverAddr = serverConn.LocalAddr().(*net.UDPAddr)
		clientA    = udpListen(t)
		clientB    = udpListen(t)
	)
	defer clientA.Close()
	defer clientB.Close()

	sessionA := exchangeClientSession(t, clientA, serverAddr, pair.Public())
	exchangeRegister(t, clientA, serverAddr, sessionA, "Alice", "room")
	sessionB := exchangeClientSession(t, clientB, serverAddr, pair.Public())
	exchangeRegister(t, clientB, serverAddr, sessionB, "Bob", "room")
	udpRead(t, clientA)

	charlie, ok := proto.PeerRecordFrom(
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 9000},
		"Charlie",
	)
	if !ok {
		t.Fatal("indirect peer record rejected")
	}
	exchangePeerListSend(t, clientA, serverAddr, sessionA, []proto.PeerRecord{charlie})

	for _, test := range []struct {
		name    string
		conn    *net.UDPConn
		session *sessioncrypto.Session
		want    map[proto.Handle]string
	}{
		{
			name:    "Alice",
			conn:    clientA,
			session: sessionA,
			want: map[proto.Handle]string{
				"Bob":     clientB.LocalAddr().String(),
				"Charlie": "192.0.2.3:9000",
			},
		},
		{
			name:    "Bob",
			conn:    clientB,
			session: sessionB,
			want: map[proto.Handle]string{
				"Alice":   clientA.LocalAddr().String(),
				"Charlie": "192.0.2.3:9000",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			kind, _, payload, err := test.session.Open(udpRead(t, test.conn))
			if err != nil || kind != proto.Type_PeerList {
				t.Fatalf("peer-list update = %#x/%v", kind, err)
			}
			records, ok := proto.PeerListParse(payload)
			if !ok {
				t.Fatal("peer-list update rejected")
			}
			addresses := exchangePeerAddresses(records)
			if len(addresses) != len(test.want) {
				t.Fatalf("peer-list addresses = %+v", addresses)
			}
			for handle, want := range test.want {
				if addresses[handle] != want {
					t.Fatalf("peer %s = %q, want %q", handle, addresses[handle], want)
				}
			}
		})
	}

	s.mu.Lock()
	stored := s.entries["room"]["Charlie"]
	s.mu.Unlock()
	if stored == nil || stored.session != nil {
		t.Fatalf("indirect entry = %+v", stored)
	}

	exchangePeerListSend(t, clientA, serverAddr, sessionA, []proto.PeerRecord{charlie})
	expectUDPTimeout(t, clientA, "duplicate indirect update")
	expectUDPTimeout(t, clientB, "duplicate indirect update")
}

func TestExchangeBroadcastsReconnectedEndpoint(t *testing.T) {
	var (
		serverConn = udpListen(t)
		pair       = testKeyPair(t)
		s          = &exchangeServer{
			conn:     serverConn,
			logger:   log.New(io.Discard, "", 0),
			pair:     pair,
			entries:  make(map[string]map[proto.Handle]*exchangeEntry),
			sessions: make(map[string][]*exchangeSession),
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
		clientA    = udpListen(t)
		clientB1   = udpListen(t)
		clientB2   = udpListen(t)
	)
	defer clientA.Close()
	defer clientB1.Close()
	defer clientB2.Close()

	sessionA := exchangeClientSession(t, clientA, serverAddr, pair.Public())
	exchangeRegister(t, clientA, serverAddr, sessionA, "Alice", "room")
	sessionB1 := exchangeClientSession(t, clientB1, serverAddr, pair.Public())
	exchangeRegister(t, clientB1, serverAddr, sessionB1, "Bob", "room")
	udpRead(t, clientA)

	sessionB2 := exchangeClientSession(t, clientB2, serverAddr, pair.Public())
	exchangeRegister(t, clientB2, serverAddr, sessionB2, "Bob", "room")
	kind, _, payload, err := sessionA.Open(udpRead(t, clientA))
	if err != nil || kind != proto.Type_PeerList {
		t.Fatalf("replacement update = %#x/%v", kind, err)
	}
	peers, ok := proto.PeerListParse(payload)
	if !ok {
		t.Fatal("replacement update rejected")
	}

	addresses := make(map[proto.Handle]string, len(peers))
	for _, record := range peers {
		addresses[record.Handle] = record.Addr().String()
	}
	if len(peers) != 1 || addresses["Bob"] != clientB2.LocalAddr().String() {
		t.Fatalf("replacement peers = %+v", addresses)
	}
}

func TestExchangeReregistersSameEndpoint(t *testing.T) {
	var (
		serverConn = udpListen(t)
		pair       = testKeyPair(t)
		s          = &exchangeServer{
			conn:     serverConn,
			logger:   log.New(io.Discard, "", 0),
			pair:     pair,
			entries:  make(map[string]map[proto.Handle]*exchangeEntry),
			sessions: make(map[string][]*exchangeSession),
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
		clientA    = udpListen(t)
		clientB    = udpListen(t)
	)
	defer clientA.Close()
	defer clientB.Close()

	sessionB := exchangeClientSession(t, clientB, serverAddr, pair.Public())
	exchangeRegister(t, clientB, serverAddr, sessionB, "Bob", "room")
	sessionA := exchangeClientSession(t, clientA, serverAddr, pair.Public())
	exchangeRegister(t, clientA, serverAddr, sessionA, "Alice", "room")
	udpRead(t, clientB)

	sessionA = exchangeClientSession(t, clientA, serverAddr, pair.Public())
	peers := exchangeRegister(t, clientA, serverAddr, sessionA, "Alice", "room")
	if len(peers) != 0 {
		t.Fatalf("passive re-registration peers = %+v", peers)
	}

	s.mu.Lock()
	sessions := len(s.sessions[clientA.LocalAddr().String()])
	s.mu.Unlock()
	if sessions != 1 {
		t.Fatalf("client sessions = %d", sessions)
	}
}

func TestExchangeSupportsMultipleSessionsFromSameEndpoint(t *testing.T) {
	var (
		serverConn = udpListen(t)
		pair       = testKeyPair(t)
		s          = &exchangeServer{
			conn:     serverConn,
			logger:   log.New(io.Discard, "", 0),
			pair:     pair,
			entries:  make(map[string]map[proto.Handle]*exchangeEntry),
			sessions: make(map[string][]*exchangeSession),
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

	client := udpListen(t)
	defer client.Close()
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	firstSession := exchangeClientSession(t, client, serverAddr, pair.Public())
	exchangeRegister(t, client, serverAddr, firstSession, "Alice", "first channel")
	secondSession := exchangeClientSession(t, client, serverAddr, pair.Public())
	exchangeRegister(t, client, serverAddr, secondSession, "Bob", "second channel")

	s.mu.Lock()
	sessionCount := len(s.sessions[client.LocalAddr().String()])
	first := s.entries["first channel"]["Alice"]
	second := s.entries["second channel"]["Bob"]
	s.mu.Unlock()
	if sessionCount != 2 || first == nil || second == nil {
		t.Fatalf("sessions/entries = %d/%v/%v", sessionCount, first, second)
	}
}

func TestExchangeEntriesSweep(t *testing.T) {
	now := time.Unix(100, 0)
	s := &exchangeServer{
		entries: map[string]map[proto.Handle]*exchangeEntry{
			"room": {
				"old":   {seen: now.Add(-proto.EntryTTL - time.Second)},
				"fresh": {seen: now.Add(-proto.EntryTTL + time.Second)},
			},
		},
		sessions: make(map[string][]*exchangeSession),
	}

	s.entriesSweep(now)
	if _, ok := s.entries["room"]["old"]; ok {
		t.Fatal("expired entry retained")
	}
	if _, ok := s.entries["room"]["fresh"]; !ok {
		t.Fatal("fresh entry deleted")
	}
}

func TestExchangeRunRejectsInvalidArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
	}{
		{name: "missing address", code: 2},
		{name: "missing port", args: []string{"127.0.0.1"}, code: 1},
		{name: "invalid address", args: []string{"bad address"}, code: 1},
		{name: "zero port", args: []string{"127.0.0.1:0"}, code: 1},
		{name: "extra argument", args: []string{"127.0.0.1:7777", "extra"}, code: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := exchangeRun(test.args, &stderr); code != test.code {
				t.Fatalf("exchange run = %d, want %d; stderr=%q", code, test.code, stderr.String())
			}
		})
	}
}

func TestExchangeAddrResolve(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "portable wildcard", raw: "0:7777", want: "0.0.0.0:7777"},
		{name: "IPv4 wildcard", raw: "0.0.0.0:7777", want: "0.0.0.0:7777"},
		{name: "loopback", raw: "127.0.0.1:7777", want: "127.0.0.1:7777"},
	} {
		t.Run(test.name, func(t *testing.T) {
			addr, err := exchangeAddrResolve(test.raw)
			if err != nil {
				t.Fatalf("resolve %q: %v", test.raw, err)
			}
			if got := addr.String(); got != test.want {
				t.Fatalf("resolve %q = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestExchangeDiscoveryRecordsIncludePublicAndLocalCandidates(t *testing.T) {
	s := &exchangeServer{
		entries: map[string]map[proto.Handle]*exchangeEntry{
			"room": {
				"Alice": {
					addr:   &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 40000},
					local:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 50000},
					handle: "Alice",
				},
			},
		},
	}

	records := s.discoveryRecords("room", "")
	addresses := make(map[string]bool, len(records))
	for _, record := range records {
		if record.Handle != "Alice" {
			t.Fatalf("candidate handle = %q", record.Handle)
		}
		addresses[record.Addr().String()] = true
	}
	if len(records) != 2 || !addresses["198.51.100.1:40000"] || !addresses["10.0.0.2:50000"] {
		t.Fatalf("discovery records = %+v", records)
	}
	if excluded := s.discoveryRecords("room", "Alice"); len(excluded) != 0 {
		t.Fatalf("excluded discovery records = %+v", excluded)
	}
}

func exchangeClientSession(
	t *testing.T,
	conn *net.UDPConn,
	serverAddr *net.UDPAddr,
	serverPublic [sessioncrypto.PublicKeyBytes]byte,
) *sessioncrypto.Session {
	t.Helper()

	pair := testKeyPair(t)
	if _, err := conn.WriteToUDP(proto.KEX(pair.Public()), serverAddr); err != nil {
		t.Fatal(err)
	}

	public, ok := proto.KEXParse(udpRead(t, conn))
	if !ok || public != serverPublic {
		t.Fatalf("exchange KEX = %x/%t", public, ok)
	}

	zero := [32]byte{}
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

func exchangeRegister(
	t *testing.T,
	conn *net.UDPConn,
	serverAddr *net.UDPAddr,
	session *sessioncrypto.Session,
	handle proto.Handle,
	channel string,
) []proto.PeerRecord {
	t.Helper()

	payload, ok := proto.Request(handle, channel, conn.LocalAddr().(*net.UDPAddr))
	if !ok {
		t.Fatal("request rejected")
	}
	packet, err := session.Seal(proto.Type_Request, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDP(packet, serverAddr); err != nil {
		t.Fatal(err)
	}

	kind, _, payload, err := session.Open(udpRead(t, conn))
	if err != nil || kind != proto.Type_PeerList {
		t.Fatalf("peer list = %#x/%v", kind, err)
	}
	records, ok := proto.PeerListParse(payload)
	if !ok {
		t.Fatal("peer list rejected")
	}

	return records
}

func testKeyPair(t *testing.T) *sessioncrypto.KeyPair {
	t.Helper()

	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		t.Fatal(err)
	}

	return pair
}

func exchangePeerListSend(
	t *testing.T,
	conn *net.UDPConn,
	serverAddr *net.UDPAddr,
	session *sessioncrypto.Session,
	records []proto.PeerRecord,
) {
	t.Helper()

	payload, ok := proto.PeerList(records)
	if !ok {
		t.Fatal("peer list rejected")
	}
	packet, err := session.Seal(proto.Type_PeerListAudio, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDP(packet, serverAddr); err != nil {
		t.Fatal(err)
	}
}

func exchangePeerAddresses(records []proto.PeerRecord) map[proto.Handle]string {
	addresses := make(map[proto.Handle]string, len(records))
	for _, record := range records {
		addresses[record.Handle] = record.Addr().String()
	}

	return addresses
}

func expectUDPTimeout(t *testing.T, conn *net.UDPConn, name string) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, proto.MaxDatagram)
	if _, _, err := conn.ReadFromUDP(buffer); err == nil {
		t.Fatalf("%s received a datagram", name)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("%s read error: %v", name, err)
	}
}
