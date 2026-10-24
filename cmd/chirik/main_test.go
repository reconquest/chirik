package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"chirik/internal/audio"
	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

func TestConfigParseChirp(t *testing.T) {
	var stderr bytes.Buffer
	cfg, ok := configParse(
		[]string{
			"Alice42@127.0.0.1:7777/free-form/channel",
			"--source=capture",
			"--sink=playback",
		},
		&stderr,
	)
	if !ok {
		t.Fatalf("parse failed: %s", stderr.String())
	}

	if cfg.handle != "Alice42" || cfg.channel != "free-form/channel" ||
		cfg.channelKey != proto.ChannelKey("free-form/channel") ||
		cfg.peerex.String() != "127.0.0.1:7777" || cfg.source != "capture" || cfg.sink != "playback" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestConfigParseRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bad-handle@127.0.0.1:7777/room"},
		{strings.Repeat("A", proto.MaxHandleBytes+1) + "@127.0.0.1:7777/room"},
		{"Alice@127.0.0.1:7777/"},
		{"Alice@127.0.0.1:7777/" + strings.Repeat("x", proto.MaxPayload-len("Alice"))},
		{"Alice127.0.0.1:7777/room"},
		{"Alice@127.0.0.1/room"},
		{"Alice@127.0.0.1:7777/room", "--peer=127.0.0.1:9001"},
	} {
		var stderr bytes.Buffer
		if _, ok := configParse(args, &stderr); ok {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}

func TestLocalEndpointUsesRouteAddressAndListeningPort(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	remote := udpListen(t)
	defer remote.Close()

	local, err := localEndpoint(conn, remote.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	listenPort := conn.LocalAddr().(*net.UDPAddr).Port
	if !local.IP.Equal(net.IPv4(127, 0, 0, 1)) || local.Port != listenPort {
		t.Fatalf("local endpoint = %s, want 127.0.0.1:%d", local, listenPort)
	}
}

func TestRunRejectsRemovedMintCommand(t *testing.T) {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	if code := run([]string{"mint", "Echo"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run = %d", code)
	}
}

func TestOutput(t *testing.T) {
	var (
		stdout bytes.Buffer
		out    = output{writer: &stdout}
	)

	out.bitrateWrite(
		[]peerBitrate{
			{handle: "Alice", bytesReceived: 13400, bytesSent: 26800},
			{handle: "Bob", bytesReceived: 6700, bytesSent: 13400},
		},
		time.Second,
	)
	want := terminalLineClear + "Alice            | in   107.20 kbit/s | out   214.40 kbit/s\n" +
		terminalLineClear + "Bob              | in    53.60 kbit/s | out   107.20 kbit/s"
	if stdout.String() != want {
		t.Fatalf("bitrate output = %q, want %q", stdout.String(), want)
	}

	stdout.Reset()
	out.bitrateWrite(
		[]peerBitrate{{handle: "Alice", bytesReceived: 6700, bytesSent: 13400}},
		time.Second,
	)
	want = terminalLineClear + terminalCursorUp + terminalLineClear +
		terminalLineClear + "Alice            | in    53.60 kbit/s | out   107.20 kbit/s"
	if stdout.String() != want {
		t.Fatalf("bitrate redraw = %q, want %q", stdout.String(), want)
	}

	stdout.Reset()
	out.lineWrite("muted")
	want = terminalLineClear + terminalLineClear + "muted\n"
	if stdout.String() != want {
		t.Fatalf("status output = %q, want %q", stdout.String(), want)
	}

	stdout.Reset()
	out.bitrateWrite(nil, time.Second)
	if stdout.Len() != 0 {
		t.Fatalf("empty bitrate output = %q", stdout.String())
	}
}

func TestManagerPeerBitrates(t *testing.T) {
	m := &manager{links: make(map[string][]*link)}
	alice := &link{
		addr:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001},
		handle:        "Alice",
		handleKnown:   true,
		state:         linkState_Active,
		audioEligible: true,
	}
	bob := &link{
		addr:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1002},
		handle:        "Bob",
		handleKnown:   true,
		state:         linkState_Active,
		audioEligible: true,
	}
	peerex := &link{
		addr:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1003},
		handle:        "Exchange",
		handleKnown:   true,
		state:         linkState_Active,
		audioEligible: true,
		peerex:        true,
	}
	inactive := &link{
		addr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1004},
		handle:      "Inactive",
		handleKnown: true,
	}
	for _, item := range []*link{bob, peerex, inactive, alice} {
		m.linkAdd(item)
	}

	alice.counters.receivedBytes.Add(2000)
	alice.counters.sentBytes.Add(1000)
	bob.counters.receivedBytes.Add(4000)
	bob.counters.sentBytes.Add(3000)
	peerex.counters.receivedBytes.Add(6000)
	peerex.counters.sentBytes.Add(5000)

	rates := m.peerBitrates()
	if len(rates) != 2 ||
		rates[0] != (peerBitrate{handle: "Alice", bytesReceived: 2000, bytesSent: 1000}) ||
		rates[1] != (peerBitrate{handle: "Bob", bytesReceived: 4000, bytesSent: 3000}) {
		t.Fatalf("first peer bitrates = %+v", rates)
	}

	alice.counters.receivedBytes.Add(200)
	alice.counters.sentBytes.Add(100)
	bob.counters.receivedBytes.Add(400)
	bob.counters.sentBytes.Add(300)
	rates = m.peerBitrates()
	if len(rates) != 2 ||
		rates[0] != (peerBitrate{handle: "Alice", bytesReceived: 200, bytesSent: 100}) ||
		rates[1] != (peerBitrate{handle: "Bob", bytesReceived: 400, bytesSent: 300}) {
		t.Fatalf("delta peer bitrates = %+v", rates)
	}
}

func TestManagerLinkLabelsUseHandle(t *testing.T) {
	var (
		stdout  bytes.Buffer
		factory = &playbackTestFactory{written: make(chan struct{})}
		m       = &manager{
			playbackOpen: factory.open,
			output:       &output{writer: &stdout},
			links:        make(map[string][]*link),
			seen:         make(map[proto.Handle]struct{}),
		}
		item = &link{
			addr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7777},
			handle:      "Alice",
			handleKnown: true,
		}
	)
	m.linkAdd(item)
	if err := m.linkPromote(item, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}

	if names := factory.streamNames(); len(names) != 1 || names[0] != "chirik peer Alice@127.0.0.1:7777" {
		t.Fatalf("playback names = %q", names)
	}
	want := terminalLineClear + "peer connected: Alice@127.0.0.1:7777\n"
	if stdout.String() != want {
		t.Fatalf("connect output = %q, want %q", stdout.String(), want)
	}

	m.linkRemove(item, "test")
	want += terminalLineClear + "peer removed: Alice@127.0.0.1:7777 (test)\n"
	if stdout.String() != want {
		t.Fatalf("remove output = %q, want %q", stdout.String(), want)
	}
}

func TestManagerPeerHandshakeAndAudio(t *testing.T) {
	connA := udpListen(t)
	transportA := transportStart(connA)
	defer transportStop(transportA)
	connB := udpListen(t)
	transportB := transportStart(connB)
	defer transportStop(transportB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	channel := "room"
	managerA, playbackA := managerTestNew(
		ctx, transportA, handleWithByte(0xa1), channel, "127.0.0.1:1",
	)
	managerB, playbackB := managerTestNew(
		ctx, transportB, handleWithByte(0xb2), channel, "127.0.0.1:1",
	)

	record, ok := proto.PeerRecordFrom(
		connB.LocalAddr().(*net.UDPAddr),
		handleWithByte(0xb2),
	)
	if !ok {
		t.Fatal("peer record rejected")
	}
	managerA.candidateAdd(record, false, time.Now())
	if len(managerB.links) != 0 {
		t.Fatalf("passive manager started with links: %+v", managerB.links)
	}

	var (
		errorsA = make(chan error, 1)
		errorsB = make(chan error, 1)
	)
	go func() { errorsA <- managerA.run() }()
	go func() { errorsB <- managerB.run() }()

	waitCondition(
		t,
		func() bool { return playbackA.streamCount() == 1 && playbackB.streamCount() == 1 },
		"peer sessions",
	)

	payload := make([]byte, proto.PlainFrame)
	managerA.frames <- payload
	waitClosed(t, playbackB.written, "manager B playback")

	if playbackB.bytesWritten() != proto.FrameSamples*2 {
		t.Fatalf("playback B bytes = %d", playbackB.bytesWritten())
	}

	cancel()
	if err := <-errorsA; err != nil {
		t.Fatal(err)
	}
	if err := <-errorsB; err != nil {
		t.Fatal(err)
	}
	learned := managerB.links[connA.LocalAddr().String()]
	if len(learned) != 1 || !learned[0].handleKnown ||
		learned[0].handle != handleWithByte(0xa1) || !learned[0].stateActive() {
		t.Fatalf("passive manager learned links = %+v", learned)
	}
	managerA.close()
	managerB.close()
}

func TestManagerExchangePrefersDirectHandshakeAndAudio(t *testing.T) {
	serverConn := udpListen(t)
	exchangePair := testKeyPair(t)
	exchange := &exchangeServer{
		conn:     serverConn,
		logger:   log.New(io.Discard, "", 0),
		pair:     exchangePair,
		entries:  make(map[string]map[proto.Handle]*exchangeEntry),
		sessions: make(map[string][]*exchangeSession),
	}
	served := make(chan error, 1)
	go func() { served <- exchange.serve() }()
	defer func() {
		serverConn.Close()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	connA := udpListen(t)
	transportA := transportStart(connA)
	defer transportStop(transportA)
	connB := udpListen(t)
	transportB := transportStart(connB)
	defer transportStop(transportB)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	channel := "direct-preferred-room"
	handleA := handleWithByte(0xa1)
	handleB := handleWithByte(0xb2)
	serverAddr := serverConn.LocalAddr().String()
	managerA, playbackA := managerTestNew(ctxA, transportA, handleA, channel, serverAddr)
	managerB, playbackB := managerTestNew(ctxB, transportB, handleB, channel, serverAddr)

	start := func(manager *manager) <-chan error {
		t.Helper()
		initial, err := manager.initialLink()
		if err != nil {
			t.Fatal(err)
		}
		manager.linkAdd(initial)
		manager.linkKEXSend(initial, time.Now())
		errors := make(chan error, 1)
		go func() { errors <- manager.run() }()
		return errors
	}
	errorsA := start(managerA)
	waitClosed(t, managerA.readyCh, "manager A exchange registration")
	errorsB := start(managerB)
	waitClosed(t, managerB.readyCh, "manager B exchange registration")
	waitCondition(
		t,
		func() bool { return playbackA.streamCount() == 1 && playbackB.streamCount() == 1 },
		"relayed peer sessions",
	)

	managerA.frames <- make([]byte, proto.PlainFrame)
	waitClosed(t, playbackB.written, "relayed manager B playback")
	if playbackB.bytesWritten() != proto.FrameSamples*2 {
		t.Fatalf("relayed playback B bytes = %d", playbackB.bytesWritten())
	}

	cancelA()
	cancelB()
	if err := <-errorsA; err != nil {
		t.Fatal(err)
	}
	if err := <-errorsB; err != nil {
		t.Fatal(err)
	}
	if links := managerA.links[relayLinkKey(handleB)]; len(links) != 0 {
		t.Fatalf("manager A retained fallback relay links = %+v", links)
	}
	if links := managerB.links[relayLinkKey(handleA)]; len(links) != 0 {
		t.Fatalf("manager B retained fallback relay links = %+v", links)
	}
	directActive := func(manager *manager, handle proto.Handle) bool {
		for _, links := range manager.links {
			for _, item := range links {
				if !item.peerex && !item.relay && item.stateActive() &&
					item.handleKnown && item.handle == handle {
					return true
				}
			}
		}
		return false
	}
	if !directActive(managerA, handleB) || !directActive(managerB, handleA) {
		t.Fatal("direct path did not win before relay fallback")
	}
	managerA.close()
	managerB.close()
}

func TestManagerExchangeFallsBackToRelay(t *testing.T) {
	serverConn := udpListen(t)
	exchangePair := testKeyPair(t)
	exchange := &exchangeServer{
		conn:     serverConn,
		logger:   log.New(io.Discard, "", 0),
		pair:     exchangePair,
		entries:  make(map[string]map[proto.Handle]*exchangeEntry),
		sessions: make(map[string][]*exchangeSession),
	}
	exchange.endpointRecords = func(
		_ *net.UDPAddr,
		_ *net.UDPAddr,
		handle proto.Handle,
	) []proto.PeerRecord {
		return []proto.PeerRecord{{
			IP:     [4]byte{192, 0, 2, 123},
			Port:   40000,
			Handle: handle,
		}}
	}
	served := make(chan error, 1)
	go func() { served <- exchange.serve() }()
	defer func() {
		serverConn.Close()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	connA := udpListen(t)
	transportA := transportStart(connA)
	defer transportStop(transportA)
	connB := udpListen(t)
	transportB := transportStart(connB)
	defer transportStop(transportB)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	channel := "relay-fallback-room"
	handleA := handleWithByte(0xa1)
	handleB := handleWithByte(0xb2)
	serverAddr := serverConn.LocalAddr().String()
	managerA, playbackA := managerTestNew(ctxA, transportA, handleA, channel, serverAddr)
	managerB, playbackB := managerTestNew(ctxB, transportB, handleB, channel, serverAddr)

	start := func(manager *manager) <-chan error {
		t.Helper()
		initial, err := manager.initialLink()
		if err != nil {
			t.Fatal(err)
		}
		manager.linkAdd(initial)
		manager.linkKEXSend(initial, time.Now())
		errors := make(chan error, 1)
		go func() { errors <- manager.run() }()
		return errors
	}
	errorsA := start(managerA)
	waitClosed(t, managerA.readyCh, "manager A exchange registration")
	fallbackStart := time.Now()
	errorsB := start(managerB)
	waitClosed(t, managerB.readyCh, "manager B exchange registration")
	waitCondition(
		t,
		func() bool { return playbackA.streamCount() == 1 && playbackB.streamCount() == 1 },
		"relay fallback peer sessions",
	)
	if elapsed := time.Since(fallbackStart); elapsed < proto.RelayFallbackDelay-250*time.Millisecond {
		t.Fatalf("relay activated before direct window: %s", elapsed)
	}

	managerA.frames <- make([]byte, proto.PlainFrame)
	waitClosed(t, playbackB.written, "fallback relay playback")
	if playbackB.bytesWritten() != proto.FrameSamples*2 {
		t.Fatalf("fallback relay playback bytes = %d", playbackB.bytesWritten())
	}

	cancelA()
	cancelB()
	if err := <-errorsA; err != nil {
		t.Fatal(err)
	}
	if err := <-errorsB; err != nil {
		t.Fatal(err)
	}
	linksA := managerA.links[relayLinkKey(handleB)]
	linksB := managerB.links[relayLinkKey(handleA)]
	if len(linksA) != 1 || !linksA[0].relay || !linksA[0].stateActive() ||
		linksA[0].handle != handleB {
		t.Fatalf("manager A fallback relay links = %+v", linksA)
	}
	if len(linksB) != 1 || !linksB[0].relay || !linksB[0].stateActive() ||
		linksB[0].handle != handleA {
		t.Fatalf("manager B fallback relay links = %+v", linksB)
	}
	managerA.close()
	managerB.close()
}

func TestManagerCandidateDeduplicatesHandle(t *testing.T) {
	conn := udpListen(t)
	transport := transportStart(conn)
	defer transportStop(transport)
	target := udpListen(t)
	defer target.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, _ := managerTestNew(
		ctx, transport, handleWithByte(1), "room", target.LocalAddr().String(),
	)
	record, ok := proto.PeerRecordFrom(target.LocalAddr().(*net.UDPAddr), handleWithByte(2))
	if !ok {
		t.Fatal("peer record rejected")
	}

	if !manager.candidateAdd(record, false, time.Now()) {
		t.Fatal("new candidate rejected")
	}
	if manager.candidateAdd(record, false, time.Now()) {
		t.Fatal("duplicate candidate accepted")
	}
	if len(manager.links[target.LocalAddr().String()]) != 1 {
		t.Fatalf("candidate links = %d", len(manager.links[target.LocalAddr().String()]))
	}
}

func TestManagerRemovedCandidateCanBeRediscovered(t *testing.T) {
	var (
		conn      = udpListen(t)
		transport = transportStart(conn)
		target    = udpListen(t)
	)
	defer transportStop(transport)
	defer target.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, _ := managerTestNew(
		ctx, transport, handleWithByte(1), "room", "127.0.0.1:1",
	)
	record, ok := proto.PeerRecordFrom(target.LocalAddr().(*net.UDPAddr), handleWithByte(2))
	if !ok {
		t.Fatal("peer record rejected")
	}
	payload, ok := proto.PeerList([]proto.PeerRecord{record})
	if !ok {
		t.Fatal("peer list rejected")
	}
	peerex := &link{peerex: true}
	if !manager.peerListHandle(peerex, payload, false, time.Now()) {
		t.Fatal("initial peer list rejected")
	}

	key := relayLinkKey(record.Handle)
	firstRelayLinks := manager.links[key]
	firstDirectLinks := manager.links[target.LocalAddr().String()]
	if len(firstRelayLinks) != 1 || !firstRelayLinks[0].relay || len(firstDirectLinks) != 1 {
		t.Fatalf("initial direct/relay candidates = direct:%+v relay:%+v", firstDirectLinks, firstRelayLinks)
	}
	firstRelay := firstRelayLinks[0]
	firstDirect := firstDirectLinks[0]
	manager.linkRemove(firstDirect, "test failure")
	manager.linkRemove(firstRelay, "test failure")
	if _, exists := manager.seen[record.Handle]; exists {
		t.Fatal("removed candidates remained permanently seen")
	}
	if !manager.peerListHandle(peerex, payload, false, time.Now()) {
		t.Fatal("repeat peer list rejected")
	}

	relayLinks := manager.links[key]
	directLinks := manager.links[target.LocalAddr().String()]
	if len(relayLinks) != 1 || relayLinks[0] == firstRelay || !relayLinks[0].relay ||
		len(directLinks) != 1 || directLinks[0] == firstDirect {
		t.Fatalf("rediscovered candidates = direct:%+v relay:%+v", directLinks, relayLinks)
	}
}

func TestManagerPeerExchangeUpdatesKnownHandleEndpoint(t *testing.T) {
	var (
		conn      = udpListen(t)
		transport = transportStart(conn)
		oldTarget = udpListen(t)
		newTarget = udpListen(t)
	)
	defer transportStop(transport)
	defer oldTarget.Close()
	defer newTarget.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, _ := managerTestNew(
		ctx, transport, handleWithByte(1), "room", "127.0.0.1:1",
	)
	handle := handleWithByte(2)
	oldItem := &link{
		addr:          addrCopy(oldTarget.LocalAddr().(*net.UDPAddr)),
		handle:        handle,
		handleKnown:   true,
		state:         linkState_Active,
		audioEligible: true,
	}
	manager.linkAdd(oldItem)
	manager.seen[handle] = struct{}{}

	record, ok := proto.PeerRecordFrom(newTarget.LocalAddr().(*net.UDPAddr), handle)
	if !ok {
		t.Fatal("replacement peer record rejected")
	}
	payload, ok := proto.PeerList([]proto.PeerRecord{record})
	if !ok {
		t.Fatal("replacement peer list rejected")
	}
	peerex := &link{peerex: true}
	if !manager.peerListHandle(peerex, payload, false, time.Now()) {
		t.Fatal("replacement peer list rejected")
	}

	relayLinks := manager.links[relayLinkKey(handle)]
	newLinks := manager.links[newTarget.LocalAddr().String()]
	if len(relayLinks) != 1 || !relayLinks[0].relay ||
		!relayLinks[0].expectedKnown || relayLinks[0].expectedHandle != handle {
		t.Fatalf("replacement relay candidate = %+v", relayLinks)
	}
	if len(newLinks) != 1 || !newLinks[0].expectedKnown || newLinks[0].expectedHandle != handle {
		t.Fatalf("replacement direct candidate = %+v", newLinks)
	}
	if len(manager.links[oldTarget.LocalAddr().String()]) != 1 {
		t.Fatal("old peer removed before replacement authentication")
	}
	if _, ok := proto.KEXParse(udpRead(t, newTarget)); !ok {
		t.Fatal("replacement direct endpoint did not receive KEX")
	}

	records := manager.peerRecords(manager.cfg.handle)
	addresses := make(map[string]bool, len(records))
	for _, record := range records {
		addresses[record.Addr().String()] = true
	}
	if len(records) != 2 || !addresses[oldTarget.LocalAddr().String()] ||
		!addresses[newTarget.LocalAddr().String()] {
		t.Fatalf("hybrid replacement snapshot = %+v", records)
	}

	if !manager.peerListHandle(peerex, payload, false, time.Now()) {
		t.Fatal("duplicate replacement peer list rejected")
	}
	if len(manager.links[relayLinkKey(handle)]) != 1 ||
		len(manager.links[newTarget.LocalAddr().String()]) != 1 {
		t.Fatal("duplicate hybrid candidates created")
	}
}

func TestManagerAuthoritativeCandidatesRaceAndFirstPromotionWins(t *testing.T) {
	conn := udpListen(t)
	transport := transportStart(conn)
	defer transportStop(transport)
	publicTarget := udpListen(t)
	defer publicTarget.Close()
	localTarget := udpListen(t)
	defer localTarget.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, _ := managerTestNew(
		ctx, transport, handleWithByte(1), "room", "127.0.0.1:1",
	)
	handle := handleWithByte(2)
	publicRecord, ok := proto.PeerRecordFrom(publicTarget.LocalAddr().(*net.UDPAddr), handle)
	if !ok {
		t.Fatal("public candidate rejected")
	}
	localRecord, ok := proto.PeerRecordFrom(localTarget.LocalAddr().(*net.UDPAddr), handle)
	if !ok {
		t.Fatal("local candidate rejected")
	}
	payload, ok := proto.PeerList([]proto.PeerRecord{publicRecord, localRecord})
	if !ok {
		t.Fatal("candidate peer list rejected")
	}

	peerex := &link{peerex: true}
	if !manager.peerListHandle(peerex, payload, false, time.Now()) {
		t.Fatal("authoritative candidate list rejected")
	}
	relayLinks := manager.links[relayLinkKey(handle)]
	publicLinks := manager.links[publicTarget.LocalAddr().String()]
	localLinks := manager.links[localTarget.LocalAddr().String()]
	if len(relayLinks) != 1 || !relayLinks[0].relay ||
		len(publicLinks) != 1 || len(localLinks) != 1 {
		t.Fatalf(
			"authoritative hybrid candidates = public:%+v local:%+v relay:%+v",
			publicLinks, localLinks, relayLinks,
		)
	}
	if _, ok := proto.KEXParse(udpRead(t, publicTarget)); !ok {
		t.Fatal("public candidate did not receive KEX")
	}
	if _, ok := proto.KEXParse(udpRead(t, localTarget)); !ok {
		t.Fatal("local candidate did not receive KEX")
	}

	winner := localLinks[0]
	winner.handle = handle
	winner.handleKnown = true
	if err := manager.linkPromote(winner, time.Now()); err != nil {
		t.Fatalf("promote local candidate: %v", err)
	}
	if len(manager.links[publicTarget.LocalAddr().String()]) != 0 ||
		len(manager.links[relayLinkKey(handle)]) != 0 {
		t.Fatal("losing public/relay candidates retained")
	}
	remaining := manager.links[localTarget.LocalAddr().String()]
	if len(remaining) != 1 || remaining[0] != winner || !winner.stateActive() {
		t.Fatalf("winning local candidate = %+v", remaining)
	}
}

func TestManagerPendingCandidateRepliesToKEX(t *testing.T) {
	conn := udpListen(t)
	transport := transportStart(conn)
	defer transportStop(transport)
	target := udpListen(t)
	defer target.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, _ := managerTestNew(
		ctx, transport, handleWithByte(1), "room", "127.0.0.1:1",
	)

	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		t.Fatal(err)
	}
	remotePair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		t.Fatal(err)
	}

	item := &link{
		addr:      addrCopy(target.LocalAddr().(*net.UDPAddr)),
		pair:      pair,
		state:     linkState_KEX,
		initiated: true,
	}
	manager.linkAdd(item)
	now := time.Unix(100, 0)
	manager.kexHandle(item.addr, remotePair.Public(), now)

	if !item.lastKEXSent.Equal(now) || item.voice == nil || item.state != linkState_Request {
		t.Fatalf(
			"KEX reply state = sent:%s voice:%t state:%d",
			item.lastKEXSent, item.voice != nil, item.state,
		)
	}
}

func TestManagerPeerListBroadcasts(t *testing.T) {
	var (
		conn      = udpListen(t)
		transport = transportStart(conn)
		targetA   = udpListen(t)
		targetB   = udpListen(t)
	)
	defer transportStop(transport)
	defer targetA.Close()
	defer targetB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		manager, _ = managerTestNew(
			ctx, transport, handleWithByte(1), "room", "127.0.0.1:1",
		)
		clientA, remoteA = sessionTestPair(t, 1)
		clientB, remoteB = sessionTestPair(t, 3)
		handleA          = handleWithByte(0xa1)
		handleB          = handleWithByte(0xb2)
		itemA            = &link{
			addr:          addrCopy(targetA.LocalAddr().(*net.UDPAddr)),
			voice:         clientA,
			handle:        handleA,
			handleKnown:   true,
			state:         linkState_Active,
			audioEligible: true,
		}
		itemB = &link{
			addr:          addrCopy(targetB.LocalAddr().(*net.UDPAddr)),
			voice:         clientB,
			handle:        handleB,
			handleKnown:   true,
			state:         linkState_Active,
			audioEligible: true,
		}
	)
	manager.linkAdd(itemA)
	manager.linkAdd(itemB)
	manager.peerListBroadcast()

	for _, test := range []struct {
		name           string
		conn           *net.UDPConn
		remote         *sessioncrypto.Session
		expectedHandle proto.Handle
		expectedAddr   string
	}{
		{"A", targetA, remoteA, handleB, targetB.LocalAddr().String()},
		{"B", targetB, remoteB, handleA, targetA.LocalAddr().String()},
	} {
		t.Run(test.name, func(t *testing.T) {
			kind, _, payload, err := test.remote.Open(udpRead(t, test.conn))
			if err != nil {
				t.Fatal(err)
			}
			records, ok := proto.PeerListParse(payload)
			if kind != proto.Type_PeerListAudio || !ok || len(records) != 1 ||
				records[0].Handle != test.expectedHandle || records[0].Addr().String() != test.expectedAddr {
				t.Fatalf("broadcast peer list = %#x, %+v, %t", kind, records, ok)
			}
		})
	}
}

func TestManagerBroadcastsPeerListToExchange(t *testing.T) {
	var (
		conn         = udpListen(t)
		transport    = transportStart(conn)
		exchangeConn = udpListen(t)
	)
	defer transportStop(transport)
	defer exchangeConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, _ := managerTestNew(
		ctx, transport, "Alice", "room", exchangeConn.LocalAddr().String(),
	)
	client, remote := sessionTestPair(t, 1)
	manager.linkAdd(&link{
		addr:   addrCopy(exchangeConn.LocalAddr().(*net.UDPAddr)),
		voice:  client,
		state:  linkState_Active,
		peerex: true,
	})
	manager.linkAdd(&link{
		addr:          &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 9000},
		handle:        "Bob",
		handleKnown:   true,
		state:         linkState_Active,
		audioEligible: true,
	})

	manager.peerListBroadcast()
	kind, _, payload, err := remote.Open(udpRead(t, exchangeConn))
	if err != nil || kind != proto.Type_PeerListAudio {
		t.Fatalf("exchange update = %#x/%v", kind, err)
	}
	records, ok := proto.PeerListParse(payload)
	if !ok || len(records) != 1 || records[0].Handle != "Bob" ||
		records[0].Addr().String() != "192.0.2.10:9000" {
		t.Fatalf("exchange update peers = %+v/%t", records, ok)
	}
}

func TestManagerDiscoveredPeerBroadcasts(t *testing.T) {
	var (
		conn      = udpListen(t)
		transport = transportStart(conn)
		targetA   = udpListen(t)
		targetB   = udpListen(t)
	)
	defer transportStop(transport)
	defer targetA.Close()
	defer targetB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		manager, _ = managerTestNew(
			ctx, transport, handleWithByte(1), "room", "127.0.0.1:1",
		)
		clientA, remoteA = sessionTestPair(t, 1)
		handleA          = handleWithByte(0xa1)
		itemA            = &link{
			addr:          addrCopy(targetA.LocalAddr().(*net.UDPAddr)),
			voice:         clientA,
			handle:        handleA,
			handleKnown:   true,
			state:         linkState_Active,
			audioEligible: true,
		}
		handleB = handleWithByte(0xb2)
	)
	_ = remoteA
	manager.linkAdd(itemA)

	recordB, ok := proto.PeerRecordFrom(targetB.LocalAddr().(*net.UDPAddr), handleB)
	if !ok {
		t.Fatal("peer record rejected")
	}
	payload, ok := proto.PeerList([]proto.PeerRecord{recordB})
	if !ok {
		t.Fatal("peer list rejected")
	}
	peerex := &link{peerex: true}
	if !manager.peerListHandle(peerex, payload, false, time.Unix(100, 0)) {
		t.Fatal("peer list rejected")
	}

	expectUDPTimeout(t, targetA, "relayed discovery broadcast")

	links := manager.links[relayLinkKey(handleB)]
	if len(links) != 1 || !links[0].relay || !links[0].expectedKnown ||
		links[0].expectedHandle != handleB || links[0].state != linkState_KEX {
		t.Fatalf("discovered relay candidate = %+v", links)
	}

	if !manager.peerListHandle(peerex, payload, false, time.Unix(101, 0)) {
		t.Fatal("duplicate peer list rejected")
	}
	if err := targetA.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, proto.MaxDatagram)
	if _, _, err := targetA.ReadFromUDP(buffer); err == nil {
		t.Fatal("duplicate peer list triggered broadcast")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("unexpected read error: %v", err)
	}
}

func TestManagerPeerRemovalBroadcasts(t *testing.T) {
	var (
		conn      = udpListen(t)
		transport = transportStart(conn)
		targetA   = udpListen(t)
	)
	defer transportStop(transport)
	defer targetA.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		manager, _ = managerTestNew(
			ctx, transport, handleWithByte(1), "room", "127.0.0.1:1",
		)
		clientA, remoteA = sessionTestPair(t, 1)
		handleA          = handleWithByte(0xa1)
		itemA            = &link{
			addr:          addrCopy(targetA.LocalAddr().(*net.UDPAddr)),
			voice:         clientA,
			handle:        handleA,
			handleKnown:   true,
			state:         linkState_Active,
			audioEligible: true,
		}
		itemB = &link{
			addr:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2},
			handle:        handleWithByte(0xb2),
			handleKnown:   true,
			state:         linkState_Active,
			audioEligible: true,
		}
	)
	manager.linkAdd(itemA)
	manager.linkAdd(itemB)
	manager.linkRemove(itemB, "test")

	kind, _, payload, err := remoteA.Open(udpRead(t, targetA))
	if err != nil {
		t.Fatal(err)
	}
	records, ok := proto.PeerListParse(payload)
	if kind != proto.Type_PeerListAudio || !ok || len(records) != 0 {
		t.Fatalf("removal peer update = %#x, %+v, %t", kind, records, ok)
	}
}

func TestManagerPeerExchangeDoesNotPoll(t *testing.T) {
	var (
		conn      = udpListen(t)
		transport = transportStart(conn)
		target    = udpListen(t)
	)
	defer transportStop(transport)
	defer target.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, _ := managerTestNew(
		ctx, transport, handleWithByte(1), "room", target.LocalAddr().String(),
	)

	now := time.Unix(100, 0)
	item := &link{
		addr:             addrCopy(target.LocalAddr().(*net.UDPAddr)),
		state:            linkState_Request,
		peerex:           true,
		requestAttempts:  1,
		requestNext:      now.Add(-time.Second),
		responseDeadline: now.Add(time.Second),
	}
	manager.linkAdd(item)
	peerList, _ := proto.PeerList(nil)
	if !manager.peerListHandle(item, peerList, false, now) {
		t.Fatal("peer-exchange response rejected")
	}
	if err := manager.tick(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(manager.links[item.addr.String()]) != 1 || item.state != linkState_Active ||
		!item.responseReceived || item.requestAttempts != 0 || !item.requestNext.IsZero() ||
		!item.responseDeadline.IsZero() {
		t.Fatalf(
			"peer-exchange state = links:%d state:%d received:%t attempts:%d next:%s deadline:%s",
			len(manager.links[item.addr.String()]), item.state, item.responseReceived,
			item.requestAttempts, item.requestNext, item.responseDeadline,
		)
	}

	if err := target.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, proto.MaxDatagram)
	if _, _, err := target.ReadFromUDP(buffer); err == nil {
		t.Fatal("active peer-exchange session sent a periodic request")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("unexpected read error: %v", err)
	}
}

func TestTermiosRawPreservesOutputFlags(t *testing.T) {
	original := syscall.Termios{
		Iflag: syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
			syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON,
		Oflag: syscall.OPOST,
		Lflag: syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN,
		Cflag: syscall.CS7 | syscall.PARENB,
	}
	term := termiosRaw(original)
	if term.Oflag != original.Oflag {
		t.Fatalf("output flags changed: %#x -> %#x", original.Oflag, term.Oflag)
	}

	if term.Iflag != 0 || term.Lflag != 0 {
		t.Fatalf("input/local flags retained: %#x/%#x", term.Iflag, term.Lflag)
	}

	if term.Cflag&syscall.CSIZE != syscall.CS8 || term.Cflag&syscall.PARENB != 0 {
		t.Fatalf("control flags = %#x", term.Cflag)
	}
}

type playbackTestFactory struct {
	mu      sync.Mutex
	streams []*playbackTest
	names   []string
	written chan struct{}
	once    sync.Once
}

type playbackTest struct {
	factory *playbackTestFactory
	mu      sync.Mutex
	bytes   int
	closed  bool
}

func managerTestNew(
	ctx context.Context,
	transport *transport,
	handle proto.Handle,
	channel string,
	peerex string,
) (*manager, *playbackTestFactory) {
	var (
		peerexAddr, _ = net.ResolveUDPAddr("udp4", peerex)
		factory       = &playbackTestFactory{written: make(chan struct{})}
		manager       = &manager{
			ctx: ctx,
			t:   transport,
			cfg: config{
				handle:     handle,
				channel:    channel,
				channelKey: proto.ChannelKey(channel),
				peerex:     peerexAddr,
			},
			local:        addrCopy(transport.conn.LocalAddr().(*net.UDPAddr)),
			playbackOpen: factory.open,
			output:       &output{writer: io.Discard},
			stderr:       io.Discard,
			links:        make(map[string][]*link),
			seen:         map[proto.Handle]struct{}{handle: {}},
			frames:       make(chan []byte, 8),
			commands:     make(chan byte, 8),
			events:       make(chan error, 8),
			readyCh:      make(chan struct{}),
		}
	)
	manager.discoveryEnsure()

	return manager, factory
}

func (f *playbackTestFactory) open(name string) (audio.PlaybackWriter, error) {
	stream := &playbackTest{factory: f}
	f.mu.Lock()
	f.streams = append(f.streams, stream)
	f.names = append(f.names, name)
	f.mu.Unlock()

	return stream, nil
}

func (f *playbackTestFactory) streamCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.streams)
}

func (f *playbackTestFactory) streamNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.names...)
}

func (f *playbackTestFactory) bytesWritten() int {
	f.mu.Lock()
	streams := append([]*playbackTest(nil), f.streams...)
	f.mu.Unlock()

	total := 0
	for _, stream := range streams {
		stream.mu.Lock()
		total += stream.bytes
		stream.mu.Unlock()
	}

	return total
}

func (p *playbackTest) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}

	p.bytes += len(data)
	p.factory.once.Do(func() { close(p.factory.written) })

	return len(data), nil
}

func (p *playbackTest) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

func handleWithByte(value byte) proto.Handle {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	return proto.Handle("peer" + string(alphabet[value%byte(len(alphabet))]))
}

func waitClosed(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s timed out", name)
	}
}

func waitCondition(t *testing.T, condition func() bool, name string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%s timed out", name)
}

func udpListen(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}

	return conn
}

func transportStop(t *transport) {
	t.conn.Close()
	<-t.stopped
}

func udpRead(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	packet := make([]byte, proto.MaxDatagram)
	n, _, err := conn.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}

	return bytes.Clone(packet[:n])
}

func sessionTestPair(
	t *testing.T,
	seed byte,
) (*sessioncrypto.Session, *sessioncrypto.Session) {
	t.Helper()

	var (
		clientKeys sessioncrypto.Keys
		remoteKeys sessioncrypto.Keys
	)
	clientKeys.Send[0] = seed
	clientKeys.Receive[0] = seed + 1
	remoteKeys.Send = clientKeys.Receive
	remoteKeys.Receive = clientKeys.Send

	client, err := sessioncrypto.SessionNew(clientKeys)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := sessioncrypto.SessionNew(remoteKeys)
	if err != nil {
		t.Fatal(err)
	}

	return client, remote
}
