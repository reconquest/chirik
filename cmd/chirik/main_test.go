package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
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

func TestRunMintPrefix(t *testing.T) {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	if code := run([]string{"mint", "Echo"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d: %s", code, stderr.String())
	}

	var (
		text         = strings.TrimSpace(stdout.String())
		decoded, err = base64.StdEncoding.DecodeString(text)
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded) != proto.CallsignBytes || !strings.HasPrefix(text, "Echo") {
		t.Fatalf("minted callsign = %q", text)
	}
}

func TestCallsignMintRejectsInvalidPrefix(t *testing.T) {
	if _, err := callsignMint("not-valid_", strings.NewReader(strings.Repeat("x", proto.CallsignBytes))); err == nil {
		t.Fatal("invalid prefix accepted")
	}
}

func TestBase64FixedDecodeRejectsNonCanonicalValue(t *testing.T) {
	text := []byte(base64.StdEncoding.EncodeToString(make([]byte, proto.CallsignBytes)))
	text[len(text)-2] = 'B'

	var callsign proto.Callsign
	if base64FixedDecode(callsign[:], string(text)) {
		t.Fatal("non-canonical base64 accepted")
	}
}

func TestConfigParseChirp(t *testing.T) {
	var (
		stderr   bytes.Buffer
		callsign = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, proto.CallsignBytes))
		channel  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, proto.ChannelBytes))
	)

	cfg, ok := configParse(
		[]string{
			callsign,
			"127.0.0.1:7777/" + channel,
			"--source=capture",
			"--sink=playback",
		},
		&stderr,
	)
	if !ok {
		t.Fatalf("parse failed: %s", stderr.String())
	}

	if cfg.peerex.String() != "127.0.0.1:7777" || cfg.source != "capture" || cfg.sink != "playback" {
		t.Fatalf("config = %+v", cfg)
	}

	if base64.StdEncoding.EncodeToString(cfg.callsign[:]) != callsign ||
		base64.StdEncoding.EncodeToString(cfg.channel[:]) != channel {
		t.Fatal("callsign or channel differs")
	}
}

func TestConfigParseRejectsInvalidArguments(t *testing.T) {
	var (
		callsign = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, proto.CallsignBytes))
		channel  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, proto.ChannelBytes))
	)

	for _, args := range [][]string{
		{"short", "127.0.0.1:7777/" + channel},
		{callsign, "127.0.0.1:7777/short"},
		{callsign, channel},
		{callsign, "127.0.0.1:7777/" + channel, "--peer=127.0.0.1:9001"},
		{callsign, "127.0.0.1:7777/" + channel, "--listen=:9000"},
	} {
		var stderr bytes.Buffer
		if _, ok := configParse(args, &stderr); ok {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}

func TestOutput(t *testing.T) {
	var (
		stdout bytes.Buffer
		out    = output{writer: &stdout}
	)

	out.bitrateWrite(13400, 26800, time.Second, 2)
	want := terminalLineClear +
		"peers   2 | in   107.20 kbit/s | out   214.40 kbit/s"
	if stdout.String() != want {
		t.Fatalf("bitrate output = %q, want %q", stdout.String(), want)
	}

	stdout.Reset()
	out.lineWrite("muted")
	want = terminalLineClear + "muted\n"
	if stdout.String() != want {
		t.Fatalf("status output = %q, want %q", stdout.String(), want)
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
	var channel proto.Channel
	channel[0] = 0x42
	managerA, playbackA := managerTestNew(
		ctx, transportA, callsignWithByte(0xa1), channel, "127.0.0.1:1",
	)
	managerB, playbackB := managerTestNew(
		ctx, transportB, callsignWithByte(0xb2), channel, "127.0.0.1:1",
	)

	record, ok := proto.PeerRecordFrom(
		connB.LocalAddr().(*net.UDPAddr),
		callsignWithByte(0xb2),
	)
	if !ok {
		t.Fatal("peer record rejected")
	}
	managerA.candidateAdd(record, false, time.Now())

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
	managerA.close()
	managerB.close()
}

func TestManagerCandidateDeduplicatesCallsign(t *testing.T) {
	conn := udpListen(t)
	transport := transportStart(conn)
	defer transportStop(transport)
	target := udpListen(t)
	defer target.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, _ := managerTestNew(
		ctx, transport, callsignWithByte(1), proto.Channel{}, target.LocalAddr().String(),
	)
	record, ok := proto.PeerRecordFrom(target.LocalAddr().(*net.UDPAddr), callsignWithByte(2))
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
		ctx, transport, callsignWithByte(1), proto.Channel{}, "127.0.0.1:1",
	)
	record, ok := proto.PeerRecordFrom(target.LocalAddr().(*net.UDPAddr), callsignWithByte(2))
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

	first := manager.links[target.LocalAddr().String()][0]
	manager.linkRemove(first, "test failure")
	if _, exists := manager.seen[record.Callsign]; exists {
		t.Fatal("removed candidate remained permanently seen")
	}
	if !manager.peerListHandle(peerex, payload, false, time.Now()) {
		t.Fatal("repeat peer list rejected")
	}

	links := manager.links[target.LocalAddr().String()]
	if len(links) != 1 || links[0] == first {
		t.Fatalf("rediscovered candidate links = %+v", links)
	}
}

func TestManagerPeerExchangeUpdatesKnownCallsignEndpoint(t *testing.T) {
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
		ctx, transport, callsignWithByte(1), proto.Channel{}, "127.0.0.1:1",
	)
	callsign := callsignWithByte(2)
	oldItem := &link{
		addr:          addrCopy(oldTarget.LocalAddr().(*net.UDPAddr)),
		callsign:      callsign,
		callsignKnown: true,
		state:         linkState_Active,
		audioEligible: true,
	}
	manager.linkAdd(oldItem)
	manager.seen[callsign] = struct{}{}

	record, ok := proto.PeerRecordFrom(newTarget.LocalAddr().(*net.UDPAddr), callsign)
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

	newLinks := manager.links[newTarget.LocalAddr().String()]
	if len(newLinks) != 1 || !newLinks[0].expectedKnown || newLinks[0].expectedCallsign != callsign {
		t.Fatalf("replacement candidate = %+v", newLinks)
	}
	if len(manager.links[oldTarget.LocalAddr().String()]) != 1 {
		t.Fatal("old peer removed before replacement authentication")
	}
	if _, ok := proto.KEXParse(udpRead(t, newTarget)); !ok {
		t.Fatal("replacement endpoint did not receive KEX")
	}

	records := manager.peerRecords(manager.cfg.callsign)
	if len(records) != 1 || records[0].Callsign != callsign ||
		records[0].Addr().String() != newTarget.LocalAddr().String() {
		t.Fatalf("replacement snapshot = %+v", records)
	}

	if !manager.peerListHandle(peerex, payload, false, time.Now()) {
		t.Fatal("duplicate replacement peer list rejected")
	}
	if len(manager.links[newTarget.LocalAddr().String()]) != 1 {
		t.Fatal("duplicate replacement candidate created")
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
		ctx, transport, callsignWithByte(1), proto.Channel{2}, "127.0.0.1:1",
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
			ctx, transport, callsignWithByte(1), proto.Channel{2}, "127.0.0.1:1",
		)
		clientA, remoteA = sessionTestPair(t, 1)
		clientB, remoteB = sessionTestPair(t, 3)
		callsignA        = callsignWithByte(0xa1)
		callsignB        = callsignWithByte(0xb2)
		itemA            = &link{
			addr:          addrCopy(targetA.LocalAddr().(*net.UDPAddr)),
			voice:         clientA,
			callsign:      callsignA,
			callsignKnown: true,
			state:         linkState_Active,
			audioEligible: true,
		}
		itemB = &link{
			addr:          addrCopy(targetB.LocalAddr().(*net.UDPAddr)),
			voice:         clientB,
			callsign:      callsignB,
			callsignKnown: true,
			state:         linkState_Active,
			audioEligible: true,
		}
	)
	manager.linkAdd(itemA)
	manager.linkAdd(itemB)
	manager.peerListBroadcast()

	for _, test := range []struct {
		name             string
		conn             *net.UDPConn
		remote           *sessioncrypto.Session
		expectedCallsign proto.Callsign
		expectedAddr     string
	}{
		{"A", targetA, remoteA, callsignB, targetB.LocalAddr().String()},
		{"B", targetB, remoteB, callsignA, targetA.LocalAddr().String()},
	} {
		t.Run(test.name, func(t *testing.T) {
			kind, _, payload, err := test.remote.Open(udpRead(t, test.conn))
			if err != nil {
				t.Fatal(err)
			}
			records, ok := proto.PeerListParse(payload)
			if kind != proto.Type_PeerListAudio || !ok || len(records) != 1 ||
				records[0].Callsign != test.expectedCallsign || records[0].Addr().String() != test.expectedAddr {
				t.Fatalf("broadcast peer list = %#x, %+v, %t", kind, records, ok)
			}
		})
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
			ctx, transport, callsignWithByte(1), proto.Channel{2}, "127.0.0.1:1",
		)
		clientA, remoteA = sessionTestPair(t, 1)
		callsignA        = callsignWithByte(0xa1)
		itemA            = &link{
			addr:          addrCopy(targetA.LocalAddr().(*net.UDPAddr)),
			voice:         clientA,
			callsign:      callsignA,
			callsignKnown: true,
			state:         linkState_Active,
			audioEligible: true,
		}
		callsignB = callsignWithByte(0xb2)
	)
	manager.linkAdd(itemA)

	recordB, ok := proto.PeerRecordFrom(targetB.LocalAddr().(*net.UDPAddr), callsignB)
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

	kind, _, update, err := remoteA.Open(udpRead(t, targetA))
	if err != nil {
		t.Fatal(err)
	}
	records, ok := proto.PeerListParse(update)
	if kind != proto.Type_PeerListAudio || !ok || len(records) != 1 ||
		records[0].Callsign != callsignB || records[0].Addr().String() != targetB.LocalAddr().String() {
		t.Fatalf("discovered peer update = %#x, %+v, %t", kind, records, ok)
	}

	links := manager.links[targetB.LocalAddr().String()]
	if len(links) != 1 || !links[0].expectedKnown || links[0].expectedCallsign != callsignB ||
		links[0].state != linkState_KEX {
		t.Fatalf("discovered candidate = %+v", links)
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
			ctx, transport, callsignWithByte(1), proto.Channel{2}, "127.0.0.1:1",
		)
		clientA, remoteA = sessionTestPair(t, 1)
		callsignA        = callsignWithByte(0xa1)
		itemA            = &link{
			addr:          addrCopy(targetA.LocalAddr().(*net.UDPAddr)),
			voice:         clientA,
			callsign:      callsignA,
			callsignKnown: true,
			state:         linkState_Active,
			audioEligible: true,
		}
		itemB = &link{
			addr:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2},
			callsign:      callsignWithByte(0xb2),
			callsignKnown: true,
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
		ctx, transport, callsignWithByte(1), proto.Channel{2}, target.LocalAddr().String(),
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
	callsign proto.Callsign,
	channel proto.Channel,
	peerex string,
) (*manager, *playbackTestFactory) {
	var (
		peerexAddr, _ = net.ResolveUDPAddr("udp4", peerex)
		factory       = &playbackTestFactory{written: make(chan struct{})}
		manager       = &manager{
			ctx: ctx,
			t:   transport,
			cfg: config{
				callsign: callsign,
				channel:  channel,
				peerex:   peerexAddr,
			},
			playbackOpen: factory.open,
			output:       &output{writer: io.Discard},
			stderr:       io.Discard,
			links:        make(map[string][]*link),
			seen:         map[proto.Callsign]struct{}{callsign: {}},
			frames:       make(chan []byte, 8),
			commands:     make(chan byte, 8),
			events:       make(chan error, 8),
			readyCh:      make(chan struct{}),
		}
	)

	return manager, factory
}

func (f *playbackTestFactory) open(string) (audio.PlaybackWriter, error) {
	stream := &playbackTest{factory: f}
	f.mu.Lock()
	f.streams = append(f.streams, stream)
	f.mu.Unlock()

	return stream, nil
}

func (f *playbackTestFactory) streamCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.streams)
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

func callsignWithByte(value byte) proto.Callsign {
	var callsign proto.Callsign
	callsign[0] = value
	return callsign
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
