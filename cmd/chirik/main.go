package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"chirik/internal/adpcm"
	"chirik/internal/audio"
	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

const terminalLineClear = "\r\x1b[2K"

type config struct {
	callsign proto.Callsign
	channel  proto.Channel
	peerex   *net.UDPAddr
	source   string
	sink     string
}

type datagram struct {
	data []byte
	addr *net.UDPAddr
}

type transport struct {
	conn    *net.UDPConn
	packets chan datagram
	errors  chan error
	stopped chan struct{}
}

type linkState byte

const (
	linkState_KEX linkState = iota
	linkState_Request
	linkState_Active
)

type link struct {
	addr *net.UDPAddr
	pair *sessioncrypto.KeyPair

	peerPublic [sessioncrypto.PublicKeyBytes]byte
	voice      *sessioncrypto.Session

	callsign         proto.Callsign
	callsignKnown    bool
	expectedCallsign proto.Callsign
	expectedKnown    bool

	state            linkState
	initiated        bool
	peerex           bool
	bootstrap        bool
	audioEligible    bool
	responseReceived bool
	connectedPrinted bool

	kexNext          time.Time
	kexDeadline      time.Time
	requestNext      time.Time
	responseDeadline time.Time
	requestAttempts  int
	lastKEXSent      time.Time
	lastSeen         time.Time

	playback     audio.PlaybackWriter
	concealer    audio.Concealer
	lastAudioSeq uint64
}

type counters struct {
	sent          atomic.Uint64
	received      atomic.Uint64
	badAuth       atomic.Uint64
	sentBytes     atomic.Uint64
	receivedBytes atomic.Uint64
}

type output struct {
	writer io.Writer
	mu     sync.Mutex
}

type manager struct {
	ctx          context.Context
	t            *transport
	cfg          config
	playbackOpen func(string) (audio.PlaybackWriter, error)
	output       *output
	stderr       io.Writer

	links map[string][]*link
	seen  map[proto.Callsign]struct{}

	frames   chan []byte
	commands chan byte
	events   chan error
	muted    atomic.Bool
	counters counters
	ready    bool
	readyCh  chan struct{}
	readyOne sync.Once
}

type terminal struct {
	fd       int
	original syscall.Termios
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "mint":
		return mintRun(args[1:], stdout, stderr)

	case "chirp":
		return chirpRun(args[1:], stdout, stderr)

	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func mintRun(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: chirik mint <prefix>")
		return 2
	}

	callsign, err := callsignMint(args[0], cryptorand.Reader)
	if err != nil {
		fmt.Fprintf(stderr, "mint callsign: %v\n", err)
		return 2
	}

	fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(callsign[:]))
	return 0
}

func chirpRun(args []string, stdout io.Writer, stderr io.Writer) int {
	cfg, ok := configParse(args, stderr)
	if !ok {
		return 2
	}

	if err := audio.Check(cfg.source, cfg.sink); err != nil {
		fmt.Fprintf(stderr, "audio startup: %v\n", err)
		return 1
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		fmt.Fprintf(stderr, "UDP socket: %v\n", err)
		return 1
	}

	t := transportStart(conn)
	defer func() {
		conn.Close()
		<-t.stopped
	}()

	device, err := audio.Open(cfg.source, cfg.sink)
	if err != nil {
		fmt.Fprintf(stderr, "start audio: %v\n", err)
		return 1
	}
	defer device.Close()

	term, err := terminalEnable(os.Stdin)
	if err != nil {
		fmt.Fprintf(stderr, "terminal raw mode: %v\n", err)
		return 1
	}
	if term != nil {
		defer term.restore()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := &manager{
		ctx:          ctx,
		t:            t,
		cfg:          cfg,
		playbackOpen: func(name string) (audio.PlaybackWriter, error) { return device.PlaybackOpen(name) },
		output:       &output{writer: stdout},
		stderr:       stderr,
		links:        make(map[string][]*link),
		seen:         map[proto.Callsign]struct{}{cfg.callsign: {}},
		frames:       make(chan []byte, 8),
		commands:     make(chan byte, 8),
		events:       make(chan error, 8),
		readyCh:      make(chan struct{}),
	}

	initial, err := m.initialLink()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go captureRun(ctx, &wg, m.events, m.frames, device.Capture, &m.muted)
	go keyboardRun(ctx, &wg, m.events, m.commands, term)
	go audioMonitor(ctx, &wg, m.events, device)

	m.linkAdd(initial)
	m.linkKEXSend(initial, time.Now())
	err = m.run()
	stop()
	device.Close()
	wg.Wait()
	m.close()
	m.output.lineClear()
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, err)
		return 1
	}

	return 0
}

func configParse(args []string, stderr io.Writer) (config, bool) {
	var (
		cfg          config
		callsignText string
		targetText   string
	)

	flags := flag.NewFlagSet("chirik chirp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&cfg.source, "source", "", "Pulse source name")
	flags.StringVar(&cfg.sink, "sink", "", "Pulse sink name")
	flags.Usage = func() { chirpUsage(stderr, flags) }

	if len(args) < 2 {
		flags.Usage()
		return config{}, false
	}
	callsignText = args[0]
	targetText = args[1]

	if err := flags.Parse(args[2:]); err != nil {
		flags.Usage()
		return config{}, false
	}

	if flags.NArg() != 0 {
		flags.Usage()
		return config{}, false
	}

	separator := strings.IndexByte(targetText, '/')
	if separator <= 0 {
		fmt.Fprintln(stderr, "target must be <peerex-host>:<peerex-port>/<channel>")
		return config{}, false
	}

	if !base64FixedDecode(cfg.callsign[:], callsignText) ||
		!base64FixedDecode(cfg.channel[:], targetText[separator+1:]) {
		fmt.Fprintln(stderr, "callsign and channel must each be a 32-byte base64 value")
		return config{}, false
	}

	peerex, err := net.ResolveUDPAddr("udp4", targetText[:separator])
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "peer exchange address: %v\n", err)
		return config{}, false

	case peerex.Port == 0:
		fmt.Fprintln(stderr, "peer exchange address: port must be non-zero")
		return config{}, false

	case len(peerex.IP) == 0 || peerex.IP.IsUnspecified():
		fmt.Fprintln(stderr, "peer exchange address: host must be specified")
		return config{}, false
	}
	cfg.peerex = addrCopy(peerex)

	return cfg, true
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  chirik mint <prefix>")
	fmt.Fprintln(w, "  chirik chirp <callsign> <peerex-host>:<peerex-port>/<channel> [flags]")
}

func chirpUsage(w io.Writer, flags *flag.FlagSet) {
	fmt.Fprintln(w, "usage: chirik chirp <callsign> <peerex-host>:<peerex-port>/<channel> [flags]")
	flags.PrintDefaults()
}

func base64FixedDecode(destination []byte, text string) bool {
	if len(text) != base64.StdEncoding.EncodedLen(len(destination)) {
		return false
	}

	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) != len(destination) {
		return false
	}

	copy(destination, decoded)
	return true
}

func callsignMint(prefix string, random io.Reader) (proto.Callsign, error) {
	var callsign proto.Callsign

	if len(prefix) > base64.RawStdEncoding.EncodedLen(len(callsign)) {
		return callsign, errors.New("prefix exceeds 43 base64 characters")
	}

	if _, err := io.ReadFull(random, callsign[:]); err != nil {
		return callsign, err
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for charIndex := range len(prefix) {
		value := strings.IndexByte(alphabet, prefix[charIndex])
		if value < 0 {
			return callsign, fmt.Errorf("prefix contains invalid base64 character %q", prefix[charIndex])
		}

		for bitIndex := range 6 {
			var (
				destinationBit = charIndex*6 + bitIndex
				set            = value&(1<<(5-bitIndex)) != 0
			)
			if destinationBit >= len(callsign)*8 {
				if set {
					return callsign, errors.New("final prefix character cannot encode a 32-byte value")
				}
				continue
			}

			var (
				byteIndex = destinationBit / 8
				mask      = byte(1 << (7 - destinationBit%8))
			)
			if set {
				callsign[byteIndex] |= mask
			} else {
				callsign[byteIndex] &^= mask
			}
		}
	}

	if !strings.HasPrefix(base64.StdEncoding.EncodeToString(callsign[:]), prefix) {
		return callsign, errors.New("minted callsign does not match prefix")
	}

	return callsign, nil
}

func transportStart(conn *net.UDPConn) *transport {
	t := &transport{
		conn:    conn,
		packets: make(chan datagram, 512),
		errors:  make(chan error, 1),
		stopped: make(chan struct{}),
	}
	go t.readLoop()

	return t
}

func (t *transport) readLoop() {
	defer close(t.stopped)

	buffer := make([]byte, proto.MaxDatagram+1)
	for {
		n, addr, err := t.conn.ReadFromUDP(buffer)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				select {
				case t.errors <- err:
				default:
				}
			}

			return
		}

		if n > proto.MaxDatagram {
			continue
		}

		packet := datagram{
			data: append([]byte(nil), buffer[:n]...),
			addr: addr,
		}
		select {
		case t.packets <- packet:
		default:
		}
	}
}

func (m *manager) initialLink() (*link, error) {
	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return nil, fmt.Errorf("key generation: %w", err)
	}

	fmt.Fprintf(m.output.writer, "peer exchange: %s; local UDP: %s\n", m.cfg.peerex, m.t.conn.LocalAddr())

	return &link{
		addr:        addrCopy(m.cfg.peerex),
		pair:        pair,
		state:       linkState_KEX,
		initiated:   true,
		peerex:      true,
		bootstrap:   true,
		kexDeadline: time.Now().Add(proto.KEXTimeout),
	}, nil
}

func (m *manager) run() error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	bitrate := time.NewTicker(time.Second)
	defer bitrate.Stop()

	var (
		bytesSentLast     uint64
		bytesReceivedLast uint64
		sampledAt         = time.Now()
	)

	for {
		select {
		case <-m.ctx.Done():
			return nil

		case err := <-m.t.errors:
			return fmt.Errorf("UDP read: %w", err)

		case err := <-m.events:
			return err

		case command := <-m.commands:
			switch command {
			case 'm':
				state := !m.muted.Load()
				m.muted.Store(state)
				if state {
					m.output.lineWrite("muted")
				} else {
					m.output.lineWrite("unmuted")
				}

			case 'q':
				return nil
			}

		case frame := <-m.frames:
			m.audioSend(frame)

		case packet := <-m.t.packets:
			m.packetHandle(packet)

		case now := <-ticker.C:
			if err := m.tick(now); err != nil {
				return err
			}

		case now := <-bitrate.C:
			bytesSent := m.counters.sentBytes.Load()
			bytesReceived := m.counters.receivedBytes.Load()
			m.output.bitrateWrite(
				bytesReceived-bytesReceivedLast,
				bytesSent-bytesSentLast,
				now.Sub(sampledAt),
				m.audioPeerCount(),
			)
			bytesSentLast = bytesSent
			bytesReceivedLast = bytesReceived
			sampledAt = now
			debugf(
				m.stderr,
				"packets sent=%d received=%d bad_auth=%d peers=%d",
				m.counters.sent.Load(), m.counters.received.Load(), m.counters.badAuth.Load(),
				m.audioPeerCount(),
			)
		}
	}
}

func (m *manager) packetHandle(packet datagram) {
	if public, ok := proto.KEXParse(packet.data); ok {
		m.kexHandle(packet.addr, public, time.Now())
		return
	}

	links := append([]*link(nil), m.links[packet.addr.String()]...)
	authFailed := false
	for _, item := range links {
		if item.voice == nil {
			continue
		}

		kind, seq, payload, err := item.voice.Open(packet.data)
		if err != nil {
			if !errors.Is(err, sessioncrypto.ErrReplay) {
				authFailed = true
			}
			continue
		}

		m.encryptedHandle(item, kind, seq, payload, packet.data)
		return
	}

	if authFailed {
		m.counters.badAuth.Add(1)
	}
}

func (m *manager) kexHandle(
	addr *net.UDPAddr,
	peerPublic [sessioncrypto.PublicKeyBytes]byte,
	now time.Time,
) {
	for _, item := range m.links[addr.String()] {
		if item.voice != nil && item.peerPublic == peerPublic {
			if now.Sub(item.lastKEXSent) >= proto.KEXInterval {
				m.linkKEXSend(item, now)
			}
			return
		}
	}

	item := (*link)(nil)
	for _, candidate := range m.links[addr.String()] {
		if candidate.state == linkState_KEX && candidate.peerPublic == ([sessioncrypto.PublicKeyBytes]byte{}) {
			item = candidate
			break
		}
	}
	kexReply := item != nil

	if item == nil {
		if udpAddrEqual(addr, m.initialPeerexAddr()) {
			return
		}

		pair, err := sessioncrypto.KeyPairGenerate()
		if err != nil {
			return
		}

		item = &link{
			addr:        addrCopy(addr),
			pair:        pair,
			state:       linkState_Request,
			kexDeadline: now.Add(proto.KEXTimeout),
		}
		m.linkAdd(item)
		m.linkKEXSend(item, now)
	}

	salt := m.cfg.channel[:]
	if item.peerex {
		zero := [proto.ChannelBytes]byte{}
		salt = zero[:]
	}

	keys, err := item.pair.Derive(peerPublic[:], salt)
	if err != nil {
		m.linkFail(item, fmt.Errorf("derive keys: %w", err))
		return
	}

	voice, err := sessioncrypto.SessionNew(keys)
	if err != nil {
		m.linkFail(item, fmt.Errorf("session keys: %w", err))
		return
	}

	item.peerPublic = peerPublic
	item.voice = voice
	item.lastSeen = now
	item.state = linkState_Request
	item.responseDeadline = now.Add(proto.ResponseTimeout)
	m.output.lineWrite(
		fmt.Sprintf(
			"peer %s public key %s",
			item.addr,
			base64.StdEncoding.EncodeToString(peerPublic[:]),
		),
	)
	if kexReply {
		m.linkKEXSend(item, now)
	}

	if !item.peerex || item.initiated {
		m.linkRequestSend(item, now)
	}
}

func (m *manager) encryptedHandle(
	item *link,
	kind byte,
	seq uint64,
	payload []byte,
	packet []byte,
) bool {
	now := time.Now()
	switch kind {
	case proto.Type_Request:
		if item.peerex || !m.requestHandle(item, payload, now) {
			return false
		}

	case proto.Type_PeerList:
		if !item.peerex || !m.peerListHandle(item, payload, false, now) {
			return false
		}

	case proto.Type_PeerListAudio:
		if item.peerex || !m.peerListHandle(item, payload, true, now) {
			return false
		}

	case proto.Type_Audio:
		if !m.audioReceive(item, seq, payload, now) {
			return false
		}

	default:
		return false
	}

	item.lastSeen = now
	m.counters.received.Add(1)
	m.counters.receivedBytes.Add(uint64(len(packet)))

	return true
}

func (m *manager) requestHandle(item *link, payload []byte, now time.Time) bool {
	callsign, channel, ok := proto.RequestParse(payload)
	if !ok || channel != m.cfg.channel {
		return false
	}

	if item.expectedKnown && callsign != item.expectedCallsign {
		return false
	}

	membershipChanged := !item.stateActive() || !item.audioEligible
	item.callsign = callsign
	item.callsignKnown = true
	if err := m.linkPromote(item, now); err != nil {
		m.linkFail(item, err)
		return false
	}

	if !m.peerListSend(item, callsign) {
		m.linkFail(item, errors.New("send peer list failed"))
		return false
	}

	item.audioEligible = true
	m.managerReady(item)
	if membershipChanged {
		m.peerListBroadcast()
	}

	return true
}

func (m *manager) peerListHandle(
	item *link,
	payload []byte,
	audioPeer bool,
	now time.Time,
) bool {
	records, ok := proto.PeerListParse(payload)
	if !ok {
		return false
	}

	if item.expectedKnown {
		item.callsign = item.expectedCallsign
		item.callsignKnown = true
	}

	membershipChanged := audioPeer && (!item.stateActive() || !item.audioEligible)
	if audioPeer {
		if err := m.linkPromote(item, now); err != nil {
			m.linkFail(item, err)
			return false
		}
		item.audioEligible = true
	}

	if item.peerex {
		item.state = linkState_Active
		item.requestAttempts = 0
		item.requestNext = time.Time{}
		item.responseDeadline = time.Time{}
	}
	item.responseReceived = true
	listChanged := membershipChanged
	for _, record := range records {
		if m.candidateAdd(record, item.peerex, now) {
			listChanged = true
		}
	}
	m.managerReady(item)
	if listChanged {
		m.peerListBroadcast()
	}

	return true
}

func (m *manager) peerListSend(item *link, requester proto.Callsign) bool {
	records := m.peerRecords(requester)
	if len(records) == 0 {
		payload, _ := proto.PeerList(nil)
		packet, err := item.voice.Seal(proto.Type_PeerListAudio, payload)
		return err == nil && datagramSend(m.t.conn, item.addr, packet) == nil
	}

	for start := 0; start < len(records); start += proto.PeersPerPacket {
		end := min(start+proto.PeersPerPacket, len(records))
		payload, ok := proto.PeerList(records[start:end])
		if !ok {
			return false
		}

		packet, err := item.voice.Seal(proto.Type_PeerListAudio, payload)
		if err != nil || datagramSend(m.t.conn, item.addr, packet) != nil {
			return false
		}
	}

	return true
}

func (m *manager) peerListBroadcast() {
	for _, links := range m.links {
		for _, item := range append([]*link(nil), links...) {
			if item.peerex || !item.stateActive() || !item.audioEligible ||
				!item.callsignKnown || item.voice == nil {
				continue
			}

			m.peerListSend(item, item.callsign)
		}
	}
}

func (m *manager) peerRecords(exclude proto.Callsign) []proto.PeerRecord {
	type candidate struct {
		record  proto.PeerRecord
		pending bool
	}

	candidates := make(map[proto.Callsign]candidate)
	for _, links := range m.links {
		for _, item := range links {
			if item.peerex {
				continue
			}

			var (
				callsign proto.Callsign
				pending  bool
			)
			switch {
			case item.callsignKnown:
				callsign = item.callsign

			case item.expectedKnown:
				callsign = item.expectedCallsign
				pending = true

			default:
				continue
			}

			if callsign == exclude {
				continue
			}

			record, ok := proto.PeerRecordFrom(item.addr, callsign)
			if !ok {
				continue
			}

			stored, exists := candidates[callsign]
			if exists && (!pending || stored.pending) {
				continue
			}

			candidates[callsign] = candidate{record: record, pending: pending}
		}
	}

	records := make([]proto.PeerRecord, 0, len(candidates))
	for _, item := range candidates {
		records = append(records, item.record)
	}

	return records
}

func (m *manager) candidateAdd(
	record proto.PeerRecord,
	allowReplacement bool,
	now time.Time,
) bool {
	if record.Callsign == m.cfg.callsign {
		return false
	}

	var (
		addr       = record.Addr()
		tracked    bool
		superseded []*link
	)
	for _, links := range m.links {
		for _, item := range links {
			if item.peerex {
				continue
			}

			matches := (item.callsignKnown && item.callsign == record.Callsign) ||
				(item.expectedKnown && item.expectedCallsign == record.Callsign)
			if !matches {
				continue
			}

			tracked = true
			if udpAddrEqual(item.addr, addr) {
				return false
			}

			if allowReplacement && item.expectedKnown && !item.callsignKnown {
				superseded = append(superseded, item)
			}
		}
	}

	if tracked && !allowReplacement {
		return false
	}

	if !tracked {
		if _, exists := m.seen[record.Callsign]; exists {
			return false
		}
	}

	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return false
	}

	for _, item := range superseded {
		m.linkRemove(item, "endpoint superseded")
	}

	item := &link{
		addr:             addr,
		pair:             pair,
		expectedCallsign: record.Callsign,
		expectedKnown:    true,
		state:            linkState_KEX,
		initiated:        true,
		kexDeadline:      now.Add(proto.KEXTimeout),
	}
	m.seen[record.Callsign] = struct{}{}
	m.linkAdd(item)
	m.linkKEXSend(item, now)

	return true
}

func (m *manager) linkPromote(item *link, now time.Time) error {
	if item.callsignKnown {
		for _, links := range m.links {
			for _, other := range append([]*link(nil), links...) {
				if other != item && other.stateActive() && other.callsignKnown && other.callsign == item.callsign {
					m.linkRemove(other, "replaced")
				}
			}
		}
		m.seen[item.callsign] = struct{}{}
	}

	if item.playback == nil {
		name := fmt.Sprintf("chirik peer %s", item.addr)
		playback, err := m.playbackOpen(name)
		if err != nil {
			return fmt.Errorf("open peer playback: %w", err)
		}
		item.playback = playback
	}

	item.state = linkState_Active
	item.lastSeen = now
	if !item.connectedPrinted {
		m.output.lineWrite(fmt.Sprintf("peer connected: %s", item.addr))
		item.connectedPrinted = true
	}

	return nil
}

func (m *manager) linkAdd(item *link) {
	key := item.addr.String()
	m.links[key] = append(m.links[key], item)
}

func (m *manager) linkRemove(item *link, reason string) {
	var (
		membershipChanged = !item.peerex && item.stateActive() && item.audioEligible && item.callsignKnown
		removedCallsign   proto.Callsign
		removedKnown      bool
		key               = item.addr.String()
		links             = m.links[key]
	)
	switch {
	case item.callsignKnown:
		removedCallsign = item.callsign
		removedKnown = true

	case item.expectedKnown:
		removedCallsign = item.expectedCallsign
		removedKnown = true
	}

	for i, candidate := range links {
		if candidate != item {
			continue
		}

		links = append(links[:i], links[i+1:]...)
		break
	}
	if len(links) == 0 {
		delete(m.links, key)
	} else {
		m.links[key] = links
	}

	if removedKnown && removedCallsign != m.cfg.callsign {
		tracked := false
		for _, trackedLinks := range m.links {
			for _, trackedItem := range trackedLinks {
				switch {
				case trackedItem.peerex:
					continue

				case trackedItem.callsignKnown && trackedItem.callsign == removedCallsign:
					tracked = true

				case trackedItem.expectedKnown && trackedItem.expectedCallsign == removedCallsign:
					tracked = true
				}

				if tracked {
					break
				}
			}

			if tracked {
				break
			}
		}

		if !tracked {
			delete(m.seen, removedCallsign)
		}
	}

	if item.playback != nil {
		item.playback.Close()
		item.playback = nil
	}

	if item.connectedPrinted {
		m.output.lineWrite(fmt.Sprintf("peer removed: %s (%s)", item.addr, reason))
	}

	if membershipChanged {
		m.peerListBroadcast()
	}
}

func (m *manager) linkFail(item *link, err error) {
	bootstrap := item.bootstrap && !m.ready
	m.linkRemove(item, err.Error())
	if bootstrap {
		select {
		case m.events <- err:
		default:
		}
	}
}

func (m *manager) linkKEXSend(item *link, now time.Time) {
	packet := proto.KEX(item.pair.Public())
	if datagramSend(m.t.conn, item.addr, packet) != nil {
		return
	}

	item.lastKEXSent = now
	item.kexNext = now.Add(proto.KEXInterval)
}

func (m *manager) linkRequestSend(item *link, now time.Time) {
	if item.voice == nil || item.requestAttempts >= proto.RequestAttempts {
		return
	}

	var (
		payload     = proto.Request(m.cfg.callsign, m.cfg.channel)
		packet, err = item.voice.Seal(proto.Type_Request, payload)
	)
	if err != nil || datagramSend(m.t.conn, item.addr, packet) != nil {
		return
	}

	item.requestAttempts++
	item.requestNext = now.Add(proto.RequestInterval)
}

func (m *manager) tick(now time.Time) error {
	for _, links := range m.links {
		for _, item := range append([]*link(nil), links...) {
			switch item.state {
			case linkState_KEX:
				if now.After(item.kexDeadline) {
					if item.bootstrap && !m.ready {
						return errors.New("key exchange timed out")
					}
					m.linkRemove(item, "key exchange timed out")
					continue
				}

				if !now.Before(item.kexNext) {
					m.linkKEXSend(item, now)
				}

			case linkState_Request:
				if (!item.peerex || item.initiated) && item.requestAttempts < proto.RequestAttempts && !now.Before(item.requestNext) {
					m.linkRequestSend(item, now)
				}

				if !item.responseDeadline.IsZero() && now.After(item.responseDeadline) && !item.responseReceived {
					if item.bootstrap && !m.ready {
						return errors.New("peer-list response timed out")
					}
					m.linkRemove(item, "peer-list response timed out")
				}

			case linkState_Active:
				if !item.peerex && item.initiated && !item.responseReceived &&
					item.requestAttempts < proto.RequestAttempts && !now.Before(item.requestNext) {
					m.linkRequestSend(item, now)
				}

				if !item.peerex && now.Sub(item.lastSeen) > proto.PeerTTL {
					m.linkRemove(item, "expired")
				}
			}
		}
	}

	return nil
}

func (m *manager) managerReady(item *link) {
	if m.ready || !item.bootstrap {
		return
	}

	m.ready = true
	m.readyOne.Do(func() { close(m.readyCh) })
	m.output.lineWrite("ready")
}

func (m *manager) audioSend(payload []byte) {
	for _, links := range m.links {
		for _, item := range append([]*link(nil), links...) {
			if item.peerex || !item.stateActive() || !item.audioEligible {
				continue
			}

			packet, err := item.voice.Seal(proto.Type_Audio, payload)
			if err != nil {
				m.linkRemove(item, "audio encryption failed")
				continue
			}

			if err := datagramSend(m.t.conn, item.addr, packet); err != nil {
				m.linkRemove(item, "audio send failed")
				continue
			}

			m.counters.sent.Add(1)
			m.counters.sentBytes.Add(uint64(len(packet)))
		}
	}
}

func (m *manager) audioReceive(
	item *link,
	seq uint64,
	payload []byte,
	now time.Time,
) bool {
	if item.peerex || !item.stateActive() || !item.audioEligible || len(payload) != proto.PlainFrame || item.playback == nil {
		return false
	}

	missing := uint64(0)
	if item.lastAudioSeq != 0 {
		missing = seq - item.lastAudioSeq - 1
	}

	state := adpcm.State{
		Predictor: int16(binary.BigEndian.Uint16(payload[0:2])),
		StepIndex: payload[2],
	}
	pcm := adpcm.Decode(state, payload[proto.StateBytes:])
	if missing != 0 {
		item.concealer.Recover(pcm)
	} else {
		item.concealer.Track(pcm)
	}

	pcmBytes := make([]byte, len(pcm)*2)
	for i, sample := range pcm {
		binary.LittleEndian.PutUint16(pcmBytes[2*i:], uint16(sample))
	}
	if _, err := item.playback.Write(pcmBytes); err != nil {
		m.linkRemove(item, "audio playback failed")
		return false
	}

	item.lastAudioSeq = seq
	item.lastSeen = now

	return true
}

func (m *manager) audioPeerCount() int {
	count := 0
	for _, links := range m.links {
		for _, item := range links {
			if item.stateActive() && item.audioEligible {
				count++
			}
		}
	}
	return count
}

func (m *manager) initialPeerexAddr() *net.UDPAddr { return m.cfg.peerex }

func (m *manager) close() {
	for _, links := range m.links {
		for _, item := range links {
			if item.playback != nil {
				item.playback.Close()
			}
		}
	}
	m.links = make(map[string][]*link)
}

func (l *link) stateActive() bool { return l.state == linkState_Active }

func captureRun(
	ctx context.Context,
	wg *sync.WaitGroup,
	events chan<- error,
	frames chan<- []byte,
	capture io.Reader,
	muted *atomic.Bool,
) {
	defer wg.Done()

	var (
		encoder    adpcm.State
		frameBytes = make([]byte, proto.FrameSamples*2)
		pcm        = make([]int16, proto.FrameSamples)
	)
	for {
		if _, err := io.ReadFull(capture, frameBytes); err != nil {
			report(ctx, events, fmt.Errorf("audio capture: %w", err))
			return
		}

		if muted.Load() {
			clear(frameBytes)
		}

		for i := range proto.FrameSamples {
			pcm[i] = int16(binary.LittleEndian.Uint16(frameBytes[2*i:]))
		}

		snapshot := encoder
		encoded := adpcm.Encode(&encoder, pcm)
		payload := make([]byte, proto.PlainFrame)
		binary.BigEndian.PutUint16(payload[0:2], uint16(snapshot.Predictor))
		payload[2] = snapshot.StepIndex
		copy(payload[proto.StateBytes:], encoded)

		select {
		case frames <- payload:
		case <-ctx.Done():
			return
		}
	}
}

func keyboardRun(
	ctx context.Context,
	wg *sync.WaitGroup,
	events chan<- error,
	commands chan<- byte,
	term *terminal,
) {
	defer wg.Done()
	if term == nil {
		<-ctx.Done()
		return
	}

	buffer := make([]byte, 1)
	for {
		ready, err := terminalReady(ctx, term.fd)
		if err != nil {
			report(ctx, events, fmt.Errorf("terminal read: %w", err))
			return
		}

		if !ready {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		n, err := syscall.Read(term.fd, buffer)
		if err != nil {
			report(ctx, events, fmt.Errorf("terminal read: %w", err))
			return
		}

		if n == 0 {
			continue
		}

		select {
		case commands <- buffer[0]:
		case <-ctx.Done():
			return
		}
	}
}

func audioMonitor(
	ctx context.Context,
	wg *sync.WaitGroup,
	events chan<- error,
	device *audio.Device,
) {
	defer wg.Done()

	err := device.Wait(ctx)
	if err != nil && ctx.Err() == nil {
		report(ctx, events, fmt.Errorf("audio server: %w", err))
	}
}

func report(ctx context.Context, events chan<- error, err error) {
	select {
	case events <- err:
	case <-ctx.Done():
	}
}

func (o *output) bitrateWrite(
	bytesReceived uint64,
	bytesSent uint64,
	elapsed time.Duration,
	peers int,
) {
	if elapsed <= 0 {
		return
	}

	factor := 8 / elapsed.Seconds() / 1000
	o.mu.Lock()
	defer o.mu.Unlock()

	fmt.Fprintf(
		o.writer,
		terminalLineClear+"peers %3d | in %8.2f kbit/s | out %8.2f kbit/s",
		peers,
		float64(bytesReceived)*factor,
		float64(bytesSent)*factor,
	)
}

func (o *output) lineWrite(message string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	fmt.Fprintf(o.writer, terminalLineClear+"%s\n", message)
}

func (o *output) lineClear() {
	o.mu.Lock()
	defer o.mu.Unlock()

	fmt.Fprint(o.writer, terminalLineClear)
}

func datagramSend(conn *net.UDPConn, addr *net.UDPAddr, packet []byte) error {
	n, err := conn.WriteToUDP(packet, addr)
	if err != nil {
		return err
	}

	if n != len(packet) {
		return io.ErrShortWrite
	}

	return nil
}

func addrCopy(addr *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func udpAddrEqual(a *net.UDPAddr, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func debugf(w io.Writer, format string, args ...any) {
	if os.Getenv("CHIRIK_DEBUG") != "" {
		fmt.Fprintf(w, "debug: "+format+"\n", args...)
	}
}

func terminalEnable(file *os.File) (*terminal, error) {
	fd := int(file.Fd())
	original, err := termiosGet(fd)
	if errors.Is(err, syscall.ENOTTY) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}
	term := termiosRaw(original)
	if err := termiosSet(fd, &term); err != nil {
		return nil, err
	}

	return &terminal{fd: fd, original: original}, nil
}

func termiosRaw(original syscall.Termios) syscall.Termios {
	term := original
	term.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	term.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	term.Cflag &^= syscall.CSIZE | syscall.PARENB
	term.Cflag |= syscall.CS8
	term.Cc[syscall.VMIN] = 1
	term.Cc[syscall.VTIME] = 0

	return term
}

func (t *terminal) restore() { termiosSet(t.fd, &t.original) }

func termiosGet(fd int) (syscall.Termios, error) {
	var term syscall.Termios

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&term)),
	)
	if errno != 0 {
		return term, errno
	}

	return term, nil
}

func termiosSet(fd int, term *syscall.Termios) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TCSETS),
		uintptr(unsafe.Pointer(term)),
	)
	if errno != 0 {
		return errno
	}

	return nil
}

func terminalReady(ctx context.Context, fd int) (bool, error) {
	if ctx.Err() != nil {
		return false, nil
	}

	var readSet syscall.FdSet
	fdSet(fd, &readSet)
	timeout := syscall.Timeval{Usec: 250000}
	n, err := syscall.Select(fd+1, &readSet, nil, nil, &timeout)
	if err != nil {
		if errors.Is(err, syscall.EINTR) {
			return false, nil
		}

		return false, err
	}

	return n > 0 && fdIsSet(fd, &readSet), nil
}

func fdSet(fd int, set *syscall.FdSet) {
	set.Bits[fd/64] |= 1 << uint(fd%64)
}

func fdIsSet(fd int, set *syscall.FdSet) bool {
	return set.Bits[fd/64]&(1<<uint(fd%64)) != 0
}
