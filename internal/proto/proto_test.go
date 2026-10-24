package proto

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestKEXParse(t *testing.T) {
	var public [PublicKeyBytes]byte
	for i := range len(public) {
		public[i] = byte(i)
	}

	packet := KEX(public)
	parsed, ok := KEXParse(packet)
	if !ok || parsed != public {
		t.Fatalf("KEX parse = %x, %t", parsed, ok)
	}

	for _, invalid := range [][]byte{
		packet[:len(packet)-1],
		append([]byte{Type_Audio}, packet[1:]...),
	} {
		if _, ok := KEXParse(invalid); ok {
			t.Fatalf("invalid KEX accepted: %x", invalid)
		}
	}
}

func TestEnvelopeParse(t *testing.T) {
	header := EnvelopeHeaderFor(Type_Audio, 0x0102030405060708)
	packet := append(header[:], bytes.Repeat([]byte{0xa5}, TagBytes)...)
	kind, seq, aad, ciphertext, ok := EnvelopeParse(packet)
	if !ok {
		t.Fatal("encrypted packet rejected")
	}

	if kind != Type_Audio || seq != 0x0102030405060708 {
		t.Fatalf("envelope = %#x/%#x", kind, seq)
	}

	if !bytes.Equal(aad, header[:]) || len(ciphertext) != TagBytes {
		t.Fatal("encrypted packet fields differ")
	}
}

func TestHandleValid(t *testing.T) {
	for _, handle := range []Handle{"Alice", "bob42", "Z9", Handle(strings.Repeat("a", MaxHandleBytes))} {
		if !HandleValid(handle) {
			t.Fatalf("valid handle rejected: %q", handle)
		}
	}

	for _, handle := range []Handle{"", "not-valid", "white space", Handle(strings.Repeat("a", MaxHandleBytes+1))} {
		if HandleValid(handle) {
			t.Fatalf("invalid handle accepted: %q", handle)
		}
	}
}

func TestChannelKey(t *testing.T) {
	if ChannelKey("room") != ChannelKey("room") || ChannelKey("room") == ChannelKey("other") {
		t.Fatal("channel-key derivation differs")
	}
}

func TestRequestParse(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 4567}
	payload, ok := Request("Alice42", "free-form/channel name", local)
	if !ok {
		t.Fatal("request rejected")
	}

	handle, channel, parsedLocal, ok := RequestParse(payload)
	if !ok || handle != "Alice42" || channel != "free-form/channel name" ||
		parsedLocal.String() != local.String() {
		t.Fatalf("request = %q/%q/%v/%t", handle, channel, parsedLocal, ok)
	}

	maxHandle := Handle(strings.Repeat("A", MaxHandleBytes))
	maxChannel := strings.Repeat("x", MaxRequestPayload-requestPrefixBytes-len(maxHandle))
	payload, ok = Request(maxHandle, maxChannel, local)
	if !ok || len(payload) != MaxRequestPayload {
		t.Fatalf("maximum request = %d/%t", len(payload), ok)
	}
	parsedHandle, parsedChannel, parsedLocal, ok := RequestParse(payload)
	if !ok || parsedHandle != maxHandle || parsedChannel != maxChannel ||
		parsedLocal.String() != local.String() {
		t.Fatalf(
			"maximum request parse = %d/%d/%v/%t",
			len(parsedHandle), len(parsedChannel), parsedLocal, ok,
		)
	}

	for _, invalid := range []struct {
		handle  Handle
		channel string
		local   *net.UDPAddr
	}{
		{handle: "Alice", local: local},
		{handle: "bad-handle", channel: "room", local: local},
		{handle: Handle(strings.Repeat("A", MaxHandleBytes+1)), channel: "room", local: local},
		{handle: maxHandle, channel: maxChannel + "x", local: local},
		{handle: "Alice", channel: "room"},
		{handle: "Alice", channel: "room", local: &net.UDPAddr{IP: net.IPv4zero, Port: 1}},
		{handle: "Alice", channel: "room", local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}},
	} {
		if _, ok := Request(invalid.handle, invalid.channel, invalid.local); ok {
			t.Fatalf(
				"invalid request built: handle=%q channel-bytes=%d local=%v",
				invalid.handle, len(invalid.channel), invalid.local,
			)
		}
	}

	valid, _ := Request("A", "x", local)
	zeroHandle := bytes.Clone(valid)
	zeroHandle[0] = 0
	invalidHandle := bytes.Clone(valid)
	invalidHandle[1] = '-'
	zeroPort := bytes.Clone(valid)
	binary.BigEndian.PutUint16(zeroPort[1+len("A")+4:], 0)
	for _, invalid := range [][]byte{
		nil,
		valid[:len(valid)-1],
		zeroHandle,
		invalidHandle,
		zeroPort,
		append(valid, bytes.Repeat([]byte{'x'}, MaxPayload)...),
	} {
		if _, _, _, ok := RequestParse(invalid); ok {
			t.Fatalf("invalid request accepted: %x", invalid)
		}
	}
}

func TestRelayParse(t *testing.T) {
	inner := bytes.Repeat([]byte{0xa5}, MaxRelayInner)
	payload, ok := Relay(Handle(strings.Repeat("A", MaxHandleBytes)), inner)
	if !ok || len(payload) != MaxPayload {
		t.Fatalf("maximum relay = %d/%t", len(payload), ok)
	}
	handle, parsed, ok := RelayParse(payload)
	if !ok || handle != Handle(strings.Repeat("A", MaxHandleBytes)) || !bytes.Equal(parsed, inner) {
		t.Fatalf("relay parse = %q/%d/%t", handle, len(parsed), ok)
	}

	for _, invalid := range []struct {
		handle Handle
		packet []byte
	}{
		{packet: []byte{1}},
		{handle: "bad-handle", packet: []byte{1}},
		{handle: "Alice"},
		{handle: "Alice", packet: bytes.Repeat([]byte{1}, MaxRelayInner+1)},
	} {
		if _, ok := Relay(invalid.handle, invalid.packet); ok {
			t.Fatalf("invalid relay built: %+v", invalid)
		}
	}

	valid, _ := Relay("Alice", []byte{1})
	zeroHandle := bytes.Clone(valid)
	zeroHandle[0] = 0
	invalidHandle := bytes.Clone(valid)
	invalidHandle[1] = '-'
	for _, invalid := range [][]byte{
		nil,
		{1, 'A'},
		zeroHandle,
		invalidHandle,
		append(valid, bytes.Repeat([]byte{1}, MaxPayload)...),
	} {
		if _, _, ok := RelayParse(invalid); ok {
			t.Fatalf("invalid relay accepted: %x", invalid)
		}
	}
}

func TestPeerList(t *testing.T) {
	first, ok := PeerRecordFrom(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 7777},
		"Alice42",
	)
	if !ok {
		t.Fatal("first peer record rejected")
	}
	second, ok := PeerRecordFrom(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 8888},
		Handle(strings.Repeat("B", MaxHandleBytes)),
	)
	if !ok {
		t.Fatal("maximum-handle peer record rejected")
	}
	want := []PeerRecord{first, second}

	payload, ok := PeerList(want)
	if !ok {
		t.Fatal("peer list rejected")
	}

	records, ok := PeerListParse(payload)
	if !ok || len(records) != len(want) {
		t.Fatalf("peer list = %+v, %t", records, ok)
	}
	for i := range want {
		if records[i] != want[i] {
			t.Fatalf("peer record %d = %+v, want %+v", i, records[i], want[i])
		}
	}

	if records[0].Addr().String() != "192.0.2.10:7777" {
		t.Fatalf("address = %s", records[0].Addr())
	}
}

func TestPeerListSplit(t *testing.T) {
	records := make([]PeerRecord, 100)
	for i := range len(records) {
		records[i] = PeerRecord{
			IP:     [4]byte{192, 0, 2, byte(i + 1)},
			Port:   uint16(i + 1),
			Handle: Handle("peer" + strings.Repeat("x", i%20)),
		}
	}

	payloads, ok := PeerListSplit(records)
	if !ok || len(payloads) < 2 {
		t.Fatalf("peer-list split = %d/%t", len(payloads), ok)
	}

	var parsed []PeerRecord
	for _, payload := range payloads {
		if len(payload) > MaxPayload {
			t.Fatalf("oversized payload = %d", len(payload))
		}

		part, ok := PeerListParse(payload)
		if !ok {
			t.Fatal("split payload rejected")
		}
		parsed = append(parsed, part...)
	}

	if len(parsed) != len(records) {
		t.Fatalf("parsed records = %d, want %d", len(parsed), len(records))
	}
	for i := range records {
		if parsed[i] != records[i] {
			t.Fatalf("parsed record %d = %+v, want %+v", i, parsed[i], records[i])
		}
	}

	empty, ok := PeerListSplit(nil)
	if !ok || len(empty) != 1 || len(empty[0]) != 0 {
		t.Fatalf("empty peer-list split = %+v/%t", empty, ok)
	}
}

func TestPeerListRejectsMalformedPayload(t *testing.T) {
	for _, payload := range [][]byte{
		{1},
		{192, 0, 2, 1, 0, 1, 0},
		{192, 0, 2, 1, 0, 1, 2, 'A'},
		{192, 0, 2, 1, 0, 0, 1, 'A'},
		{192, 0, 2, 1, 0, 1, 1, '-'},
	} {
		if _, ok := PeerListParse(payload); ok {
			t.Fatalf("malformed peer list accepted: %x", payload)
		}
	}
}

func TestAudioBitrate(t *testing.T) {
	if AudioPacketBytes != 268 {
		t.Fatalf("audio packet bytes = %d, want 268", AudioPacketBytes)
	}

	if AudioPacketsPerSecond != 100 {
		t.Fatalf("audio packets per second = %d, want 100", AudioPacketsPerSecond)
	}

	if AudioPayloadBitrate != 214400 {
		t.Fatalf("audio payload bitrate = %d, want 214400", AudioPayloadBitrate)
	}

	if AudioIPv4UDPBitrate != 236800 {
		t.Fatalf("audio IPv4/UDP bitrate = %d, want 236800", AudioIPv4UDPBitrate)
	}
}
