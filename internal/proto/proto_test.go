package proto

import (
	"bytes"
	"net"
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

func TestRequestParse(t *testing.T) {
	var (
		callsign Callsign
		channel  Channel
	)
	for i := range CallsignBytes {
		callsign[i] = byte(i)
		channel[i] = byte(255 - i)
	}

	var (
		payload                           = Request(callsign, channel)
		parsedCallsign, parsedChannel, ok = RequestParse(payload)
	)
	if !ok || parsedCallsign != callsign || parsedChannel != channel {
		t.Fatal("request differs")
	}

	if _, _, ok := RequestParse(append(payload, 0)); ok {
		t.Fatal("oversized request accepted")
	}
}

func TestPeerList(t *testing.T) {
	var callsign Callsign
	for i := range CallsignBytes {
		callsign[i] = byte(i)
	}

	record, ok := PeerRecordFrom(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 7777},
		callsign,
	)
	if !ok {
		t.Fatal("peer record rejected")
	}

	payload, ok := PeerList([]PeerRecord{record})
	if !ok {
		t.Fatal("peer list rejected")
	}

	records, ok := PeerListParse(payload)
	if !ok || len(records) != 1 || records[0] != record {
		t.Fatalf("peer list = %+v, %t", records, ok)
	}

	if records[0].Addr().String() != "192.0.2.10:7777" {
		t.Fatalf("address = %s", records[0].Addr())
	}
}

func TestPeerListLimits(t *testing.T) {
	records := make([]PeerRecord, PeersPerPacket)
	for i := range len(records) {
		records[i].Port = uint16(i + 1)
	}

	payload, ok := PeerList(records)
	if !ok || len(payload) != PeersPerPacket*PeerRecordBytes {
		t.Fatalf("maximum peer list = %d, %t", len(payload), ok)
	}

	if _, ok := PeerList(append(records, PeerRecord{Port: 1})); ok {
		t.Fatal("oversized peer list accepted")
	}

	if _, ok := PeerListParse([]byte{1}); ok {
		t.Fatal("misaligned peer list accepted")
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
