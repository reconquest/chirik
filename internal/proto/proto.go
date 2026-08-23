package proto

import (
	"encoding/binary"
	"net"
	"time"
)

const (
	SampleRate   = 48000
	Channels     = 1
	FrameSamples = 480
	FrameBytes   = 240
	StateBytes   = 3
	PlainFrame   = StateBytes + FrameBytes

	Type_Audio         = byte(0x00)
	Type_Request       = byte(0x04)
	Type_PeerList      = byte(0x06)
	Type_PeerListAudio = byte(0x07)
	Type_KEX           = byte(0x80)

	CallsignBytes   = 32
	ChannelBytes    = 32
	PublicKeyBytes  = 32
	KEXPacketBytes  = 1 + PublicKeyBytes
	EnvelopeHeader  = 1 + 8
	TagBytes        = 16
	MaxDatagram     = 1200
	MaxPayload      = MaxDatagram - EnvelopeHeader - TagBytes
	EndpointBytes   = 4 + 2
	RequestBytes    = CallsignBytes + ChannelBytes
	PeerRecordBytes = EndpointBytes + CallsignBytes
	PeersPerPacket  = MaxPayload / PeerRecordBytes

	AudioPacketBytes        = EnvelopeHeader + PlainFrame + TagBytes
	AudioPacketsPerSecond   = SampleRate / FrameSamples
	AudioPayloadBitrate     = AudioPacketBytes * AudioPacketsPerSecond * 8
	AudioIPv4UDPHeaderBytes = 20 + 8
	AudioIPv4UDPBitrate     = (AudioPacketBytes + AudioIPv4UDPHeaderBytes) * AudioPacketsPerSecond * 8

	KEXInterval     = 500 * time.Millisecond
	KEXTimeout      = 10 * time.Second
	RequestInterval = 500 * time.Millisecond
	RequestAttempts = 3
	ResponseTimeout = 10 * time.Second
	PeerTTL         = time.Minute
	EntryTTL        = 24 * time.Hour
)

type Callsign [CallsignBytes]byte

type Channel [ChannelBytes]byte

type PeerRecord struct {
	IP       [4]byte
	Port     uint16
	Callsign Callsign
}

func TypeEncrypted(kind byte) bool {
	switch kind {
	case Type_Audio, Type_Request, Type_PeerList, Type_PeerListAudio:
		return true
	default:
		return false
	}
}

func KEX(public [PublicKeyBytes]byte) []byte {
	packet := make([]byte, KEXPacketBytes)
	packet[0] = Type_KEX
	copy(packet[1:], public[:])

	return packet
}

func KEXParse(packet []byte) ([PublicKeyBytes]byte, bool) {
	var public [PublicKeyBytes]byte

	if len(packet) != KEXPacketBytes || packet[0] != Type_KEX {
		return public, false
	}

	copy(public[:], packet[1:])

	return public, true
}

func EnvelopeHeaderFor(kind byte, seq uint64) [EnvelopeHeader]byte {
	var header [EnvelopeHeader]byte

	header[0] = kind
	binary.BigEndian.PutUint64(header[1:], seq)

	return header
}

func EnvelopeParse(
	packet []byte,
) (kind byte, seq uint64, aad []byte, ciphertext []byte, ok bool) {
	if len(packet) < EnvelopeHeader+TagBytes || len(packet) > MaxDatagram {
		return 0, 0, nil, nil, false
	}

	kind = packet[0]
	seq = binary.BigEndian.Uint64(packet[1:EnvelopeHeader])
	if !TypeEncrypted(kind) || seq == 0 {
		return 0, 0, nil, nil, false
	}

	return kind, seq, packet[:EnvelopeHeader], packet[EnvelopeHeader:], true
}

func Request(callsign Callsign, channel Channel) []byte {
	payload := make([]byte, RequestBytes)
	copy(payload, callsign[:])
	copy(payload[CallsignBytes:], channel[:])

	return payload
}

func RequestParse(payload []byte) (Callsign, Channel, bool) {
	var (
		callsign Callsign
		channel  Channel
	)

	if len(payload) != RequestBytes {
		return callsign, channel, false
	}

	copy(callsign[:], payload[:CallsignBytes])
	copy(channel[:], payload[CallsignBytes:])

	return callsign, channel, true
}

func PeerRecordFrom(addr *net.UDPAddr, callsign Callsign) (PeerRecord, bool) {
	var record PeerRecord

	ip := addr.IP.To4()
	if ip == nil || addr.Port < 1 || addr.Port > 65535 {
		return record, false
	}

	copy(record.IP[:], ip)
	record.Port = uint16(addr.Port)
	record.Callsign = callsign

	return record, true
}

func (r PeerRecord) Addr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IPv4(r.IP[0], r.IP[1], r.IP[2], r.IP[3]),
		Port: int(r.Port),
	}
}

func PeerList(records []PeerRecord) ([]byte, bool) {
	if len(records) > PeersPerPacket {
		return nil, false
	}

	payload := make([]byte, len(records)*PeerRecordBytes)
	for i, record := range records {
		if record.Port == 0 {
			return nil, false
		}

		offset := i * PeerRecordBytes
		copy(payload[offset:offset+4], record.IP[:])
		binary.BigEndian.PutUint16(payload[offset+4:offset+6], record.Port)
		copy(payload[offset+6:offset+PeerRecordBytes], record.Callsign[:])
	}

	return payload, true
}

func PeerListParse(payload []byte) ([]PeerRecord, bool) {
	if len(payload) > MaxPayload || len(payload)%PeerRecordBytes != 0 {
		return nil, false
	}

	records := make([]PeerRecord, len(payload)/PeerRecordBytes)
	for i := range len(records) {
		offset := i * PeerRecordBytes
		copy(records[i].IP[:], payload[offset:offset+4])
		records[i].Port = binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		copy(records[i].Callsign[:], payload[offset+6:offset+PeerRecordBytes])
		if records[i].Port == 0 {
			return nil, false
		}
	}

	return records, true
}
