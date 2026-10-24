package proto

import (
	"crypto/sha256"
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
	Type_Relay         = byte(0x08)
	Type_KEX           = byte(0x80)

	PublicKeyBytes = 32
	KEXPacketBytes = 1 + PublicKeyBytes
	EnvelopeHeader = 1 + 8
	TagBytes       = 16
	MaxDatagram    = 1200
	MaxPayload     = MaxDatagram - EnvelopeHeader - TagBytes
	MaxHandleBytes = 255

	AudioPacketBytes        = EnvelopeHeader + PlainFrame + TagBytes
	AudioPacketsPerSecond   = SampleRate / FrameSamples
	AudioPayloadBitrate     = AudioPacketBytes * AudioPacketsPerSecond * 8
	AudioIPv4UDPHeaderBytes = 20 + 8
	AudioIPv4UDPBitrate     = (AudioPacketBytes + AudioIPv4UDPHeaderBytes) * AudioPacketsPerSecond * 8

	KEXInterval        = 500 * time.Millisecond
	KEXTimeout         = 10 * time.Second
	RequestInterval    = 500 * time.Millisecond
	RequestAttempts    = 3
	ResponseTimeout    = 10 * time.Second
	RelayFallbackDelay = 2 * time.Second
	PeerTTL            = time.Minute
	EntryTTL           = 24 * time.Hour

	relayPrefixBytes      = 1
	MaxRelayInner         = MaxPayload - relayPrefixBytes - MaxHandleBytes
	MaxRequestPayload     = MaxRelayInner - EnvelopeHeader - TagBytes
	requestPrefixBytes    = 1 + 4 + 2
	peerRecordPrefixBytes = 4 + 2 + 1
)

type Handle string

type PeerRecord struct {
	IP     [4]byte
	Port   uint16
	Handle Handle
}

func HandleValid(handle Handle) bool {
	if len(handle) == 0 || len(handle) > MaxHandleBytes {
		return false
	}

	for _, char := range []byte(handle) {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		default:
			return false
		}
	}

	return true
}

func ChannelKey(channel string) [32]byte { return sha256.Sum256([]byte(channel)) }

func TypeEncrypted(kind byte) bool {
	switch kind {
	case Type_Audio, Type_Request, Type_PeerList, Type_PeerListAudio, Type_Relay:
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

func RequestValid(handle Handle, channel string) bool {
	return HandleValid(handle) && len(channel) != 0 &&
		requestPrefixBytes+len(handle)+len(channel) <= MaxRequestPayload
}

func Request(handle Handle, channel string, local *net.UDPAddr) ([]byte, bool) {
	if local == nil || local.IP.IsUnspecified() {
		return nil, false
	}
	localRecord, ok := PeerRecordFrom(local, handle)
	if !ok || !RequestValid(handle, channel) {
		return nil, false
	}

	payload := make([]byte, requestPrefixBytes+len(handle)+len(channel))
	payload[0] = byte(len(handle))
	copy(payload[1:1+len(handle)], handle)
	offset := 1 + len(handle)
	copy(payload[offset:offset+4], localRecord.IP[:])
	binary.BigEndian.PutUint16(payload[offset+4:offset+6], localRecord.Port)
	copy(payload[offset+6:], channel)

	return payload, true
}

func RequestParse(payload []byte) (Handle, string, *net.UDPAddr, bool) {
	if len(payload) < requestPrefixBytes+2 || len(payload) > MaxPayload {
		return "", "", nil, false
	}

	handleBytes := int(payload[0])
	offset := 1 + handleBytes
	if handleBytes == 0 || offset+6 >= len(payload) {
		return "", "", nil, false
	}

	handle := Handle(payload[1:offset])
	localRecord := PeerRecord{
		Port:   binary.BigEndian.Uint16(payload[offset+4 : offset+6]),
		Handle: handle,
	}
	copy(localRecord.IP[:], payload[offset:offset+4])
	channel := string(payload[offset+6:])
	local := localRecord.Addr()
	if !RequestValid(handle, channel) || localRecord.Port == 0 || local.IP.IsUnspecified() {
		return "", "", nil, false
	}

	return handle, channel, local, true
}

func Relay(handle Handle, packet []byte) ([]byte, bool) {
	if !HandleValid(handle) || len(packet) == 0 || len(packet) > MaxRelayInner {
		return nil, false
	}

	payload := make([]byte, relayPrefixBytes+len(handle)+len(packet))
	payload[0] = byte(len(handle))
	copy(payload[relayPrefixBytes:], handle)
	copy(payload[relayPrefixBytes+len(handle):], packet)

	return payload, true
}

func RelayParse(payload []byte) (Handle, []byte, bool) {
	if len(payload) < relayPrefixBytes+2 || len(payload) > MaxPayload {
		return "", nil, false
	}

	handleBytes := int(payload[0])
	offset := relayPrefixBytes + handleBytes
	if handleBytes == 0 || offset >= len(payload) {
		return "", nil, false
	}

	handle := Handle(payload[relayPrefixBytes:offset])
	packet := payload[offset:]
	if !HandleValid(handle) || len(packet) > MaxRelayInner {
		return "", nil, false
	}

	return handle, packet, true
}

func PeerRecordFrom(addr *net.UDPAddr, handle Handle) (PeerRecord, bool) {
	var record PeerRecord

	ip := addr.IP.To4()
	if ip == nil || addr.Port < 1 || addr.Port > 65535 || !HandleValid(handle) {
		return record, false
	}

	copy(record.IP[:], ip)
	record.Port = uint16(addr.Port)
	record.Handle = handle

	return record, true
}

func (r PeerRecord) Addr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IPv4(r.IP[0], r.IP[1], r.IP[2], r.IP[3]),
		Port: int(r.Port),
	}
}

func PeerList(records []PeerRecord) ([]byte, bool) {
	size := 0
	for _, record := range records {
		if record.Port == 0 || !HandleValid(record.Handle) {
			return nil, false
		}

		size += peerRecordPrefixBytes + len(record.Handle)
		if size > MaxPayload {
			return nil, false
		}
	}

	payload := make([]byte, size)
	offset := 0
	for _, record := range records {
		copy(payload[offset:offset+4], record.IP[:])
		binary.BigEndian.PutUint16(payload[offset+4:offset+6], record.Port)
		payload[offset+6] = byte(len(record.Handle))
		copy(payload[offset+peerRecordPrefixBytes:], record.Handle)
		offset += peerRecordPrefixBytes + len(record.Handle)
	}

	return payload, true
}

func PeerListSplit(records []PeerRecord) ([][]byte, bool) {
	if len(records) == 0 {
		return [][]byte{{}}, true
	}

	var (
		payloads [][]byte
		start    int
		size     int
	)
	for i, record := range records {
		if record.Port == 0 || !HandleValid(record.Handle) {
			return nil, false
		}

		recordBytes := peerRecordPrefixBytes + len(record.Handle)
		if recordBytes > MaxPayload {
			return nil, false
		}

		if size+recordBytes > MaxPayload {
			payload, ok := PeerList(records[start:i])
			if !ok {
				return nil, false
			}
			payloads = append(payloads, payload)
			start = i
			size = 0
		}

		size += recordBytes
	}

	payload, ok := PeerList(records[start:])
	if !ok {
		return nil, false
	}
	payloads = append(payloads, payload)

	return payloads, true
}

func PeerListParse(payload []byte) ([]PeerRecord, bool) {
	if len(payload) > MaxPayload {
		return nil, false
	}

	var records []PeerRecord
	for offset := 0; offset < len(payload); {
		if len(payload)-offset < peerRecordPrefixBytes {
			return nil, false
		}

		handleBytes := int(payload[offset+6])
		end := offset + peerRecordPrefixBytes + handleBytes
		if handleBytes == 0 || end > len(payload) {
			return nil, false
		}

		record := PeerRecord{
			Port:   binary.BigEndian.Uint16(payload[offset+4 : offset+6]),
			Handle: Handle(payload[offset+peerRecordPrefixBytes : end]),
		}
		copy(record.IP[:], payload[offset:offset+4])
		if record.Port == 0 || !HandleValid(record.Handle) {
			return nil, false
		}

		records = append(records, record)
		offset = end
	}

	return records, true
}
