package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"chirik/internal/proto"
)

const PublicKeyBytes = proto.PublicKeyBytes

const infoLabel = "CHIRIK-V2-AES-256-GCM"

var (
	ErrPacket     = errors.New("invalid encrypted packet")
	ErrPayload    = errors.New("invalid payload")
	ErrReplay     = errors.New("stale or duplicate sequence")
	ErrSequence   = errors.New("invalid sequence")
	ErrUnknown    = errors.New("unknown packet type")
	ErrPublicKeys = errors.New("identical public keys")
)

type KeyPair struct {
	private *ecdh.PrivateKey
	public  [PublicKeyBytes]byte
}

type Keys struct {
	Send    [32]byte
	Receive [32]byte
}

type Session struct {
	send cipher.AEAD
	recv cipher.AEAD

	mu       sync.Mutex
	sendSeq  [256]uint64
	recvLast [256]uint64
}

func KeyPairGenerate() (*KeyPair, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return keyPairNew(private), nil
}

func KeyPairFromPrivate(privateBytes []byte) (*KeyPair, error) {
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}

	return keyPairNew(private), nil
}

func (p *KeyPair) Public() [PublicKeyBytes]byte { return p.public }
func (p *KeyPair) PrivateBytes() []byte         { return append([]byte(nil), p.private.Bytes()...) }

func (p *KeyPair) Derive(peerBytes []byte, salt []byte) (Keys, error) {
	var keys Keys

	if len(peerBytes) != PublicKeyBytes {
		return keys, fmt.Errorf("peer public key length %d", len(peerBytes))
	}

	peer, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return keys, fmt.Errorf("peer public key: %w", err)
	}

	shared, err := p.private.ECDH(peer)
	if err != nil {
		return keys, fmt.Errorf("ECDH: %w", err)
	}

	order := bytes.Compare(p.public[:], peerBytes)
	if order == 0 {
		return keys, ErrPublicKeys
	}

	info := make([]byte, 0, len(infoLabel)+2*PublicKeyBytes)
	info = append(info, infoLabel...)
	if order < 0 {
		info = append(info, p.public[:]...)
		info = append(info, peerBytes...)
	} else {
		info = append(info, peerBytes...)
		info = append(info, p.public[:]...)
	}

	material, err := hkdf.Key(sha256.New, shared, salt, string(info), 64)
	if err != nil {
		return Keys{}, fmt.Errorf("derive session keys: %w", err)
	}

	if order < 0 {
		copy(keys.Send[:], material[:32])
		copy(keys.Receive[:], material[32:])
	} else {
		copy(keys.Send[:], material[32:])
		copy(keys.Receive[:], material[:32])
	}

	return keys, nil
}

func SessionNew(keys Keys) (*Session, error) {
	send, err := aeadNew(keys.Send[:])
	if err != nil {
		return nil, fmt.Errorf("send AEAD: %w", err)
	}

	recv, err := aeadNew(keys.Receive[:])
	if err != nil {
		return nil, fmt.Errorf("receive AEAD: %w", err)
	}

	return &Session{send: send, recv: recv}, nil
}

func (s *Session) Seal(kind byte, payload []byte) ([]byte, error) {
	if !proto.TypeEncrypted(kind) {
		return nil, ErrUnknown
	}

	if len(payload) > proto.MaxPayload {
		return nil, ErrPayload
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	seq := s.sendSeq[kind] + 1
	if seq == 0 {
		return nil, ErrSequence
	}
	s.sendSeq[kind] = seq

	header := proto.EnvelopeHeaderFor(kind, seq)
	nonce := nonceFor(kind, seq)
	packet := make([]byte, proto.EnvelopeHeader, proto.EnvelopeHeader+len(payload)+proto.TagBytes)
	copy(packet, header[:])
	packet = s.send.Seal(packet, nonce[:], payload, header[:])

	return packet, nil
}

func (s *Session) Open(packet []byte) (kind byte, seq uint64, payload []byte, err error) {
	kind, seq, aad, ciphertext, ok := proto.EnvelopeParse(packet)
	if !ok {
		return 0, 0, nil, ErrPacket
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if seq <= s.recvLast[kind] {
		return kind, seq, nil, ErrReplay
	}

	nonce := nonceFor(kind, seq)
	payload, err = s.recv.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return kind, seq, nil, err
	}

	if len(payload) > proto.MaxPayload {
		return kind, seq, nil, ErrPayload
	}

	s.recvLast[kind] = seq

	return kind, seq, payload, nil
}

func keyPairNew(private *ecdh.PrivateKey) *KeyPair {
	pair := &KeyPair{private: private}
	copy(pair.public[:], private.PublicKey().Bytes())

	return pair
}

func aeadNew(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func nonceFor(kind byte, seq uint64) [12]byte {
	var nonce [12]byte

	nonce[0] = kind
	binary.BigEndian.PutUint64(nonce[4:], seq)

	return nonce
}
