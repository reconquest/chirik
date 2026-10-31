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

	"github.com/reconquest/karma-go"

	"chirik/internal/proto"
)

const PublicKeyBytes = proto.PublicKeyBytes

const sessionKeyMaterialBytes = 64

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
		return nil, karma.Format(err, "generate X25519 key pair")
	}

	return keyPairNew(private), nil
}

func (pair *KeyPair) Public() [PublicKeyBytes]byte { return pair.public }

func (pair *KeyPair) Derive(peerBytes, salt []byte) (Keys, error) {
	var keys Keys

	if len(peerBytes) != PublicKeyBytes {
		return keys, fmt.Errorf("peer public key length %d", len(peerBytes))
	}

	peer, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return keys, karma.Format(err, "parse peer public key")
	}

	shared, err := pair.private.ECDH(peer)
	if err != nil {
		return keys, karma.Format(err, "derive ECDH shared secret")
	}

	order := bytes.Compare(pair.public[:], peerBytes)
	if order == 0 {
		return keys, ErrPublicKeys
	}

	info := make([]byte, 0, len(infoLabel)+2*PublicKeyBytes)

	info = append(info, infoLabel...)

	if order < 0 {
		info = append(info, pair.public[:]...)
		info = append(info, peerBytes...)
	} else {
		info = append(info, peerBytes...)
		info = append(info, pair.public[:]...)
	}

	material, err := hkdf.Key(
		sha256.New,
		shared,
		salt,
		string(info),
		sessionKeyMaterialBytes,
	)
	if err != nil {
		return Keys{}, karma.Format(err, "derive session keys")
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
		return nil, karma.Format(err, "create send AEAD")
	}

	recv, err := aeadNew(keys.Receive[:])
	if err != nil {
		return nil, karma.Format(err, "create receive AEAD")
	}

	return &Session{send: send, recv: recv}, nil
}

func (session *Session) Seal(kind byte, payload []byte) ([]byte, error) {
	if !proto.TypeEncrypted(kind) {
		return nil, ErrUnknown
	}

	if len(payload) > proto.MaxPayload {
		return nil, ErrPayload
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	seq := session.sendSeq[kind] + 1
	if seq == 0 {
		return nil, ErrSequence
	}

	session.sendSeq[kind] = seq

	header := proto.EnvelopeHeaderFor(kind, seq)
	nonce := nonceFor(kind, seq)
	packet := make(
		[]byte,
		proto.EnvelopeHeader,
		proto.EnvelopeHeader+len(payload)+proto.TagBytes,
	)
	copy(packet, header[:])

	packet = session.send.Seal(packet, nonce[:], payload, header[:])

	return packet, nil
}

func (session *Session) Open(
	packet []byte,
) (byte, uint64, []byte, error) {
	kind, seq, aad, ciphertext, ok := proto.EnvelopeParse(packet)
	if !ok {
		return 0, 0, nil, ErrPacket
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if seq <= session.recvLast[kind] {
		return kind, seq, nil, ErrReplay
	}

	nonce := nonceFor(kind, seq)

	payload, err := session.recv.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return kind, seq, nil, karma.Format(err, "decrypt session packet")
	}

	if len(payload) > proto.MaxPayload {
		return kind, seq, nil, ErrPayload
	}

	session.recvLast[kind] = seq

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
		return nil, karma.Format(err, "create AES cipher")
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, karma.Format(err, "create GCM")
	}

	return aead, nil
}

func nonceFor(kind byte, seq uint64) [12]byte {
	var nonce [12]byte

	nonce[0] = kind
	binary.BigEndian.PutUint64(nonce[4:], seq)

	return nonce
}
