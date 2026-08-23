package crypto

import (
	"bytes"
	"errors"
	"testing"

	"chirik/internal/proto"
)

func TestDeriveComplements(t *testing.T) {
	a := keyPair(t)
	b := keyPair(t)
	publicA := a.Public()
	publicB := b.Public()
	salt := bytes.Repeat([]byte{0xa5}, proto.ChannelBytes)

	keysA, err := a.Derive(publicB[:], salt)
	if err != nil {
		t.Fatal(err)
	}

	keysB, err := b.Derive(publicA[:], salt)
	if err != nil {
		t.Fatal(err)
	}

	if keysA.Send != keysB.Receive {
		t.Fatal("A send key does not equal B receive key")
	}

	if keysA.Receive != keysB.Send {
		t.Fatal("A receive key does not equal B send key")
	}

	if keysA.Send == keysA.Receive {
		t.Fatal("directional keys are equal")
	}
}

func TestDeriveSeparatesChannels(t *testing.T) {
	a := keyPair(t)
	b := keyPair(t)
	publicB := b.Public()

	first, err := a.Derive(publicB[:], bytes.Repeat([]byte{1}, proto.ChannelBytes))
	if err != nil {
		t.Fatal(err)
	}

	second, err := a.Derive(publicB[:], bytes.Repeat([]byte{2}, proto.ChannelBytes))
	if err != nil {
		t.Fatal(err)
	}

	if first.Send == second.Send || first.Receive == second.Receive {
		t.Fatal("channel did not separate derived material")
	}
}

func TestKeyPairFromPrivate(t *testing.T) {
	original := keyPair(t)
	restored, err := KeyPairFromPrivate(original.PrivateBytes())
	if err != nil {
		t.Fatal(err)
	}

	if restored.Public() != original.Public() {
		t.Fatal("restored public key differs")
	}
}

func TestSessionSealOpen(t *testing.T) {
	sessionA, sessionB := sessionPair(t)
	plaintext := bytes.Repeat([]byte{0xa5}, proto.PlainFrame)
	packet, err := sessionA.Seal(proto.Type_Audio, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if len(packet) != proto.AudioPacketBytes {
		t.Fatalf("packet length = %d", len(packet))
	}

	kind, seq, opened, err := sessionB.Open(packet)
	if err != nil {
		t.Fatal(err)
	}

	if kind != proto.Type_Audio || seq != 1 {
		t.Fatalf("packet = %#x/%d", kind, seq)
	}

	if !bytes.Equal(opened, plaintext) {
		t.Fatal("plaintext differs")
	}

	if _, _, _, err := sessionB.Open(packet); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestSessionAcceptsGapDropsReordering(t *testing.T) {
	sessionA, sessionB := sessionPair(t)
	first, err := sessionA.Seal(proto.Type_Audio, make([]byte, proto.PlainFrame))
	if err != nil {
		t.Fatal(err)
	}

	second, err := sessionA.Seal(proto.Type_Audio, make([]byte, proto.PlainFrame))
	if err != nil {
		t.Fatal(err)
	}

	third, err := sessionA.Seal(proto.Type_Audio, make([]byte, proto.PlainFrame))
	if err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := sessionB.Open(first); err != nil {
		t.Fatal(err)
	}

	if _, seq, _, err := sessionB.Open(third); err != nil || seq != 3 {
		t.Fatalf("gap packet = %d, %v", seq, err)
	}

	if _, _, _, err := sessionB.Open(second); !errors.Is(err, ErrReplay) {
		t.Fatalf("reordered error = %v", err)
	}
}

func TestSessionCountersArePerType(t *testing.T) {
	sessionA, sessionB := sessionPair(t)
	request, err := sessionA.Seal(proto.Type_Request, make([]byte, proto.RequestBytes))
	if err != nil {
		t.Fatal(err)
	}

	audio, err := sessionA.Seal(proto.Type_Audio, make([]byte, proto.PlainFrame))
	if err != nil {
		t.Fatal(err)
	}

	for _, packet := range [][]byte{request, audio} {
		_, seq, _, err := sessionB.Open(packet)
		if err != nil {
			t.Fatal(err)
		}

		if seq != 1 {
			t.Fatalf("sequence = %d, want 1", seq)
		}
	}
}

func TestSessionTampering(t *testing.T) {
	sessionA, sessionB := sessionPair(t)
	packet, err := sessionA.Seal(proto.Type_Audio, make([]byte, proto.PlainFrame))
	if err != nil {
		t.Fatal(err)
	}

	packet[len(packet)-1] ^= 1
	if _, _, _, err := sessionB.Open(packet); err == nil {
		t.Fatal("tampered packet authenticated")
	}
}

func sessionPair(t *testing.T) (*Session, *Session) {
	t.Helper()

	a := keyPair(t)
	b := keyPair(t)
	publicA := a.Public()
	publicB := b.Public()
	salt := bytes.Repeat([]byte{0xa5}, proto.ChannelBytes)
	keysA, err := a.Derive(publicB[:], salt)
	if err != nil {
		t.Fatal(err)
	}

	keysB, err := b.Derive(publicA[:], salt)
	if err != nil {
		t.Fatal(err)
	}

	sessionA, err := SessionNew(keysA)
	if err != nil {
		t.Fatal(err)
	}

	sessionB, err := SessionNew(keysB)
	if err != nil {
		t.Fatal(err)
	}

	return sessionA, sessionB
}

func keyPair(t *testing.T) *KeyPair {
	t.Helper()

	pair, err := KeyPairGenerate()
	if err != nil {
		t.Fatal(err)
	}

	return pair
}
