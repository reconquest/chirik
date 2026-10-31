package main

import (
	"net"
	"sync/atomic"
	"time"

	"chirik/internal/audio"
	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

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

	handle         proto.Handle
	handleKnown    bool
	expectedHandle proto.Handle
	expectedKnown  bool

	state            linkState
	initiated        bool
	peerex           bool
	relay            bool
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

	counters             counters
	sampledSentBytes     uint64
	sampledReceivedBytes uint64
}

type counters struct {
	sent          atomic.Uint64
	received      atomic.Uint64
	badAuth       atomic.Uint64
	sentBytes     atomic.Uint64
	receivedBytes atomic.Uint64
}

func (link *link) stateActive() bool { return link.state == linkState_Active }

func (link *link) identity() (proto.Handle, bool) {
	switch {
	case link.handleKnown:
		return link.handle, true

	case link.expectedKnown:
		return link.expectedHandle, true

	default:
		return "", false
	}
}

func (link *link) matchesHandle(handle proto.Handle) bool {
	return (link.handleKnown && link.handle == handle) ||
		(link.expectedKnown && link.expectedHandle == handle)
}
