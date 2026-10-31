package main

import (
	"net"
	"time"

	"github.com/reconquest/karma-go"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

const endpointRefreshInterval = time.Second

func (client *client) endpointRefresh(now time.Time) {
	if now.Before(client.endpointRefreshNext) {
		return
	}

	client.endpointRefreshNext = now.Add(endpointRefreshInterval)

	local, err := localEndpoint(client.t.conn, client.cfg.peerex)
	if err != nil {
		client.endpointUnavailable(err)

		return
	}

	client.endpointChanged(local)
	client.endpointRecoveryResume(now)
}

func (client *client) endpointUnavailable(err error) {
	if !client.peerexRecoveryRequired && client.logger != nil {
		client.logger.Print(
			"INFO ",
			karma.Format(err, "local UDP endpoint unavailable"),
		)
	}

	client.peerexRecoveryRequired = true
	client.peerexRecoveryStarted = false
}

func (client *client) endpointChanged(local *net.UDPAddr) {
	if udpAddrEqual(local, client.local) {
		return
	}

	if client.logger != nil {
		client.logger.Print("INFO ", karma.
			Describe("previous", client.local).
			Describe("current", local).
			Format(nil, "local UDP endpoint changed"),
		)
	}

	client.local = local
	client.peerexRecoveryRequired = true
	client.peerexRecoveryStarted = false
}

func (client *client) endpointRecoveryResume(now time.Time) {
	if !client.peerexRecoveryRequired || client.peerexRecoveryStarted {
		return
	}

	err := client.peerexRecoveryStart(now)
	if err != nil && client.logger != nil {
		client.logger.Print("ERROR ", karma.Format(err, "exchange recovery"))
	}
}

func (client *client) peerexRecoveryStart(now time.Time) error {
	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return karma.Format(err, "generate exchange key pair")
	}

	item := client.peerexLink()
	if item == nil {
		item = &link{
			addr:      addrCopy(client.cfg.peerex),
			peerex:    true,
			bootstrap: true,
		}
		client.linkAdd(item)
	}

	item.pair = pair
	item.peerPublic = [sessioncrypto.PublicKeyBytes]byte{}
	item.voice = nil
	item.state = linkState_KEX
	item.initiated = true
	item.audioEligible = false
	item.responseReceived = false
	item.kexNext = time.Time{}
	item.kexDeadline = now.Add(proto.KEXTimeout)
	item.requestNext = time.Time{}
	item.responseDeadline = time.Time{}
	item.requestAttempts = 0
	item.lastKEXSent = time.Time{}
	item.lastSeen = now
	client.peerexRecoveryStarted = true

	sendErr := client.linkKEXSend(item, now)
	if sendErr != nil {
		client.linkRemove(item, sendErr.Error())

		return sendErr
	}

	if client.logger != nil {
		client.logger.Print("INFO ", karma.
			Describe("address", item.addr).
			Format(nil, "exchange recovery started"),
		)
	}

	return nil
}

func (client *client) peerexLink() *link {
	for _, item := range client.links[client.cfg.peerex.String()] {
		if item.peerex {
			return item
		}
	}

	return nil
}
