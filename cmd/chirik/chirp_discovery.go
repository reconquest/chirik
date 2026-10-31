package main

import (
	"github.com/reconquest/karma-go"

	"chirik/internal/proto"
)

func (client *client) peerListBroadcast() {
	err := client.discoveryEnsure().broadcast(client.cfg.channel)
	client.peerListBroadcastReport(err)
}

func (client *client) peerListAnnounce(item *link, changed bool) error {
	if item.relay {
		return client.relayPeerListSend(item)
	}

	engine := client.discoveryEnsure()
	recipient := discoveryRecipient{
		addr:    item.addr,
		handle:  item.handle,
		session: item.voice,
	}

	err := engine.reply(client.cfg.channel, recipient)
	if changed {
		broadcastErr := engine.broadcastExcept(client.cfg.channel, recipient)
		client.peerListBroadcastReport(broadcastErr)
	}

	return err
}

func (client *client) peerListBroadcastReport(err error) {
	if err == nil {
		return
	}

	logger := client.logger
	if logger == nil {
		logger = loggerNew(client.stderr)
	}

	logger.Print("ERROR ", karma.Format(err, "broadcast peer list"))
}

func (client *client) discoveryEnsure() *discoveryEngine {
	if client.discovery != nil {
		return client.discovery
	}

	client.discovery = &discoveryEngine{
		conn: client.t.conn,
		policy: discoveryPolicy{
			audio: true,
			ttl:   proto.PeerTTL,
		},
		records: func(channel string, exclude proto.Handle) []proto.PeerRecord {
			if channel != client.cfg.channel {
				return nil
			}

			return client.peerRecords(exclude)
		},
		recipients: client.discoveryRecipients,
	}

	return client.discovery
}

func (client *client) discoveryRecipients(channel string) []discoveryRecipient {
	if channel != client.cfg.channel {
		return nil
	}

	var recipients []discoveryRecipient

	for _, links := range client.links {
		for _, item := range append([]*link(nil), links...) {
			if !item.stateActive() || item.voice == nil || item.relay {
				continue
			}

			if item.peerex {
				recipients = append(recipients, discoveryRecipient{
					addr:    addrCopy(item.addr),
					session: item.voice,
				})

				continue
			}

			if !item.audioEligible || !item.handleKnown {
				continue
			}

			recipients = append(recipients, discoveryRecipient{
				addr:    addrCopy(item.addr),
				handle:  item.handle,
				session: item.voice,
			})
		}
	}

	return recipients
}
