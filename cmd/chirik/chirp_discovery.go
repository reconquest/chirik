package main

import (
	"chirik/internal/proto"
)

func (m *manager) peerListBroadcast() { m.discoveryEnsure().broadcast(m.cfg.channel) }

func (m *manager) discoveryEnsure() *discoveryEngine {
	if m.discovery != nil {
		return m.discovery
	}

	m.discovery = &discoveryEngine{
		conn: m.t.conn,
		policy: discoveryPolicy{
			audio: true,
			ttl:   proto.PeerTTL,
		},
		records: func(_ string, exclude proto.Handle) []proto.PeerRecord {
			return m.peerRecords(exclude)
		},
		recipients: m.discoveryRecipients,
	}

	return m.discovery
}

func (m *manager) discoveryRecipients(channel string) []discoveryRecipient {
	if channel != m.cfg.channel {
		return nil
	}

	var recipients []discoveryRecipient
	for _, links := range m.links {
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
