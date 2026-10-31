package main

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/reconquest/karma-go"

	"chirik/internal/proto"
)

const endpointRecordsPerPeer = 2

func (server *exchangeServer) peerListHandle(
	session *exchangeSession,
	payload []byte,
	now time.Time,
) {
	server.mu.Lock()

	if !server.sessionContains(session) || !session.registered {
		server.mu.Unlock()

		return
	}

	channel := session.channel
	source := session.handle
	server.mu.Unlock()

	records, ok := proto.PeerListParse(payload)
	if !ok {
		return
	}

	changed := discoveryMerge(
		records,
		func(record proto.PeerRecord) bool {
			return server.discoveryCandidateAdd(channel, source, record, now)
		},
	)

	server.mu.Lock()

	if server.sessionContains(session) {
		session.seen = now
	}

	server.mu.Unlock()

	if changed {
		err := server.discoveryEnsure().broadcast(channel)
		if err != nil {
			server.logger.Print(
				"ERROR ",
				karma.Format(err, "broadcast peer list"),
			)
		}
	}
}

func (server *exchangeServer) discoveryCandidateAdd(
	channel string,
	source proto.Handle,
	record proto.PeerRecord,
	now time.Time,
) bool {
	if record.Handle == source {
		return false
	}

	server.mu.Lock()
	defer server.mu.Unlock()

	entries := server.entries[channel]
	if entries == nil {
		entries = make(map[proto.Handle]*exchangeEntry)
		server.entries[channel] = entries
	}

	stored := entries[record.Handle]
	if stored != nil {
		endpointMatches := udpAddrEqual(stored.addr, record.Addr()) ||
			udpAddrEqual(stored.local, record.Addr())
		if endpointMatches && stored.session == nil {
			stored.seen = now
		}

		return false
	}

	entries[record.Handle] = &exchangeEntry{
		addr:   record.Addr(),
		handle: record.Handle,
		seen:   now,
	}

	return true
}

func (server *exchangeServer) discoveryEnsure() *discoveryEngine {
	if server.discovery != nil {
		return server.discovery
	}

	server.discovery = &discoveryEngine{
		conn: server.conn,
		policy: discoveryPolicy{
			audio: false,
			ttl:   proto.EntryTTL,
		},
		records:    server.discoveryRecords,
		recipients: server.discoveryRecipients,
		packetSent: server.discoveryPacketSent,
	}

	return server.discovery
}

func (server *exchangeServer) discoveryRecords(
	channel string,
	exclude proto.Handle,
) []proto.PeerRecord {
	server.mu.Lock()
	defer server.mu.Unlock()

	entries := server.entries[channel]
	records := make([]proto.PeerRecord, 0, endpointRecordsPerPeer*len(entries))

	for _, item := range entries {
		if item.handle == exclude {
			continue
		}

		records = append(
			records,
			server.endpointRecordsFor(item.addr, item.local, item.handle)...)
	}

	return records
}

func (server *exchangeServer) endpointRecordsFor(
	public *net.UDPAddr,
	local *net.UDPAddr,
	handle proto.Handle,
) []proto.PeerRecord {
	if server.endpointRecords != nil {
		return server.endpointRecords(public, local, handle)
	}

	return exchangeEndpointRecords(public, local, handle)
}

func exchangeEndpointRecords(
	public *net.UDPAddr,
	local *net.UDPAddr,
	handle proto.Handle,
) []proto.PeerRecord {
	records := make([]proto.PeerRecord, 0, endpointRecordsPerPeer)
	if record, ok := proto.PeerRecordFrom(public, handle); ok {
		records = append(records, record)
	}

	if local != nil && !udpAddrEqual(local, public) {
		if record, ok := proto.PeerRecordFrom(local, handle); ok {
			records = append(records, record)
		}
	}

	return records
}

func (server *exchangeServer) discoveryRecipients(
	channel string,
) []discoveryRecipient {
	server.mu.Lock()
	defer server.mu.Unlock()

	entries := server.entries[channel]
	recipients := make([]discoveryRecipient, 0, len(entries))

	for _, item := range entries {
		if item.session == nil || item.session.voice == nil {
			continue
		}

		recipients = append(recipients, discoveryRecipient{
			addr:    addrCopy(item.addr),
			handle:  item.handle,
			session: item.session.voice,
		})
	}

	return recipients
}

func (server *exchangeServer) discoveryPacketSent(
	channel string,
	recipient discoveryRecipient,
	packet int,
	packets int,
	records []proto.PeerRecord,
) {
	server.logger.Print("INFO ", karma.
		Describe("type", "PEER_LIST").
		Describe("channel", channel).
		Describe("to_handle", recipient.handle).
		Describe("to_addr", recipient.addr).
		Describe("packet", packet).
		Describe("packets", packets).
		Describe("peers", exchangeRecordsLog(records)).
		Format(nil, "packet sent"),
	)
}

func exchangeRecordsLog(records []proto.PeerRecord) string {
	peers := make([]string, len(records))
	for index, record := range records {
		peers[index] = fmt.Sprintf("%s@%s", record.Handle, record.Addr())
	}

	slices.Sort(peers)

	return strings.Join(peers, ",")
}
