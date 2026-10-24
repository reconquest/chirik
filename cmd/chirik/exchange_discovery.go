package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"chirik/internal/proto"
)

func (s *exchangeServer) peerListHandle(
	session *exchangeSession,
	payload []byte,
	now time.Time,
) {
	s.mu.Lock()
	if !s.sessionContains(session) || !session.registered {
		s.mu.Unlock()
		return
	}
	channel := session.channel
	source := session.handle
	s.mu.Unlock()

	records, ok := s.discoveryEnsure().decode(payload)
	if !ok {
		return
	}
	changed := s.discoveryEnsure().merge(
		records,
		func(record proto.PeerRecord) bool {
			return s.discoveryCandidateAdd(channel, source, record, now)
		},
	)

	s.mu.Lock()
	if s.sessionContains(session) {
		session.seen = now
	}
	s.mu.Unlock()
	if changed {
		s.discoveryEnsure().broadcast(channel)
	}
}

func (s *exchangeServer) discoveryCandidateAdd(
	channel string,
	source proto.Handle,
	record proto.PeerRecord,
	now time.Time,
) bool {
	if record.Handle == source {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries := s.entries[channel]
	if entries == nil {
		entries = make(map[proto.Handle]*exchangeEntry)
		s.entries[channel] = entries
	}

	stored := entries[record.Handle]
	if stored != nil {
		if (udpAddrEqual(stored.addr, record.Addr()) || udpAddrEqual(stored.local, record.Addr())) &&
			stored.session == nil {
			stored.seen = now
		}
		return false
	}

	entries[record.Handle] = &exchangeEntry{
		addr:    record.Addr(),
		handle:  record.Handle,
		channel: channel,
		seen:    now,
	}
	return true
}

func (s *exchangeServer) discoveryEnsure() *discoveryEngine {
	if s.discovery != nil {
		return s.discovery
	}

	s.discovery = &discoveryEngine{
		conn: s.conn,
		policy: discoveryPolicy{
			audio: false,
			ttl:   proto.EntryTTL,
		},
		records:    s.discoveryRecords,
		recipients: s.discoveryRecipients,
		packetSent: s.discoveryPacketSent,
	}
	return s.discovery
}

func (s *exchangeServer) discoveryRecords(
	channel string,
	exclude proto.Handle,
) []proto.PeerRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := s.entries[channel]
	records := make([]proto.PeerRecord, 0, 2*len(entries))
	for _, item := range entries {
		if item.handle == exclude {
			continue
		}
		records = append(records, s.endpointRecordsFor(item.addr, item.local, item.handle)...)
	}
	return records
}

func (s *exchangeServer) endpointRecordsFor(
	public *net.UDPAddr,
	local *net.UDPAddr,
	handle proto.Handle,
) []proto.PeerRecord {
	if s.endpointRecords != nil {
		return s.endpointRecords(public, local, handle)
	}
	return exchangeEndpointRecords(public, local, handle)
}

func exchangeEndpointRecords(
	public *net.UDPAddr,
	local *net.UDPAddr,
	handle proto.Handle,
) []proto.PeerRecord {
	records := make([]proto.PeerRecord, 0, 2)
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

func (s *exchangeServer) discoveryRecipients(channel string) []discoveryRecipient {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := s.entries[channel]
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

func (s *exchangeServer) discoveryPacketSent(
	channel string,
	recipient discoveryRecipient,
	packet int,
	packets int,
	records []proto.PeerRecord,
) {
	s.logger.Printf(
		"SEND type=PEER_LIST channel=%q to_handle=%q to_addr=%s packet=%d/%d peers=[%s]",
		channel, recipient.handle, recipient.addr,
		packet, packets,
		exchangeRecordsLog(records),
	)
}

func exchangeRecordsLog(records []proto.PeerRecord) string {
	peers := make([]string, len(records))
	for i, record := range records {
		peers[i] = fmt.Sprintf("%s@%s", record.Handle, record.Addr())
	}
	sort.Strings(peers)

	return strings.Join(peers, ",")
}
