package main

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/reconquest/karma-go"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

const (
	linkRemovalReplaced  = "replaced"
	directRouteFreshness = 2 * proto.RelayFallbackDelay
)

func (client *client) peerRecords(exclude proto.Handle) []proto.PeerRecord {
	var records []proto.PeerRecord

	seen := make(map[string]struct{})

	for _, links := range client.links {
		for _, item := range links {
			if item.peerex || item.relay {
				continue
			}

			handle, known := item.identity()
			if !known || handle == exclude {
				continue
			}

			record, ok := proto.PeerRecordFrom(item.addr, handle)
			if !ok {
				continue
			}

			key := string(handle) + "\x00" + item.addr.String()
			if _, exists := seen[key]; exists {
				continue
			}

			seen[key] = struct{}{}

			records = append(records, record)
		}
	}

	slices.SortFunc(records, func(left, right proto.PeerRecord) int {
		if left.Handle != right.Handle {
			return cmp.Compare(left.Handle, right.Handle)
		}

		return cmp.Compare(left.Addr().String(), right.Addr().String())
	})

	return records
}

func (client *client) candidateAdd(
	record proto.PeerRecord,
	allowReplacement bool,
	now time.Time,
) bool {
	if record.Handle == client.cfg.handle {
		return false
	}

	tracked, directExists := client.candidatePresence(record)
	if directExists {
		return client.existingDirectRelayAdd(record, allowReplacement, now)
	}

	if tracked && !allowReplacement {
		return false
	}

	if !tracked {
		if _, exists := client.seen[record.Handle]; exists {
			return false
		}
	}

	directAdded := client.directCandidateAdd(record, now)
	relayAdded := false

	if allowReplacement {
		relayAdded = client.relayCandidateAdd(
			record.Handle,
			now,
			proto.RelayFallbackDelay,
		)
	}

	return directAdded || relayAdded
}

func (client *client) existingDirectRelayAdd(
	record proto.PeerRecord,
	allowReplacement bool,
	now time.Time,
) bool {
	if !allowReplacement {
		return false
	}

	return client.relayCandidateAdd(
		record.Handle,
		now,
		proto.RelayFallbackDelay,
	)
}

func (client *client) candidatePresence(
	record proto.PeerRecord,
) (bool, bool) {
	addr := record.Addr()
	tracked := false
	directExists := false

	for _, links := range client.links {
		for _, item := range links {
			if item.peerex || !item.matchesHandle(record.Handle) {
				continue
			}

			tracked = true

			if !item.relay && udpAddrEqual(item.addr, addr) {
				directExists = true
			}
		}
	}

	return tracked, directExists
}

func (client *client) directCandidateAdd(
	record proto.PeerRecord,
	now time.Time,
) bool {
	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return false
	}

	item := &link{
		addr:           record.Addr(),
		pair:           pair,
		expectedHandle: record.Handle,
		expectedKnown:  true,
		state:          linkState_KEX,
		initiated:      true,
		kexDeadline:    now.Add(proto.KEXTimeout),
	}

	client.seen[record.Handle] = struct{}{}
	client.linkAdd(item)

	err = client.linkKEXSend(item, now)
	if err != nil {
		client.linkRemove(item, err.Error())

		return false
	}

	return true
}

func (client *client) linkPromote(item *link, now time.Time) error {
	routeReplacement := client.peerRouteAnnounced(item)

	err := client.linkPlaybackEnsure(item)
	if err != nil {
		return err
	}

	if !item.connectedPrinted {
		client.linkReplaceCompetitors(item)
	}

	item.state = linkState_Active
	item.lastSeen = now

	announced := client.linkConnectedNotify(item)
	if announced && !routeReplacement {
		client.peerCueQueue(peerCueConnect)
	}

	return nil
}

func (client *client) peerRouteAnnounced(candidate *link) bool {
	if !candidate.handleKnown {
		return false
	}

	for _, links := range client.links {
		for _, item := range links {
			if item == candidate || item.peerex || !item.connectedPrinted ||
				!item.matchesHandle(candidate.handle) {
				continue
			}

			return true
		}
	}

	return false
}

func (client *client) linkReplaceCompetitors(item *link) {
	if !item.handleKnown {
		return
	}

	for _, links := range client.links {
		for _, other := range append([]*link(nil), links...) {
			if other == item || other.peerex {
				continue
			}

			if other.matchesHandle(item.handle) {
				client.linkRemove(other, linkRemovalReplaced)
			}
		}
	}

	client.seen[item.handle] = struct{}{}
}

func (client *client) linkPlaybackEnsure(item *link) error {
	if !item.handleKnown || item.playback != nil {
		return nil
	}

	name := fmt.Sprintf("chirik peer %s@%s", item.handle, linkEndpoint(item))

	playback, err := client.playbackOpen(name)
	if err != nil {
		return karma.Format(err, "open peer playback")
	}

	item.playback = playback

	return nil
}

func (client *client) linkConnectedNotify(item *link) bool {
	if !item.handleKnown || item.connectedPrinted {
		return false
	}

	client.output.lineWrite(
		fmt.Sprintf("peer connected: %s@%s", item.handle, linkEndpoint(item)),
	)

	item.connectedPrinted = true

	return true
}

func (client *client) linkAdd(item *link) {
	key := linkKey(item)

	client.links[key] = append(client.links[key], item)
}

func (client *client) linkRemove(item *link, reason string) {
	if item.peerex {
		if item.stateActive() && client.ready {
			client.peerexRecoveryRequired = true
		}

		if client.peerexRecoveryRequired {
			client.peerexRecoveryStarted = false
		}
	}

	membershipChanged := linkMembershipChanged(item)
	client.linkIndexRemove(item)
	client.linkSeenRemove(item)
	linkPlaybackClose(item)
	client.linkRemovedNotify(item, reason)

	if membershipChanged {
		client.peerListBroadcast()
	}
}

func linkMembershipChanged(item *link) bool {
	return !item.peerex && !item.relay && item.stateActive() &&
		item.audioEligible && item.handleKnown
}

func (client *client) linkSeenRemove(item *link) {
	handle, known := item.identity()
	if known && handle != client.cfg.handle &&
		!client.peerHandleTracked(handle) {
		delete(client.seen, handle)
	}
}

func linkPlaybackClose(item *link) {
	if item.playback == nil {
		return
	}

	item.playback.Close()

	item.playback = nil
}

func (client *client) linkRemovedNotify(item *link, reason string) {
	if !item.connectedPrinted {
		return
	}

	client.output.lineWrite(
		fmt.Sprintf(
			"peer removed: %s@%s (%s)",
			item.handle,
			linkEndpoint(item),
			reason,
		),
	)

	if reason != linkRemovalReplaced {
		client.peerCueQueue(peerCueDisconnect)
	}
}

func (client *client) linkIndexRemove(item *link) {
	key := linkKey(item)
	links := client.links[key]

	for index, candidate := range links {
		if candidate == item {
			links = append(links[:index], links[index+1:]...)

			break
		}
	}

	if len(links) == 0 {
		delete(client.links, key)
	} else {
		client.links[key] = links
	}
}

func (client *client) directRoutePreferred(
	candidate *link,
	now time.Time,
) bool {
	handle, known := candidate.identity()
	if candidate.peerex || !candidate.relay || !known {
		return false
	}

	for _, links := range client.links {
		for _, item := range links {
			if !directRouteMatches(item, candidate, handle) {
				continue
			}

			if now.Sub(item.lastSeen) <= directRouteFreshness {
				return true
			}
		}
	}

	return false
}

func directRouteMatches(
	item *link,
	candidate *link,
	handle proto.Handle,
) bool {
	return item != candidate && !item.peerex && !item.relay &&
		item.stateActive() && item.audioEligible && item.matchesHandle(handle)
}

func (client *client) peerHandleTracked(handle proto.Handle) bool {
	for _, links := range client.links {
		for _, item := range links {
			if !item.peerex && item.matchesHandle(handle) {
				return true
			}
		}
	}

	return false
}

func (client *client) linkFail(item *link, err error) {
	bootstrap := item.bootstrap && !client.ready
	client.linkRemove(item, err.Error())

	if bootstrap {
		select {
		case client.events <- err:
		default:
		}
	}
}

func (client *client) linkKEXSend(item *link, now time.Time) error {
	var err error

	if item.relay {
		target, _ := item.identity()

		err = client.relaySend(target, proto.KEX(item.pair.Public()))
	} else {
		err = datagramSend(
			client.t.conn,
			item.addr,
			proto.KEX(item.pair.Public()),
		)
	}

	if err != nil {
		return karma.Format(err, "send key exchange")
	}

	item.lastKEXSent = now
	item.kexNext = now.Add(proto.KEXInterval)

	return nil
}

func (client *client) linkRequestSend(item *link, now time.Time) error {
	if item.voice == nil || item.requestAttempts >= proto.RequestAttempts {
		return nil
	}

	packet, err := client.linkRequestPacket(item)
	if err != nil {
		return err
	}

	if item.relay {
		target, _ := item.identity()

		err = client.relaySend(target, packet)
	} else {
		err = datagramSend(client.t.conn, item.addr, packet)
	}

	if err != nil {
		return karma.Format(err, "send peer request")
	}

	item.requestAttempts++

	item.requestNext = now.Add(proto.RequestInterval)

	return nil
}

func (client *client) peerexRegistrationSend(
	item *link,
	now time.Time,
) error {
	if item.voice == nil {
		return errors.New("exchange session unavailable")
	}

	packet, err := client.linkRequestPacket(item)
	if err != nil {
		return err
	}

	err = datagramSend(client.t.conn, item.addr, packet)
	if err != nil {
		return karma.Format(err, "send exchange registration")
	}

	item.registrationNext = now.Add(peerexRegistrationInterval)
	item.responseDeadline = now.Add(proto.ResponseTimeout)
	item.responseReceived = false
	item.registrationAttempts++

	return nil
}

func (client *client) linkRequestPacket(item *link) ([]byte, error) {
	payload, ok := proto.Request(
		client.cfg.handle,
		client.cfg.channel,
		client.local,
	)
	if !ok {
		return nil, errors.New("encode peer request")
	}

	packet, err := item.voice.Seal(proto.Type_Request, payload)
	if err != nil {
		return nil, karma.Format(err, "encrypt peer request")
	}

	return packet, nil
}
