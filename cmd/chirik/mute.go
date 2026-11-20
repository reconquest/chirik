package main

import (
	"fmt"

	"chirik/internal/proto"
)

func (client *client) muteToggle() {
	muted := !client.muted.Load()
	client.muted.Store(muted)
	client.output.lineWrite(muteLabel(muted))
	client.peerCueQueue(muteCue(muted))
	client.voiceBroadcast(proto.Type_MuteState, client.mutePayload())
}

func (client *client) mutePayload() []byte {
	if client.muted.Load() {
		return []byte{1}
	}

	return []byte{0}
}

func (client *client) muteStateReceive(item *link, payload []byte) bool {
	if !item.voicePeer() ||
		!item.handleKnown || len(payload) != 1 || payload[0] > 1 {
		return false
	}

	muted := payload[0] == 1
	previous, known := client.peerMuted[item.handle]

	if known && previous == muted {
		return true
	}

	if client.peerMuted == nil {
		client.peerMuted = make(map[proto.Handle]bool)
	}

	client.peerMuted[item.handle] = muted
	client.output.lineWrite(
		fmt.Sprintf("peer %s %s", item.handle, muteLabel(muted)),
	)

	if known || muted {
		client.peerCueQueue(muteCue(muted))
	}

	return true
}

func muteLabel(muted bool) string {
	if muted {
		return "muted"
	}

	return "unmuted"
}

func muteCue(muted bool) peerCue {
	if muted {
		return peerCueMute
	}

	return peerCueUnmute
}
