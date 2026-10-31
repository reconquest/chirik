package main

import (
	"cmp"
	"fmt"
	"io"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/reconquest/karma-go"

	"chirik/internal/proto"
)

const (
	bitsPerByte    = 8
	bitsPerKilobit = 1000

	terminalLineClear = "\r\x1b[2K"
	terminalCursorUp  = "\x1b[1A"
)

type peerBitrate struct {
	handle        proto.Handle
	bytesReceived uint64
	bytesSent     uint64
}

type output struct {
	logger       *log.Logger
	writer       io.Writer
	mu           sync.Mutex
	bitrateLines int
	err          error
}

func (output *output) bitrateWrite(rates []peerBitrate, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}

	factor := bitsPerByte / elapsed.Seconds() / bitsPerKilobit

	output.mu.Lock()
	defer output.mu.Unlock()

	output.bitrateClearLocked()

	for index, rate := range rates {
		if index != 0 {
			output.writef("\n")
		}

		output.writef(
			terminalLineClear+"%-16s | in %8.2f kbit/s | out %8.2f kbit/s",
			rate.handle,
			float64(rate.bytesReceived)*factor,
			float64(rate.bytesSent)*factor,
		)
	}

	output.bitrateLines = len(rates)
}

func (output *output) writef(format string, args ...any) {
	if output.err != nil {
		return
	}

	_, err := fmt.Fprintf(output.writer, format, args...)
	if err != nil {
		output.err = karma.Format(err, "write terminal output")
	}
}

func (output *output) writeError() error {
	output.mu.Lock()
	defer output.mu.Unlock()

	return output.err
}

func (output *output) lineWrite(message any) {
	output.mu.Lock()
	defer output.mu.Unlock()

	output.bitrateClearLocked()

	if output.logger != nil {
		output.logger.Print("INFO ", message)

		return
	}

	output.writef(terminalLineClear+"%v\n", message)
}

func (output *output) lineClear() {
	output.mu.Lock()
	defer output.mu.Unlock()

	if output.bitrateLines == 0 {
		output.writef(terminalLineClear)

		return
	}

	output.bitrateClearLocked()
}

func (output *output) bitrateClearLocked() {
	for index := range output.bitrateLines {
		output.writef(terminalLineClear)

		if index+1 < output.bitrateLines {
			output.writef(terminalCursorUp)
		}
	}

	output.bitrateLines = 0
}

func (client *client) peerBitrates() []peerBitrate {
	var rates []peerBitrate

	for _, links := range client.links {
		for _, item := range links {
			if item.peerex || !item.stateActive() || !item.audioEligible ||
				!item.handleKnown {
				continue
			}

			var (
				bytesSent     = item.counters.sentBytes.Load()
				bytesReceived = item.counters.receivedBytes.Load()
			)

			rates = append(rates, peerBitrate{
				handle:        item.handle,
				bytesReceived: bytesReceived - item.sampledReceivedBytes,
				bytesSent:     bytesSent - item.sampledSentBytes,
			})
			item.sampledSentBytes = bytesSent
			item.sampledReceivedBytes = bytesReceived
		}
	}

	slices.SortFunc(rates, func(left, right peerBitrate) int {
		return cmp.Compare(left.handle, right.handle)
	})

	return rates
}
