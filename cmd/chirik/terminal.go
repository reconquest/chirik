package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/reconquest/karma-go"
)

const (
	terminalPollInterval = 250 * time.Millisecond
	descriptorSetBits    = 64
)

type terminal struct {
	descriptor int
	original   syscall.Termios
}

func chirpTerminalStart() (
	context.Context,
	context.CancelFunc,
	*terminal,
	error,
) {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)

	term, err := terminalEnable(os.Stdin)
	if err != nil {
		stop()

		return ctx, stop, term, err
	}

	return ctx, stop, term, nil
}

func keyboardRun(
	ctx context.Context,
	workers *sync.WaitGroup,
	events chan<- error,
	commands chan<- byte,
	term *terminal,
) {
	defer workers.Done()

	if term == nil {
		<-ctx.Done()

		return
	}

	buffer := make([]byte, 1)
	for {
		command, ready, err := keyboardRead(ctx, term, buffer)
		if err != nil {
			report(ctx, events, err)

			return
		}

		if !ready {
			if ctx.Err() != nil {
				return
			}

			continue
		}

		select {
		case commands <- command:
		case <-ctx.Done():
			return
		}
	}
}

func keyboardRead(
	ctx context.Context,
	term *terminal,
	buffer []byte,
) (byte, bool, error) {
	ready, err := terminalReady(ctx, term.descriptor)
	if err != nil {
		return 0, false, karma.Format(err, "read terminal")
	}

	if !ready {
		return 0, false, nil
	}

	readCount, err := syscall.Read(term.descriptor, buffer)
	if errors.Is(err, syscall.EINTR) {
		return 0, false, nil
	}

	if err != nil {
		return 0, false, karma.Format(err, "read terminal")
	}

	if readCount == 0 {
		return 0, false, karma.Format(io.EOF, "read terminal")
	}

	return buffer[0], true, nil
}

func terminalEnable(file *os.File) (*terminal, error) {
	descriptor := int(file.Fd())
	original, err := termiosGet(descriptor)

	if errors.Is(err, syscall.ENOTTY) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	term := termiosRaw(original)

	setErr := termiosSet(descriptor, &term)
	if setErr != nil {
		return nil, setErr
	}

	return &terminal{descriptor: descriptor, original: original}, nil
}

func termiosRaw(original syscall.Termios) syscall.Termios {
	term := original

	term.Iflag &^= syscall.IGNBRK | syscall.BRKINT |
		syscall.PARMRK | syscall.ISTRIP | syscall.INLCR |
		syscall.IGNCR | syscall.ICRNL | syscall.IXON
	term.Lflag &^= syscall.ECHO | syscall.ECHONL |
		syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	term.Cflag &^= syscall.CSIZE | syscall.PARENB

	term.Cflag |= syscall.CS8

	term.Cc[syscall.VMIN] = 1
	term.Cc[syscall.VTIME] = 0

	return term
}

func (t *terminal) restore() error {
	return termiosSet(t.descriptor, &t.original)
}

func termiosGet(descriptor int) (syscall.Termios, error) {
	var term syscall.Termios

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(descriptor),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&term)),
	)
	if errno != 0 {
		return term, karma.Format(errno, "get terminal settings")
	}

	return term, nil
}

func termiosSet(descriptor int, term *syscall.Termios) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(descriptor),
		uintptr(syscall.TCSETS),
		uintptr(unsafe.Pointer(term)),
	)
	if errno != 0 {
		return karma.Format(errno, "set terminal settings")
	}

	return nil
}

func terminalReady(ctx context.Context, descriptor int) (bool, error) {
	if ctx.Err() != nil {
		return false, nil
	}

	var readSet syscall.FdSet

	fdSet(descriptor, &readSet)

	timeout := syscall.NsecToTimeval(terminalPollInterval.Nanoseconds())

	readCount, err := syscall.Select(descriptor+1, &readSet, nil, nil, &timeout)
	if err != nil {
		if errors.Is(err, syscall.EINTR) {
			return false, nil
		}

		return false, karma.Format(err, "wait for terminal input")
	}

	return readCount > 0 && fdIsSet(descriptor, &readSet), nil
}

func fdSet(descriptor int, set *syscall.FdSet) {
	set.Bits[descriptor/descriptorSetBits] |= 1 << uint(
		descriptor%descriptorSetBits,
	)
}

func fdIsSet(descriptor int, set *syscall.FdSet) bool {
	bit := uint(descriptor % descriptorSetBits)

	return set.Bits[descriptor/descriptorSetBits]&(1<<bit) != 0
}
