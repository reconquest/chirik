package main

import (
	"errors"
	"io"
	"net"

	"github.com/reconquest/karma-go"

	"chirik/internal/proto"
)

const packetQueueSize = 512

type datagram struct {
	data []byte
	addr *net.UDPAddr
}

type transport struct {
	conn    *net.UDPConn
	packets chan datagram
	errors  chan error
	stopped chan struct{}
}

func transportStart(conn *net.UDPConn) *transport {
	transport := &transport{
		conn:    conn,
		packets: make(chan datagram, packetQueueSize),
		errors:  make(chan error, 1),
		stopped: make(chan struct{}),
	}
	go transport.readLoop()

	return transport
}

func (transport *transport) close() error {
	err := transport.conn.Close()
	<-transport.stopped

	if err != nil && !errors.Is(err, net.ErrClosed) {
		return karma.Format(err, "close UDP transport")
	}

	return nil
}

func (transport *transport) readLoop() {
	defer close(transport.stopped)

	buffer := make([]byte, proto.MaxDatagram+1)
	for {
		readCount, addr, err := transport.conn.ReadFromUDP(buffer)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				select {
				case transport.errors <- karma.Format(err, "read UDP datagram"):
				default:
				}
			}

			return
		}

		if readCount > proto.MaxDatagram {
			continue
		}

		packet := datagram{
			data: append([]byte(nil), buffer[:readCount]...),
			addr: addr,
		}
		select {
		case transport.packets <- packet:
		default:
		}
	}
}

func datagramSend(conn *net.UDPConn, addr *net.UDPAddr, packet []byte) error {
	writtenCount, err := conn.WriteToUDP(packet, addr)
	if err != nil {
		return karma.Describe("address", addr).Format(err, "write UDP datagram")
	}

	if writtenCount != len(packet) {
		return io.ErrShortWrite
	}

	return nil
}

func localEndpoint(
	conn *net.UDPConn,
	remote *net.UDPAddr,
) (*net.UDPAddr, error) {
	probe, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		return nil, karma.Describe("remote", remote).
			Format(err, "probe UDP route")
	}

	local, valid := probe.LocalAddr().(*net.UDPAddr)

	closeErr := probe.Close()
	if closeErr != nil {
		return nil, karma.Format(closeErr, "close UDP route probe")
	}

	if !valid {
		return nil, errors.New("route probe address is not UDP")
	}

	listen, valid := conn.LocalAddr().(*net.UDPAddr)
	if !valid {
		return nil, errors.New("listening address is not UDP")
	}

	localIP := local.IP.To4()
	if localIP == nil || localIP.IsUnspecified() || listen.Port == 0 {
		return nil, errors.New("no routable IPv4 endpoint")
	}

	return &net.UDPAddr{
		IP:   append(net.IP(nil), localIP...),
		Port: listen.Port,
	}, nil
}

func addrCopy(addr *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone &&
		a.IP.Equal(b.IP)
}
