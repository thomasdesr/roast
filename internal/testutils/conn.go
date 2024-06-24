package testutils

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

var netdebug = os.Getenv("NETDEBUG") != ""

type Conn struct {
	Name string
	TB   testing.TB
	net.Conn

	idleTimeout time.Duration
}

func (c *Conn) checkAndBumpIdleTimeout() {
	if c.idleTimeout > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.idleTimeout))
	}
}

func (c Conn) Read(b []byte) (n int, err error) {
	c.TB.Helper()

	c.checkAndBumpIdleTimeout()

	n, err = c.Conn.Read(b)
	if netdebug {
		c.TB.Logf("%s: Read %d bytes: %q", c.Name, n, b[:n])
	}

	c.checkAndBumpIdleTimeout()

	return
}

func (c Conn) Write(b []byte) (n int, err error) {
	c.TB.Helper()

	c.checkAndBumpIdleTimeout()

	n, err = c.Conn.Write(b)
	if netdebug {
		c.TB.Logf("%s: Wrote %d bytes: %q", c.Name, n, b[:n])
	}

	c.checkAndBumpIdleTimeout()

	return
}

type Listener struct {
	TB testing.TB
	net.Listener
}

func (l Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if !netdebug {
		return c, nil
	}

	return Conn{"listener", l.TB, c, time.Second * 5}, nil
}

func ListenerDialer(t testing.TB) (net.Listener, func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()

	// l, err := net.Listen("unix", t.TempDir()+"/listener.sock")
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen on socket: %v", err)
	}

	dialFunc := func(ctx context.Context, network string, address string) (net.Conn, error) {
		// Ensure we connect to the listener
		c, err := net.Dial(l.Addr().Network(), l.Addr().String())
		if err != nil {
			return nil, err
		}

		if !netdebug {
			return c, nil
		}

		return Conn{"dialer", t, c, time.Second * 5}, nil
	}

	return Listener{t, l}, dialFunc
}

func ConnPipe(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()

	listener, dialer := ListenerDialer(t)

	leftC := make(chan net.Conn)
	rightC := make(chan net.Conn)
	go func() {
		j, err := listener.Accept()
		if err != nil {
			t.Fatalf("failed to accept: %v", err)
		}

		leftC <- j
	}()

	go func() {
		j, err := dialer(context.Background(), listener.Addr().Network(), listener.Addr().String())
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}

		rightC <- j
	}()

	return <-leftC, <-rightC
}
